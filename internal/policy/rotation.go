package policy

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"time"

	"github.com/daxchain-io/daxib/internal/policyseal"
	"github.com/daxchain-io/daxib/internal/secret"
)

// rotation.go is the SI-1 crash-safe admin-passphrase rotation: a THREE-phase staged
// protocol that never leaves policy.json unverifiable under the pinned anchor on
// recovery (the failure mode of the old single-shot ChangeAdminPassphrase, which
// resealed policy.json under the NEW key and only THEN landed the new anchor — a crash
// between left policy.json sealed under NEW while the on-disk anchor still pinned OLD,
// so the guardrails were unverifiable / unusable = fail-OPEN).
//
// The on-disk protocol mirrors the keystore §3.8 rotation (stage → commit → swap),
// adapted to the policy engine's two state classes (the anchor in the config class,
// policy.json in the state class). The service drives the three engine phases,
// landing the anchor between them:
//
//	STAGE   : land a DUAL-KEY anchor {verify_key: OLD, verify_key_next: NEW,
//	          staged_salt: NEW_salt}. policy.json is STILL sealed under OLD, so it
//	          verifies (verifyUnderAnchor accepts either key). This is the commit
//	          point: once the staged anchor is on disk, recovery rolls FORWARD/BACK by
//	          inspecting which key policy.json verifies under.
//	RESEAL  : reseal policy.json under the NEW key (nonce bumped). It now verifies
//	          under verify_key_next. The anchor is unchanged (still dual-key, still
//	          accepts the NEW seal).
//	PROMOTE : land the FINAL anchor {verify_key: NEW, verify_key_next: null,
//	          staged_salt: dropped}. policy.json verifies under the single pinned key.
//
// At EVERY crash point the (anchor, policy.json) pair verifies under SOME key the
// anchor pins, so the guardrails stay INTACT and the limits are never wiped. Recovery
// (RecoverAdminRotation, run by the service at Open) converges a half-finished
// rotation to a clean single-key anchor: roll FORWARD (promote) when policy.json is
// already resealed under NEW, roll BACK (drop the staged key) otherwise.

// StageAdminRotation is phase 1. It authenticates the CURRENT admin passphrase
// against the pinned verify key, derives the NEW key family under a fresh staged salt
// (the private key is zeroed immediately inside StageRotation — staging records only
// the public key), and returns the DUAL-KEY anchor for the service to land. policy.json
// is NOT touched (it stays sealed under the OLD key and keeps verifying). The engine's
// in-memory anchor is updated to the dual-key form so a follow-up Reseal in the same
// process sees the staged key.
func (e *Engine) StageAdminRotation(current, next *secret.Bytes) (policyseal.Anchor, error) {
	if !e.anchorFound {
		return policyseal.Anchor{}, errAdminAuth("no anchor is pinned; nothing to rotate")
	}
	if next == nil || next.Len() == 0 {
		return policyseal.Anchor{}, errAdminAuth("the new admin passphrase is required")
	}
	// Authenticate the CURRENT passphrase (must derive the pinned verify key). A staged
	// rotation already in flight is refused here — the operator must let recovery
	// converge it first (re-running change-admin-passphrase after Open does so).
	if e.anchor.VerifyKeyNext != "" {
		return policyseal.Anchor{}, errAdminAuth("a passphrase rotation is already staged; re-open to converge it before staging another")
	}
	sk, err := e.authenticate(current)
	if err != nil {
		return policyseal.Anchor{}, err
	}
	zeroKey(sk)

	params := e.anchor.Scrypt
	nextKey, stagedSalt, serr := policyseal.StageRotation(next.Reveal(), params)
	if serr != nil {
		return policyseal.Anchor{}, errAdminAuth("deriving the staged rotation key: " + serr.Error())
	}
	staged := e.anchor
	staged.VerifyKeyNext = nextKey
	staged.StagedSalt = policyseal.EncodeSalt(stagedSalt)
	e.anchor = staged
	return staged, nil
}

// ResealUnderStagedRotation is phase 2. With a staged rotation in flight it
// authenticates the NEW passphrase against the staged verify_key_next, loads + verifies
// the active body (which still verifies under the OLD key), and reseals policy.json
// under the NEW key (nonce bumped past the watermark). After this, policy.json verifies
// under verify_key_next. The anchor is unchanged (still dual-key). The engine's
// activeNonce/watermark reflect the bumped nonce.
func (e *Engine) ResealUnderStagedRotation(next *secret.Bytes) error {
	if !e.anchorFound || e.anchor.VerifyKeyNext == "" {
		return errAdminAuth("no staged rotation to reseal")
	}
	if next == nil || next.Len() == 0 {
		return errAdminAuth("the new admin passphrase is required")
	}
	// Re-derive the NEW family from the staged salt and confirm it equals the staged
	// key (a wrong new passphrase here is policy.admin_auth — NOT a seal violation).
	fam, cerr := policyseal.CommitRotation(next.Reveal(), e.anchor, e.anchor.Scrypt)
	if cerr != nil {
		return errAdminAuth("the new admin passphrase does not match the staged rotation: " + cerr.Error())
	}
	defer zeroFamily(fam)

	lr, present, lerr := e.loadActive()
	if lerr != nil {
		return lerr
	}
	if !present {
		return errSeal("missing", "no policy to reseal under the staged key")
	}

	body := lr.policy
	body.Nonce = e.anchor.NonceWatermark + 1
	body.UpdatedAt = e.now().UTC().Format(time.RFC3339)
	if werr := e.sealAndWriteWith(fam.Private, body); werr != nil {
		return werr
	}
	// The reseal bumped the nonce; record it so a same-process Promote stamps the
	// matching watermark. The on-disk anchor still carries the OLD watermark, but
	// policy.json.nonce (wm+1) >= that, so no rollback fires before Promote lands.
	e.activeNonce = body.Nonce
	return nil
}

// PromoteAdminRotation is phase 3. It requires a staged rotation whose policy.json
// already verifies under verify_key_next (the reseal happened), and returns the FINAL
// single-key anchor (verify_key := the staged key, salt := the staged salt, staged
// fields cleared, watermark bumped to the resealed nonce) for the service to land.
func (e *Engine) PromoteAdminRotation() (policyseal.Anchor, error) {
	if !e.anchorFound || e.anchor.VerifyKeyNext == "" {
		return policyseal.Anchor{}, errAdminAuth("no staged rotation to promote")
	}
	bodyRaw, sig, nonce, perr := e.readSealedBody()
	if perr != nil {
		return policyseal.Anchor{}, perr
	}
	nextPK, ok, nerr := e.anchor.VerifyKeyNextBytes()
	if nerr != nil || !ok {
		return policyseal.Anchor{}, errSeal("bad_key", "the staged verify key is malformed")
	}
	if !policyseal.Verify(bodyRaw, sig, nextPK) {
		return policyseal.Anchor{}, errSeal("bad_sig", "policy.json does not verify under the staged key; refusing to promote (reseal did not complete)")
	}
	promoted := e.anchor
	promoted.VerifyKey = e.anchor.VerifyKeyNext
	promoted.Salt = e.anchor.StagedSalt
	promoted.VerifyKeyNext = ""
	promoted.StagedSalt = ""
	if nonce > promoted.NonceWatermark {
		promoted.NonceWatermark = nonce
	}
	e.anchor = promoted
	return promoted, nil
}

// RecoverAdminRotation converges a half-finished staged rotation at Open
// (passphrase-free). It returns the anchor the service should land + a flag noting
// whether it changed. With no staged key it is a no-op. With a staged key it inspects
// which key policy.json verifies under:
//
//   - verifies under verify_key_next (NEW) ⇒ the reseal completed ⇒ roll FORWARD
//     (promote to the single NEW key, watermark bumped).
//   - verifies under verify_key (OLD) only ⇒ the reseal did NOT complete ⇒ roll BACK
//     (drop the staged key/salt, keep OLD). policy.json (under OLD) still verifies.
//
// If policy.json verifies under NEITHER key, it leaves the anchor INTACT and returns a
// seal_violation (fail closed — never widen the trust root on a corrupt body). The
// service lands the returned anchor only when changed is true.
func (e *Engine) RecoverAdminRotation() (anchor policyseal.Anchor, changed bool, err error) {
	if !e.anchorFound || e.anchor.VerifyKeyNext == "" {
		return e.anchor, false, nil
	}
	bodyRaw, sig, nonce, perr := e.readSealedBody()
	if perr != nil {
		// policy.json missing/unparseable under a staged anchor: fail closed, leave the
		// anchor intact so the next real op surfaces the seal violation.
		return e.anchor, false, perr
	}

	if nextPK, ok, nerr := e.anchor.VerifyKeyNextBytes(); nerr == nil && ok && policyseal.Verify(bodyRaw, sig, nextPK) {
		// Resealed under NEW ⇒ roll FORWARD (promote).
		promoted := e.anchor
		promoted.VerifyKey = e.anchor.VerifyKeyNext
		promoted.Salt = e.anchor.StagedSalt
		promoted.VerifyKeyNext = ""
		promoted.StagedSalt = ""
		if nonce > promoted.NonceWatermark {
			promoted.NonceWatermark = nonce
		}
		e.anchor = promoted
		return promoted, true, nil
	}

	if oldPK, oerr := e.anchor.VerifyKeyBytes(); oerr == nil && policyseal.Verify(bodyRaw, sig, oldPK) {
		// Still sealed under OLD ⇒ roll BACK (drop the staged key).
		rolled := e.anchor
		rolled.VerifyKeyNext = ""
		rolled.StagedSalt = ""
		e.anchor = rolled
		return rolled, true, nil
	}

	// Verifies under neither key — a corrupt/tampered body. Fail closed.
	return e.anchor, false, errSeal("bad_sig", "policy.json verifies under neither the pinned nor the staged key during rotation recovery")
}

// readSealedBody reads policy.json and returns the body bytes, the raw seal signature,
// and the body nonce. It does NOT verify the seal (callers verify against a chosen
// key). A missing/unparseable file is a seal_violation (fail closed).
func (e *Engine) readSealedBody() (bodyRaw, sig []byte, nonce uint64, err error) {
	raw, rerr := os.ReadFile(e.policyPath()) // #nosec G304 -- fixed join of the configured state dir
	if rerr != nil {
		return nil, nil, 0, errSeal("missing", "policy.json is not present")
	}
	env, body, derr := decodeEnvelope(raw)
	if derr != nil {
		return nil, nil, 0, derr
	}
	s, berr := decodeBase64(env.Seal.Sig)
	if berr != nil {
		return nil, nil, 0, errSeal("unparseable", "policy.json seal signature is not valid base64")
	}
	// Read the nonce permissively (the strict decode runs at the real load path).
	var head struct {
		Nonce uint64 `json:"nonce"`
	}
	_ = json.Unmarshal(body, &head)
	return body, s, head.Nonce, nil
}

// zeroFamily zeroes the private key material of a rotated family (the public key +
// salt are not secret).
func zeroFamily(fam policyseal.RotatedFamily) {
	if fam.Private != nil {
		zeroKey(ed25519.PrivateKey(fam.Private))
	}
}
