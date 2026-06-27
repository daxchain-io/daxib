package policy

import (
	"crypto/ed25519"
	"crypto/subtle"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/daxchain-io/daxib/internal/fsx"
	"github.com/daxchain-io/daxib/internal/policyseal"
	"github.com/daxchain-io/daxib/internal/secret"
)

// Change is the admin `policy set` mutation. A nil pointer field leaves that gate
// unchanged (tri-state). The CLI translates flags into this struct; per-network
// overrides are upserted by network name. RefreshSelf is the live keystore address
// snapshot to seal into self_addresses on every mutation. WrittenBy stamps the
// binary version.
type Change struct {
	Default     *Limits
	Networks    []NetworkRule
	RefreshSelf []string
	WrittenBy   string
}

// AllowEntry / DenyEntry are the `policy allow|deny <address>` mutations. The CLI
// pre-resolves the input to a pinned address; the engine pins what it is handed.
type AllowEntry struct {
	Address     string
	Label       string
	Remove      bool
	RefreshSelf []string
	WrittenBy   string
}

type DenyEntry struct {
	Address     string
	Label       string
	Remove      bool
	RefreshSelf []string
	WrittenBy   string
}

// InitSeal bootstraps the anchor on the FIRST `policy set`: it generates a salt +
// verify keypair from the admin passphrase and a default (permissive-shape) body at
// nonce 1, seals it, writes policy.json, and returns the new anchor (watermark 0,
// bumped to 1). It REFUSES to replace an existing trust root. The caller writes the
// returned anchor to the config class (policy.json first, anchor second).
func (e *Engine) InitSeal(adminPass *secret.Bytes, refreshSelf []string, writtenBy string) (policyseal.Anchor, error) {
	if e.anchorFound {
		return policyseal.Anchor{}, errAdminAuth("an anchor is already pinned; refusing to replace the trust root (use `policy set` to update, or `policy reset` to re-seal)")
	}
	if adminPass == nil || adminPass.Len() == 0 {
		return policyseal.Anchor{}, errAdminAuth("the admin passphrase is required to bootstrap the policy anchor")
	}
	salt, err := policyseal.NewSalt()
	if err != nil {
		return policyseal.Anchor{}, errState("generating anchor salt", err)
	}
	params := e.bootstrapParams()
	sk, pk, derr := policyseal.DeriveSealKey(adminPass.Reveal(), salt, params)
	if derr != nil {
		return policyseal.Anchor{}, errAdminAuth("deriving the seal key: " + derr.Error())
	}
	defer zeroKey(sk)

	anchor := policyseal.Anchor{
		VerifyKey:      policyseal.EncodeKey(pk),
		Salt:           policyseal.EncodeSalt(salt),
		Scrypt:         params,
		NonceWatermark: 0,
	}
	body := defaultPolicy(writtenBy)
	body.Nonce = 1
	body.SelfAddresses = sortedLower(refreshSelf)
	if werr := e.sealAndWriteWith(sk, body); werr != nil {
		return policyseal.Anchor{}, werr
	}
	anchor.NonceWatermark = body.Nonce
	// The engine now holds the freshly-pinned anchor (so a follow-up Show in the
	// same process verifies).
	e.anchor = anchor
	e.anchorFound = true
	return anchor, nil
}

// Set applies a Change (limits/gates/per-network overrides) under the admin
// passphrase. It runs the ordered mutation pipeline and returns the updated anchor
// (watermark bumped). Requires an existing anchor.
func (e *Engine) Set(adminPass *secret.Bytes, c Change) (policyseal.Anchor, error) {
	return e.mutate(adminPass, c.RefreshSelf, c.WrittenBy, func(p *Policy) {
		if c.Default != nil {
			applyDefault(&p.Rules.Default, c.Default)
		}
		for _, n := range c.Networks {
			upsertNetwork(&p.Rules, n)
		}
	})
}

// Allow adds (or removes) an allowlist address pin under the admin passphrase.
func (e *Engine) Allow(adminPass *secret.Bytes, entry AllowEntry) (policyseal.Anchor, error) {
	return e.mutate(adminPass, entry.RefreshSelf, entry.WrittenBy, func(p *Policy) {
		if entry.Remove {
			p.Allowlist = removePin(p.Allowlist, entry.Address)
			return
		}
		p.Allowlist = upsertPin(p.Allowlist, entry.Address, entry.Label, e.now())
	})
}

// Deny adds (or removes) a denylist address pin under the admin passphrase.
func (e *Engine) Deny(adminPass *secret.Bytes, entry DenyEntry) (policyseal.Anchor, error) {
	return e.mutate(adminPass, entry.RefreshSelf, entry.WrittenBy, func(p *Policy) {
		if entry.Remove {
			p.Denylist = removePin(p.Denylist, entry.Address)
			return
		}
		p.Denylist = upsertPin(p.Denylist, entry.Address, entry.Label, e.now())
	})
}

// Reset reseals a fresh DEFAULT body under the EXISTING key family. It authenticates
// against the ANCHOR (a prompt-compromised agent that trashed policy.json cannot
// reset under a passphrase of its own choosing, because its passphrase never derives
// the pinned key). The nonce restarts at watermark+1. Requires an anchor.
func (e *Engine) Reset(adminPass *secret.Bytes, refreshSelf []string, writtenBy string) (policyseal.Anchor, error) {
	if !e.anchorFound {
		return policyseal.Anchor{}, errAdminAuth("no anchor is pinned; reset cannot authenticate (re-bootstrap with `policy set`)")
	}
	sk, err := e.authenticate(adminPass)
	if err != nil {
		return policyseal.Anchor{}, err
	}
	defer zeroKey(sk)

	body := defaultPolicy(writtenBy)
	body.Nonce = e.anchor.NonceWatermark + 1
	body.SelfAddresses = sortedLower(refreshSelf)
	if werr := e.sealAndWriteWith(sk, body); werr != nil {
		return policyseal.Anchor{}, werr
	}
	anchor := e.anchor
	anchor.NonceWatermark = body.Nonce
	e.anchor = anchor
	return anchor, nil
}

// Admin-passphrase rotation is the SI-1 crash-safe THREE-phase staged protocol in
// rotation.go (StageAdminRotation → ResealUnderStagedRotation → PromoteAdminRotation,
// with RecoverAdminRotation converging an interrupted rotation at Open). The old
// single-shot rotate-then-reland was removed: it could leave policy.json sealed under
// the new key while the anchor still pinned the old one on a crash (fail-open).

// ── the shared mutation pipeline ─────────────────────────────────────────────

// mutate runs the ordered admin pipeline (§4.7):
//
//	authenticate (derive pk; pk != anchor.verify_key ⇒ policy.admin_auth)
//	→ load + verify seal (bad sig ⇒ policy.seal_violation)
//	→ apply mutation
//	→ nonce++ (≥ watermark+1)
//	→ refresh self_addresses (sealed snapshot)
//	→ re-sign the EXACT new bytes
//	→ write the envelope atomically
//	→ bump the watermark; return the new anchor
func (e *Engine) mutate(adminPass *secret.Bytes, refreshSelf []string, writtenBy string, fn func(*Policy)) (policyseal.Anchor, error) {
	if !e.anchorFound {
		return policyseal.Anchor{}, errAdminAuth("no anchor is pinned; run `policy set` to bootstrap first")
	}
	sk, err := e.authenticate(adminPass)
	if err != nil {
		return policyseal.Anchor{}, err
	}
	defer zeroKey(sk)

	lr, present, lerr := e.loadActive()
	if lerr != nil {
		return policyseal.Anchor{}, lerr
	}
	if !present {
		return policyseal.Anchor{}, errSeal("missing", "policy.json is missing under a pinned anchor")
	}

	body := lr.policy
	fn(&body)
	body.Nonce++
	if body.Nonce <= e.anchor.NonceWatermark {
		body.Nonce = e.anchor.NonceWatermark + 1
	}
	if refreshSelf != nil {
		body.SelfAddresses = sortedLower(refreshSelf)
	}
	if writtenBy != "" {
		body.WrittenBy = writtenBy
	}
	body.UpdatedAt = e.now().UTC().Format(time.RFC3339)

	if werr := e.sealAndWriteWith(sk, body); werr != nil {
		return policyseal.Anchor{}, werr
	}
	anchor := e.anchor
	if body.Nonce > anchor.NonceWatermark {
		anchor.NonceWatermark = body.Nonce
	}
	e.anchor = anchor
	return anchor, nil
}

// authenticate derives (sk, pk) from the admin passphrase + anchor salt and
// constant-time-compares pk to the pinned verify key (or verify_key_next during
// rotation). A mismatch is policy.admin_auth (the passphrase is wrong — NOT a seal
// violation). The caller MUST zero the returned sk.
func (e *Engine) authenticate(adminPass *secret.Bytes) (ed25519.PrivateKey, error) {
	if adminPass == nil || adminPass.Len() == 0 {
		return nil, errAdminAuth("the admin passphrase is required for this mutation")
	}
	salt, err := e.anchor.SaltBytes()
	if err != nil {
		return nil, errSeal("bad_salt", "the anchor salt is malformed")
	}
	sk, pk, derr := policyseal.DeriveSealKey(adminPass.Reveal(), salt, e.anchor.Scrypt)
	if derr != nil {
		return nil, errAdminAuth("deriving the seal key from the admin passphrase: " + derr.Error())
	}
	want, kerr := e.anchor.VerifyKeyBytes()
	if kerr != nil {
		zeroKey(sk)
		return nil, errSeal("bad_key", "the anchor verify key is malformed")
	}
	if subtle.ConstantTimeCompare(pk, want) == 1 {
		return sk, nil
	}
	// Try the staged rotation key.
	if next, ok, nerr := e.anchor.VerifyKeyNextBytes(); nerr == nil && ok && subtle.ConstantTimeCompare(pk, next) == 1 {
		return sk, nil
	}
	zeroKey(sk)
	return nil, errAdminAuth("the admin passphrase does not derive the pinned verify key")
}

// sealAndWriteWith marshals the body via the ordered writer, signs with sk, and
// atomically writes the two-member envelope to policy.json (state class). A
// read-only state mount is a config.read_only (mutation refused).
func (e *Engine) sealAndWriteWith(sk ed25519.PrivateKey, body Policy) error {
	bodyBytes := writeBody(body)
	sig := policyseal.Sign(bodyBytes, sk)
	env := marshalEnvelope(bodyBytes, sig)
	if err := fsx.MkdirAll(e.dir, 0o700); err != nil {
		if fsx.IsReadOnly(err) {
			return errState("state dir is read-only; cannot write policy.json", err)
		}
		return errState("creating state dir for policy.json", err)
	}
	if werr := fsx.WriteAtomic(e.policyPath(), env, 0o600); werr != nil {
		if fsx.IsReadOnly(werr) {
			return errState("policy.json is on a read-only mount", werr)
		}
		return errState("writing policy.json", werr)
	}
	return nil
}

// ── body mutation helpers ────────────────────────────────────────────────────

// defaultPolicy is a fresh body shell with the allowlist OFF by default —
// petty-cash simplicity ("a cool project, not a bank"): limits + the denylist are
// ALWAYS enforced, but sends are allowed to ANY address within the configured
// limits unless the operator opts into deny-by-default destinations via
// `policy set --allowlist on`. Limits are absent (the default block resolves nil =
// no limit) so a fresh policy denies nothing by amount until `policy set` adds caps.
// include_self stays on so a self/change destination always passes once the
// allowlist IS turned on.
func defaultPolicy(writtenBy string) Policy {
	on := true
	off := false
	return Policy{
		Version:   bodyVersion,
		WrittenBy: writtenBy,
		Rules: Rules{
			Default: Limits{
				AllowlistOn: &off,
				IncludeSelf: &on,
			},
		},
	}
}

func applyDefault(dst *Limits, src *Limits) {
	if src.MaxTxSat != nil {
		dst.MaxTxSat = src.MaxTxSat
	}
	if src.MaxDaySat != nil {
		dst.MaxDaySat = src.MaxDaySat
	}
	if src.MaxFeeRate != nil {
		dst.MaxFeeRate = src.MaxFeeRate
	}
	if src.AllowlistOn != nil {
		dst.AllowlistOn = src.AllowlistOn
	}
	if src.IncludeSelf != nil {
		dst.IncludeSelf = src.IncludeSelf
	}
}

func upsertNetwork(r *Rules, n NetworkRule) {
	for i := range r.Networks {
		if strings.EqualFold(r.Networks[i].Network, n.Network) {
			applyDefault(&r.Networks[i].Limits, &n.Limits)
			return
		}
	}
	r.Networks = append(r.Networks, n)
	sort.Slice(r.Networks, func(i, j int) bool { return r.Networks[i].Network < r.Networks[j].Network })
}

func upsertPin(pins []PinEntry, addr, label string, now time.Time) []PinEntry {
	for i := range pins {
		if pins[i].Source == "address" && strings.EqualFold(pins[i].Address, addr) {
			if label != "" {
				pins[i].Label = label
			}
			return pins
		}
	}
	return append(pins, PinEntry{
		Source:  "address",
		Address: addr,
		Label:   label,
		AddedAt: now.UTC().Format(time.RFC3339),
	})
}

func removePin(pins []PinEntry, addr string) []PinEntry {
	out := pins[:0]
	for _, p := range pins {
		if p.Source == "address" && strings.EqualFold(p.Address, addr) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// zeroKey overwrites a private key in place.
func zeroKey(sk ed25519.PrivateKey) {
	for i := range sk {
		sk[i] = 0
	}
	runtime.KeepAlive(sk)
}
