package service

import (
	"context"

	"github.com/daxchain-io/daxib/internal/config"
	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/journal"
	"github.com/daxchain-io/daxib/internal/policy"
	"github.com/daxchain-io/daxib/internal/policyseal"
	"github.com/daxchain-io/daxib/internal/secret"
)

// policy.go wires the M5 sealed-policy engine into the core. The cli/mcpserver
// frontends never import internal/policy directly (the arch lattice forbids it);
// they drive the engine through these service methods. The engine reads the anchor
// from the config DIRECTORY (config class) and keeps policy.json + counters in the
// state DIRECTORY (state class).

// openPolicyEngine builds the policy engine for one operation: it reads the anchor
// directly from the config dir (NOT via TOML/env/flag) and roots the engine at the
// state dir. A missing config dir means no anchor (the permissive opt-in path).
func (s *Service) openPolicyEngine(ctx context.Context) (*policy.Engine, error) {
	// Policy ops are network-scoped (per-network limits/counters, the active-family
	// self snapshot, the active-network check). With no network resolved they would
	// silently operate against a defaulted family, so fail with usage.network_required.
	// This is the shared gate for show/set/allow/deny/verify/check/counters/reset/
	// change-admin-passphrase/pin. The in-pipeline Reserve path goes through SendTx,
	// which already guards earlier.
	if err := s.requireNetwork(); err != nil {
		return nil, err
	}
	var anchor policyseal.Anchor
	found := false
	if s.opts.Config != "" {
		ar, err := config.OpenAnchor(s.opts.Config)
		if err != nil {
			return nil, err
		}
		raw, ok, rerr := ar.ReadAnchor(ctx)
		if rerr != nil {
			return nil, rerr
		}
		if ok {
			a, perr := policyseal.ParseAnchor(raw)
			if perr != nil {
				return nil, domain.Wrap("policy.seal_violation", "the pinned policy anchor is malformed", perr)
			}
			anchor = a
			found = true
		}
	}
	eng, err := policy.Open(s.stateDir, anchor, found, s.clock)
	if err != nil {
		return nil, err
	}
	// DAXIB_KDF_LIGHT forces the cheap admin scrypt cost at bootstrap only (tests);
	// it has no effect on an already-pinned anchor.
	eng.SetLightKDF(s.opts.KDFLight)
	return eng, nil
}

// writeAnchor persists a (possibly bootstrapped/updated) anchor to the config dir.
// On a read-only config mount it returns the typed config.read_only so the caller
// can fall back to emitting the anchor JSON for an out-of-band land.
func (s *Service) writeAnchor(ctx context.Context, anchor policyseal.Anchor) error {
	if s.opts.Config == "" {
		return domain.New("config.not_found", "no config directory configured for the policy anchor (set --config / DAXIB_CONFIG)")
	}
	ar, err := config.OpenAnchor(s.opts.Config)
	if err != nil {
		return err
	}
	raw, merr := anchor.Marshal()
	if merr != nil {
		return domain.Wrap("policy.seal_violation", "encoding the policy anchor", merr)
	}
	return ar.WriteAnchor(ctx, raw)
}

// selfSnapshot enumerates EVERY known address across EVERY wallet in the keystore —
// the sealed self_addresses snapshot that include_self resolves against. Sealing the
// snapshot (not reading the live keystore at eval time) is what stops a
// prompt-compromised agent from importing an attacker key to mint itself an
// allowlisted destination. Best-effort: an unreadable keystore yields an empty set.
func (s *Service) selfSnapshot(ctx context.Context) []string {
	wallets, err := s.keys.ListWallets(ctx, s.net)
	if err != nil {
		return nil
	}
	var out []string
	for _, w := range wallets {
		// A BOUND wallet whose locked network != the active network has no chain at
		// s.net (and ListAddresses returns wallet.not_found for it). Skip it
		// gracefully — the sealed self-allowlist enumerates the ACTIVE family only.
		_, addrs, aerr := s.keys.ListAddresses(ctx, w.Name, s.net)
		if aerr != nil {
			continue
		}
		for _, a := range addrs {
			out = append(out, a.Address)
		}
	}
	return out
}

// dryRunPolicyCheck returns a reserve callback for the --dry-run path that runs a
// CHECK-only Evaluate (writes NO reservation) and returns the policy.denied.* error
// when the would-be send is over-limit/non-allowlisted, so a dry-run that would be
// denied exits 3 before the preview sign. With no active policy it is permissive.
func (s *Service) dryRunPolicyCheck(_ string) reserveFn {
	return func(ctx context.Context, preArt sendArtifact) error {
		eng, err := s.openPolicyEngine(ctx)
		if err != nil {
			return err
		}
		d, cerr := eng.Check(ctx, policy.Check{
			Network:    string(s.net),
			Recipient:  preArt.recipient,
			AmountSat:  preArt.recipSat,
			FeeSat:     preArt.feeSat,
			FeeRate:    preArt.feeRate,
			ChangeAddr: preArt.changeAddr,
		})
		if cerr != nil {
			return cerr
		}
		if !d.Allowed {
			e := domain.New(d.Code, d.Reason)
			if d.Data != nil {
				e = domain.WithData(e, d.Data)
			}
			return e
		}
		return nil
	}
}

// reconcilePolicyOrphans resolves orphaned spend reservations against the journal at
// Open. Best-effort (never fails Open). It is the policy-side twin of the journal
// reconcile (policy may not import journal, so service drives it).
//
// POL-1 — fail CLOSED on the offline path. This runs at Open WITHOUT dialing a
// backend, so it cannot positively learn whether a `signed` record's bytes are live
// on the network. A `signed` record HAS journaled signed bytes that MAY already have
// reached the mempool — the SendTx accepted path commits the reservation and only
// THEN writes SetState(broadcast), so a crash between those two leaves a live tx in
// `signed`; reconcileWallet also rebroadcasts `signed` records under the send-lock.
// Releasing a `signed` orphan's reservation (refunding the rolling-24h budget) would
// therefore let an agent re-spend a budget that a live tx already consumed
// (fail-OPEN). So offline we leave a `signed` orphan RESERVED — over-counting is the
// safe direction. An ONLINE path (a real send's reconcileWallet, or `tx wait`/`tx
// status`) positively settles it later: confirmed/broadcast ⇒ commit; a permanent
// reject flips the record to `failed`, releasing the reservation.
//
// Only a reservation whose record is DEFINITIVELY pre-broadcast is released here:
//   - rec == nil: the reservation was taken in buildAndSign BEFORE journal.Append, so
//     a missing journal record means build/sign aborted before any bytes were ever
//     journaled — no broadcast was possible ⇒ release.
//   - rec.Status == failed: a positively-terminalized record (an abort before a
//     broadcast was recorded, or a permanent reject) ⇒ release.
func (s *Service) reconcilePolicyOrphans(ctx context.Context) {
	eng, err := s.openPolicyEngine(ctx)
	if err != nil {
		return // a seal failure surfaces on the next real op, not at Open
	}
	orphans, oerr := eng.Orphans(ctx)
	if oerr != nil || len(orphans) == 0 {
		return
	}
	// Index journal records by reservation id across all networks present in orphans.
	for _, o := range orphans {
		rec, jerr := s.journalByReservation(ctx, domainNetwork(o.Network), o.ID)
		if jerr != nil {
			// A journal-read fault (lock timeout from a concurrent process, an IO/
			// permission fault, a read-only state mount) is NOT a "no record" signal: the
			// journaled bytes MAY be live. Fail CLOSED — leave the orphan RESERVED (over-
			// counting is the safe direction) and let a later online settle resolve it.
			// Releasing here would refund a budget a live tx may already have consumed.
			continue
		}
		switch {
		case rec == nil:
			// No journal record references this reservation ⇒ the crash landed between
			// Reserve and journal.Append, so no signed bytes were ever journaled and no
			// broadcast was possible ⇒ release (free the budget).
			_ = eng.ReleaseOrphan(ctx, o.Network, o.ID)
		case rec.Status == "broadcast" || rec.Status == "confirmed" || rec.Status == "replaced":
			// `broadcast`/`confirmed`: the bytes reached (or will reach) the chain ⇒
			// commit. `replaced`: an RBF replacement superseded this record and charged
			// ONLY the fee DELTA over this original's reservation — so the original's
			// reservation must stay COMMITTED (counted), or the rolling-24h window
			// under-counts the live replacement's full outflow (releasing it here would
			// let an RBF cycle leak the original payment amount back into the budget).
			_ = eng.CommitOrphan(ctx, o.Network, o.ID, rec.Txid)
		case rec.Status == "failed":
			// Positively pre-broadcast: an abort-before-broadcast or a permanent reject
			// terminalized the record ⇒ no live bytes ⇒ release.
			_ = eng.ReleaseOrphan(ctx, o.Network, o.ID)
		default:
			// `signed` (or any not-yet-terminal state): the journaled bytes MAY be live on
			// the network and we cannot prove otherwise offline. Leave the reservation
			// RESERVED (fail closed); an online settle resolves it. NEVER release here.
		}
	}
}

// policyRotationFaultHook lets crash-point tests abort PolicyChangeAdminPassphrase at
// a named step ("after_stage" / "after_reseal" / "after_promote"), simulating a
// process kill that leaves the on-disk anchor + policy.json in whatever state the
// prior steps produced. Production leaves it nil. Test-only.
var policyRotationFaultHook func(point string) error

func firePolicyRotationFault(point string) error {
	if policyRotationFaultHook == nil {
		return nil
	}
	return policyRotationFaultHook(point)
}

// recoverPolicyRotation converges a half-finished staged admin-passphrase rotation
// (SI-1) at Open: it asks the engine which key policy.json verifies under and, if the
// anchor must change (roll forward = promote, roll back = drop the staged key), lands
// the converged anchor to the config class. Best-effort at the Open path (a converge
// failure surfaces on the next real op as a seal violation), but it RETURNS the error
// to the explicit pre-rotation caller so a new rotation never stacks on an
// unconverged one. With no staged rotation it is a no-op.
func (s *Service) recoverPolicyRotation(ctx context.Context, eng *policy.Engine) error {
	anchor, changed, rerr := eng.RecoverAdminRotation()
	if rerr != nil {
		return rerr
	}
	if !changed {
		return nil
	}
	// Land the converged anchor. On a read-only config mount we cannot rewrite it; the
	// dual-key anchor on disk still verifies policy.json (under whichever key it is
	// sealed), so the guardrails remain usable — swallow that one case.
	if werr := s.writeAnchor(ctx, anchor); werr != nil {
		if config.AnchorIsReadOnly(werr) {
			return nil
		}
		return werr
	}
	return nil
}

// reconcilePolicyRotation is the Open-path (best-effort) twin of
// recoverPolicyRotation: it converges an interrupted rotation without failing Open.
func (s *Service) reconcilePolicyRotation(ctx context.Context) {
	eng, err := s.openPolicyEngine(ctx)
	if err != nil {
		return // a seal failure surfaces on the next real op, not at Open
	}
	_ = s.recoverPolicyRotation(ctx, eng)
}

// journalByReservation finds the journal record cross-linked to a reservation id on
// a network (a small scan; the reconcile worklist is bounded by in-flight sends). It
// returns (nil, nil) ONLY when the journal genuinely has no record for the
// reservation; a journal-read fault is returned as a non-nil error so callers do NOT
// conflate "no record" (release-safe) with "could not read" (fail-closed). A nil
// journal is treated as "no record" (production always wires one).
func (s *Service) journalByReservation(ctx context.Context, net domain.Network, resID string) (*journal.Record, error) {
	if s.journal == nil {
		return nil, nil
	}
	recs, err := s.journal.List(ctx, net, "")
	if err != nil {
		return nil, err
	}
	for _, r := range recs {
		if r.ReservationID == resID {
			return r, nil
		}
	}
	return nil, nil
}

// domainNetwork narrows a network string to the domain type.
func domainNetwork(s string) domain.Network { return domain.Network(s) }

// acquireAdminPassphrase resolves the admin passphrase through the §3.6 precedence
// using the ADMIN channels (DAXIB_ADMIN_PASSPHRASE[_FILE] / --admin-passphrase-*),
// independent of the keystore passphrase.
func (s *Service) acquireAdminPassphrase(stdin bool, file string) (*secret.Bytes, error) {
	b, _, err := s.acquire(adminSpec(stdin, file, false))
	return b, err
}

func (s *Service) acquireAdminNewPassphrase(stdin bool, file string) (*secret.Bytes, error) {
	b, _, err := s.acquire(adminNewSpec(stdin, file, false))
	return b, err
}

// ── result types (the CLI imports service, never policy) ─────────────────────

// PolicyShowResult is `policy show` / `policy verify` output: the seal status plus
// the active limits (rendered as a flat view the CLI prints).
type PolicyShowResult struct {
	SealStatus policy.SealStatus `json:"seal"`
	Present    bool              `json:"present"`
	Network    string            `json:"network"`
	Default    LimitView         `json:"default"`
	Networks   []NetworkView     `json:"networks,omitempty"`
	Allowlist  []PinView         `json:"allowlist,omitempty"`
	Denylist   []PinView         `json:"denylist,omitempty"`
	SelfCount  int               `json:"self_addresses"`
}

// LimitView is a flattened, resolved limit set for rendering (null/absent collapsed
// to "" / false where the writer's tri-state is not needed by a reader).
type LimitView struct {
	MaxTxSat    string `json:"max_tx_sat,omitempty"`
	MaxDaySat   string `json:"max_day_sat,omitempty"`
	MaxFeeRate  string `json:"max_fee_rate_sat_vb,omitempty"`
	AllowlistOn bool   `json:"allowlist_enabled"`
	IncludeSelf bool   `json:"include_self"`
}

type NetworkView struct {
	Network string `json:"network"`
	LimitView
}

type PinView struct {
	Address string `json:"address"`
	Label   string `json:"label,omitempty"`
	AddedAt string `json:"added_at,omitempty"`
}

// PolicyMutationResult is returned by the admin mutations: the new anchor (so the
// CLI can emit it on a read-only config mount) plus a flag noting whether the anchor
// was written to disk or needs out-of-band landing.
type PolicyMutationResult struct {
	Anchor        AnchorView `json:"anchor"`
	AnchorWritten bool       `json:"anchor_written"`
	AnchorJSON    string     `json:"anchor_json,omitempty"` // emitted when the config mount is read-only
	Nonce         uint64     `json:"nonce"`
}

// AnchorView is the renderable anchor (the verify key + watermark; the salt is
// shown so an operator can audit/land it).
type AnchorView struct {
	VerifyKey      string `json:"verify_key"`
	VerifyKeyNext  string `json:"verify_key_next,omitempty"`
	Salt           string `json:"salt"`
	NonceWatermark uint64 `json:"nonce_watermark"`
}

func anchorView(a policyseal.Anchor) AnchorView {
	return AnchorView{
		VerifyKey:      a.VerifyKey,
		VerifyKeyNext:  a.VerifyKeyNext,
		Salt:           a.Salt,
		NonceWatermark: a.NonceWatermark,
	}
}

// PolicyReleaseResult is `policy release <id>` output: the released reservation id +
// network.
type PolicyReleaseResult struct {
	ReservationID string `json:"reservation_id"`
	Network       string `json:"network"`
	Released      bool   `json:"released"`
}

// PolicyCheckResult is `policy check` / dry-run evaluation output.
type PolicyCheckResult struct {
	Allowed    bool           `json:"allowed"`
	Code       string         `json:"code,omitempty"`
	Reason     string         `json:"reason,omitempty"`
	RetryAfter string         `json:"retry_after,omitempty"`
	Data       map[string]any `json:"data,omitempty"`
}

// PolicyCountersResult is `policy counters` output.
type PolicyCountersResult struct {
	Counters []policy.CounterUsage `json:"counters"`
}
