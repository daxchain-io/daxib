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
// Open: a reservation whose journal record reached `broadcast` ⇒ commit; still
// `signed`/absent ⇒ release. Best-effort (never fails Open). It is the policy-side
// twin of the journal reconcile (policy may not import journal, so service drives it).
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
		rec := s.journalByReservation(ctx, domainNetwork(o.Network), o.ID)
		switch {
		case rec == nil:
			// No journal record references this reservation ⇒ no bytes were ever
			// broadcast ⇒ release (free the budget).
			_ = eng.ReleaseOrphan(ctx, o.Network, o.ID)
		case rec.Status == "broadcast" || rec.Status == "confirmed" || rec.Status == "replaced":
			// `broadcast`/`confirmed`: the bytes reached (or will reach) the chain ⇒
			// commit. `replaced`: an RBF replacement superseded this record and charged
			// ONLY the fee DELTA over this original's reservation — so the original's
			// reservation must stay COMMITTED (counted), or the rolling-24h window
			// under-counts the live replacement's full outflow (releasing it here would
			// let an RBF cycle leak the original payment amount back into the budget).
			_ = eng.CommitOrphan(ctx, o.Network, o.ID, rec.Txid)
		default: // still `signed`/`failed` ⇒ no recorded broadcast ⇒ release
			_ = eng.ReleaseOrphan(ctx, o.Network, o.ID)
		}
	}
}

// journalByReservation finds the journal record cross-linked to a reservation id on
// a network (a small scan; the reconcile worklist is bounded by in-flight sends).
func (s *Service) journalByReservation(ctx context.Context, net domain.Network, resID string) *journal.Record {
	if s.journal == nil {
		return nil
	}
	recs, err := s.journal.List(ctx, net, "")
	if err != nil {
		return nil
	}
	for _, r := range recs {
		if r.ReservationID == resID {
			return r
		}
	}
	return nil
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
