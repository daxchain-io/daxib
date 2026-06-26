package policy

import (
	"context"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/fsx"
	"github.com/daxchain-io/daxib/internal/policyseal"
)

// lockTimeout bounds the per-network policy flock (maps to state.lock_timeout).
const lockTimeout = 30 * time.Second

// Engine is the impure policy shell: it loads + verifies the sealed policy against
// the anchor, sums the rolling-24h window under a per-network flock, runs the pure
// Evaluate, and durably reserves spend BEFORE the caller can sign. It holds the
// config-class anchor (read by internal/config), the state-class dir (policy.json +
// counters), and an injected clock.
type Engine struct {
	dir         string            // state-class root (policy.json + policy/spend/<net>.json)
	anchor      policyseal.Anchor // config-class trust root
	anchorFound bool              // false + no policy.json ⇒ permissive no-op
	clock       func() time.Time
	mu          sync.Map // per-network in-process mutex (taken before flock)

	// activeNonce is the loaded policy nonce (stamped into counter writes). Set on
	// each load; 0 when no policy.
	activeNonce uint64

	// lightKDF forces the cheap admin scrypt cost at BOOTSTRAP only (the first
	// InitSeal). Set from DAXIB_KDF_LIGHT so the CLI/integration tests stay fast; it
	// has NO effect on an already-pinned anchor (the anchor's pinned params win).
	lightKDF bool
}

// SetLightKDF forces the cheap admin scrypt cost at bootstrap (tests). It has no
// effect once an anchor is pinned (the anchor's params are authoritative).
func (e *Engine) SetLightKDF(v bool) { e.lightKDF = v }

// bootstrapParams returns the scrypt cost for a fresh anchor: the cheap test cost
// when lightKDF is set, else the production default (N=2^17).
func (e *Engine) bootstrapParams() policyseal.ScryptParams {
	if e.lightKDF {
		return policyseal.ScryptParams{N: 1 << 4, R: 8, P: 1}
	}
	return policyseal.DefaultScryptParams()
}

// Open builds an engine rooted at the state dir, holding the (possibly absent)
// anchor. It is lazy: it creates nothing until the first Reserve/mutation. A nil
// clock defaults to time.Now.
func Open(stateDir string, anchor policyseal.Anchor, anchorFound bool, clock func() time.Time) (*Engine, error) {
	if stateDir == "" {
		return nil, errState("policy engine: empty state dir", nil)
	}
	if clock == nil {
		clock = time.Now
	}
	return &Engine{dir: stateDir, anchor: anchor, anchorFound: anchorFound, clock: clock}, nil
}

// policyPath is <stateDir>/policy.json.
func (e *Engine) policyPath() string { return filepath.Join(e.dir, "policy.json") }

func (e *Engine) now() time.Time { return e.clock() }

// Anchor returns the engine's pinned anchor (for `policy pin --print`).
func (e *Engine) Anchor() policyseal.Anchor { return e.anchor }

// AnchorFound reports whether an anchor is pinned.
func (e *Engine) AnchorFound() bool { return e.anchorFound }

// loadActive loads + verifies the active policy against the anchor, enforcing the
// fail-closed asymmetry:
//
//   - no anchor + no policy.json ⇒ permissive (present=false, nil) — opt-in.
//   - anchor present + policy missing/unverifiable ⇒ seal_violation.
//   - policy present + anchor missing ⇒ seal_violation.
//   - body.nonce < anchor.watermark ⇒ rollback.
//   - unknown body field / future version ⇒ version refusal.
//
// On success it records activeNonce for counter stamping.
func (e *Engine) loadActive() (lr loadResult, present bool, err error) {
	raw, rerr := os.ReadFile(e.policyPath()) // #nosec G304 -- fixed join of the configured state dir
	policyExists := rerr == nil
	if rerr != nil && !os.IsNotExist(rerr) {
		return loadResult{}, false, errSeal("unreadable", "cannot read policy.json: "+rerr.Error())
	}

	switch {
	case !e.anchorFound && !policyExists:
		return loadResult{}, false, nil // permissive opt-in
	case !e.anchorFound && policyExists:
		return loadResult{}, false, errSeal("anchor_missing", "policy.json is present but no anchor is pinned; refusing (fail-closed)")
	case e.anchorFound && !policyExists:
		return loadResult{}, false, errSeal("missing", "an anchor is pinned but policy.json is missing; refusing (fail-closed)")
	}

	env, body, derr := decodeEnvelope(raw)
	if derr != nil {
		return loadResult{}, false, derr
	}
	sig, berr := decodeBase64(env.Seal.Sig)
	if berr != nil {
		return loadResult{}, false, errSeal("unparseable", "policy.json seal signature is not valid base64")
	}
	if !verifyUnderAnchor(body, sig, e.anchor) {
		return loadResult{}, false, errSeal("bad_sig", "policy.json seal does not verify under the pinned anchor key")
	}
	pol, perr := decodeBodyStrict(body)
	if perr != nil {
		return loadResult{}, false, perr
	}
	if pol.Nonce < e.anchor.NonceWatermark {
		return loadResult{}, false, errRollback(pol.Nonce, e.anchor.NonceWatermark)
	}
	e.activeNonce = pol.Nonce
	return loadResult{policy: pol, bodyRaw: body, seal: env.Seal}, true, nil
}

// Show returns the active policy plus a seal-status summary. It is unauthenticated
// (no passphrase) and read-only.
func (e *Engine) Show() (Policy, SealStatus, error) {
	lr, present, err := e.loadActive()
	st := SealStatus{AnchorFound: e.anchorFound, Watermark: e.anchor.NonceWatermark}
	if err != nil {
		st.Reason = domain.AsError(err).Code
		return Policy{}, st, err
	}
	if !present {
		st.Present = false
		return Policy{}, st, nil
	}
	st.Present = true
	st.Verified = true
	st.Nonce = lr.policy.Nonce
	st.WrittenBy = lr.policy.WrittenBy
	return lr.policy, st, nil
}

// SealStatus is the unauthenticated health summary surfaced by `policy show` /
// `policy verify`.
type SealStatus struct {
	Present     bool   `json:"present"`
	AnchorFound bool   `json:"anchor_found"`
	Verified    bool   `json:"verified"`
	Nonce       uint64 `json:"nonce"`
	Watermark   uint64 `json:"watermark"`
	WrittenBy   string `json:"written_by,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// Verify reports whether policy.json verifies under the pinned anchor (passphrase-
// free, CI-friendly). With no anchor and no policy it is a clean "verified: opt-in"
// (no error). Any seal/rollback/version failure returns the typed error (exit 8).
func (e *Engine) Verify() (SealStatus, error) {
	_, st, err := e.Show()
	return st, err
}

// VerifyUnderKey reports whether policy.json verifies under a SUPPLIED candidate
// verify key (the `policy pin --verify <key>` canary). Passphrase-free. Returns a
// seal_violation when it does not verify.
func (e *Engine) VerifyUnderKey(candidate string) error {
	raw, rerr := os.ReadFile(e.policyPath()) // #nosec G304
	if rerr != nil {
		return errSeal("missing", "policy.json is not present")
	}
	_, body, derr := decodeEnvelope(raw)
	if derr != nil {
		return derr
	}
	env, _, _ := decodeEnvelope(raw)
	sig, berr := decodeBase64(env.Seal.Sig)
	if berr != nil {
		return errSeal("unparseable", "seal signature is not valid base64")
	}
	probe := policyseal.Anchor{VerifyKey: candidate}
	pk, kerr := probe.VerifyKeyBytes()
	if kerr != nil {
		return errSeal("bad_key", "the supplied verify key is malformed")
	}
	if !policyseal.Verify(body, sig, pk) {
		return errSeal("bad_sig", "policy.json does not verify under the supplied key")
	}
	return nil
}

// Check is the dry-run evaluation path (`policy check` / send --dry-run): it
// verifies the seal + sums the window READ-ONLY and runs Evaluate, writing NO
// reservation. With no active policy it is permissive (Allowed=true).
func (e *Engine) Check(ctx context.Context, req Check) (Decision, error) {
	lr, present, err := e.loadActive()
	if err != nil {
		return Decision{}, err
	}
	if !present {
		return Decision{Allowed: true}, nil
	}
	var spent *big.Int
	serr := e.withNetworkLock(ctx, req.Network, func() error {
		cf, lerr := e.loadCounter(req.Network)
		if lerr != nil {
			return lerr
		}
		spent = sumWindow(cf, e.now(), "")
		return nil
	})
	if serr != nil {
		return Decision{}, serr
	}
	return Evaluate(lr.policy, req, spent, e.now()), nil
}

// Counters returns the current rolling-24h usage per network (the networks that
// have a counter file). Read-only, passphrase-free.
func (e *Engine) Counters(ctx context.Context) ([]CounterUsage, error) {
	dir := filepath.Join(e.dir, "policy", "spend")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, errState("reading spend dir", err)
	}
	var out []CounterUsage
	for _, de := range entries {
		name := de.Name()
		if de.IsDir() || filepath.Ext(name) != ".json" {
			continue
		}
		net := name[:len(name)-len(".json")]
		var usage CounterUsage
		lerr := e.withNetworkLock(ctx, net, func() error {
			cf, e2 := e.loadCounter(net)
			if e2 != nil {
				return e2
			}
			usage = CounterUsage{
				Network:      net,
				Used24hSat:   sumWindow(cf, e.now(), "").String(),
				Reservations: len(cf.Entries),
			}
			return nil
		})
		if lerr != nil {
			return nil, lerr
		}
		out = append(out, usage)
	}
	return out, nil
}

// CounterUsage is one network's rolling-24h usage.
type CounterUsage struct {
	Network      string `json:"network"`
	Used24hSat   string `json:"used_24h_sat"`
	Reservations int    `json:"reservations"`
}

// ── the spend reservation lifecycle ──────────────────────────────────────────

// Reservation is a durable spend reservation handle returned by Reserve. The caller
// Commits it on broadcast accepted, or Releases it on a pre-sign failure. ID is
// persisted (recorded in the journal record for crash reconciliation).
type Reservation struct {
	id      string
	network string
	sat     int64
	engine  *Engine
	noop    bool // permissive (no active policy): commit/release are no-ops
}

// ID returns the reservation id (recorded in the journal for reconciliation).
func (r Reservation) ID() string { return r.id }

// Reserve verifies the seal + anti-rollback nonce, sums the rolling-24h window
// under the per-network flock, runs Evaluate, and — if allowed — atomically appends
// a {id, sat, reserved} entry to the per-network counter BEFORE the caller can
// sign. A denied check writes NOTHING and returns a typed policy.denied.* error
// (exit 3). With no active policy it returns a no-op reservation (permissive).
//
// MUST be called AFTER the tx is built and BEFORE Signer signs (§2.7/§5.1) — the
// reservation is durable before any signature exists, so a compromised agent
// SIGKILLing itself to dodge the counter gains nothing.
func (e *Engine) Reserve(ctx context.Context, req Check) (Reservation, error) {
	lr, present, err := e.loadActive()
	if err != nil {
		return Reservation{}, err
	}
	if !present {
		return Reservation{engine: e, noop: true}, nil
	}

	var res Reservation
	lerr := e.withNetworkLock(ctx, req.Network, func() error {
		cf, cerr := e.loadCounter(req.Network)
		if cerr != nil {
			return cerr
		}
		spent := sumWindow(cf, e.now(), "")
		d := Evaluate(lr.policy, req, spent, e.now())
		if !d.Allowed {
			return decisionError(d)
		}
		now := e.now()
		id := ulid(now)
		// The counter row records the WINDOW charge (delta for an RBF replacement,
		// full spend for a normal send), so the rolling-24h sum never double-counts an
		// original payment a replacement supersedes.
		charge := req.windowCharge()
		cf.Entries = append(cf.Entries, counterEntry{
			ID:    id,
			TS:    now.UTC().Format(time.RFC3339Nano),
			Sat:   big.NewInt(charge).String(),
			State: stateReserved,
		})
		if werr := e.writeCounter(req.Network, cf, now); werr != nil {
			return werr
		}
		res = Reservation{id: id, network: req.Network, sat: charge, engine: e}
		return nil
	})
	if lerr != nil {
		return Reservation{}, lerr
	}
	return res, nil
}

// Commit promotes a reservation reserved→committed (broadcast accepted). Idempotent;
// a no-op reservation does nothing. The txid is recorded for audit.
func (r Reservation) Commit(ctx context.Context, txid string) error {
	if r.noop || r.engine == nil {
		return nil
	}
	return r.engine.transition(ctx, r.network, r.id, stateCommitted, txid)
}

// Release frees a reservation reserved→released (a pre-sign / permanent-reject
// failure). Idempotent; a no-op reservation does nothing. NEVER release a committed
// reservation (over-counting is the safe direction).
func (r Reservation) Release(ctx context.Context) error {
	if r.noop || r.engine == nil {
		return nil
	}
	return r.engine.transition(ctx, r.network, r.id, stateReleased, "")
}

// transition flips a counter entry's state under the per-network lock. A committed
// row is never moved to released (the safe direction).
func (e *Engine) transition(ctx context.Context, network, id, to, txid string) error {
	return e.withNetworkLock(ctx, network, func() error {
		cf, err := e.loadCounter(network)
		if err != nil {
			return err
		}
		ent := cf.findEntry(id)
		if ent == nil {
			return nil // already pruned / unknown — idempotent
		}
		if ent.State == stateCommitted && to == stateReleased {
			return nil // never release a committed spend
		}
		ent.State = to
		if txid != "" {
			ent.Hash = txid
		}
		return e.writeCounter(network, cf, e.now())
	})
}

// ── orphan reconciliation (driven by service at Open) ────────────────────────

// OrphanReservation is a still-reserved counter row left by a crash. service reads
// each one against the journal: a record that reached `broadcast` ⇒ CommitOrphan;
// still `signed`/absent ⇒ ReleaseOrphan.
type OrphanReservation struct {
	ID      string `json:"id"`
	Network string `json:"network"`
	Sat     string `json:"sat"`
}

// Orphans returns every still-reserved entry across all per-network counters.
func (e *Engine) Orphans(ctx context.Context) ([]OrphanReservation, error) {
	dir := filepath.Join(e.dir, "policy", "spend")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, errState("reading spend dir", err)
	}
	var out []OrphanReservation
	for _, de := range entries {
		name := de.Name()
		if de.IsDir() || filepath.Ext(name) != ".json" {
			continue
		}
		net := name[:len(name)-len(".json")]
		lerr := e.withNetworkLock(ctx, net, func() error {
			cf, e2 := e.loadCounter(net)
			if e2 != nil {
				return e2
			}
			for _, ent := range cf.Entries {
				if ent.State == stateReserved {
					out = append(out, OrphanReservation{ID: ent.ID, Network: net, Sat: ent.Sat})
				}
			}
			return nil
		})
		if lerr != nil {
			return nil, lerr
		}
	}
	return out, nil
}

// CommitOrphan / ReleaseOrphan are the reconcile twins of Commit/Release.
func (e *Engine) CommitOrphan(ctx context.Context, network, id, txid string) error {
	return e.transition(ctx, network, id, stateCommitted, txid)
}

func (e *Engine) ReleaseOrphan(ctx context.Context, network, id string) error {
	return e.transition(ctx, network, id, stateReleased, "")
}

// ── locking ──────────────────────────────────────────────────────────────────

// withNetworkLock takes the per-network in-process mutex THEN the cross-process
// flock (fixed order), runs fn, and releases both. A flock timeout maps to
// state.lock_timeout (exit 11).
func (e *Engine) withNetworkLock(ctx context.Context, network string, fn func() error) error {
	muAny, _ := e.mu.LoadOrStore(network, &sync.Mutex{})
	mu := muAny.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()

	locksDir := filepath.Join(e.dir, "policy", "locks")
	if err := fsx.MkdirAll(locksDir, 0o700); err != nil {
		if fsx.IsReadOnly(err) {
			return errState("policy lock dir is read-only", err)
		}
		return errState("creating policy lock dir", err)
	}
	lockBase := filepath.Join(locksDir, "spend-"+network)
	lctx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()
	unlock, err := fsx.Lock(lctx, lockBase)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return domain.New("state.lock_timeout", "timed out acquiring the policy spend lock")
		}
		return errState("acquiring policy spend lock", err)
	}
	defer unlock()
	return fn()
}

// decisionError turns a denied Decision into a typed domain error carrying the
// canonical code + data (retryable on the day limit).
func decisionError(d Decision) error {
	e := domain.New(d.Code, d.Reason)
	if d.Data != nil {
		e = domain.WithData(e, d.Data)
	}
	return e
}

// decodeBase64 decodes a standard base64 string.
func decodeBase64(s string) ([]byte, error) {
	return base64Decode(s)
}
