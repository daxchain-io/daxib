package policy

import (
	"bytes"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/daxchain-io/daxib/internal/fsx"
)

// counterVersion is the on-disk counter schema version.
const counterVersion = 1

// window is the rolling spend window (24h). A debit at ts counts while
// ts > now-24h.
const window = 24 * time.Hour

// reservation states.
const (
	stateReserved  = "reserved"
	stateCommitted = "committed"
	stateReleased  = "released"
)

// counterFile is the durable rolling-24h spend ledger for ONE network (the
// aggregate-across-wallets cap is per-network, so one file per network under one
// per-network lock). Each entry is a timestamped reservation: {id, sat, state}. The
// window sum filters ts > now-24h; reserved+committed count, released does not.
//
// Fail-closed posture: an unparseable counter file is a policy.state_error (a
// reset/zeroed/corrupt counter must NOT silently re-widen the window). The
// CounterNonce records the policy generation the file was last written under (a
// tripwire that survives in the file for audit).
type counterFile struct {
	Version     int            `json:"version"`
	PolicyNonce uint64         `json:"policy_nonce"`
	Network     string         `json:"network"`
	Entries     []counterEntry `json:"entries"`
}

type counterEntry struct {
	ID    string `json:"id"`
	TS    string `json:"ts"`    // RFC3339Nano UTC
	Sat   string `json:"sat"`   // decimal (amount + fee)
	State string `json:"state"` // reserved|committed|released
	Hash  string `json:"hash,omitempty"`
}

// counterPath is <stateDir>/policy/spend/<network>.json.
func (e *Engine) counterPath(network string) string {
	return filepath.Join(e.dir, "policy", "spend", network+".json")
}

// loadCounter reads the per-network counter file (missing = empty, lazy). An
// unparseable file fails closed (policy.state_error). The caller MUST hold the
// per-network lock.
func (e *Engine) loadCounter(network string) (*counterFile, error) {
	path := e.counterPath(network)
	b, err := os.ReadFile(path) // #nosec G304 -- state path is a fixed join of the configured state dir
	if err != nil {
		if os.IsNotExist(err) {
			return &counterFile{Version: counterVersion, Network: network}, nil
		}
		return nil, errState("reading spend counter "+path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var cf counterFile
	if derr := dec.Decode(&cf); derr != nil {
		// A corrupt/zeroed counter must fail closed, never silently re-widen.
		return nil, errState("spend counter "+path+" is corrupt; refusing to proceed (fail-closed)", derr)
	}
	if cf.Network == "" {
		cf.Network = network
	}
	return &cf, nil
}

// writeCounter prunes terminal+aged entries and atomically writes the counter. The
// caller MUST hold the per-network lock.
func (e *Engine) writeCounter(network string, cf *counterFile, now time.Time) error {
	cf.Version = counterVersion
	cf.Network = network
	cf.PolicyNonce = e.activeNonce
	prune(cf, now)
	data, err := json.Marshal(cf)
	if err != nil {
		return errState("encoding spend counter", err)
	}
	dir := filepath.Dir(e.counterPath(network))
	if mkErr := fsx.MkdirAll(dir, 0o700); mkErr != nil {
		if fsx.IsReadOnly(mkErr) {
			return errState("spend counter dir is read-only", mkErr)
		}
		return errState("creating spend counter dir", mkErr)
	}
	if werr := fsx.WriteAtomic(e.counterPath(network), data, 0o600); werr != nil {
		return errState("writing spend counter", werr)
	}
	return nil
}

// sumWindow sums the in-window (ts > now-24h) NON-released debits, optionally
// excluding one entry by id (used so a reservation's own row is not double-counted
// when re-summing). The caller MUST hold the per-network lock.
func sumWindow(cf *counterFile, now time.Time, excludeID string) *big.Int {
	total := big.NewInt(0)
	cutoff := now.Add(-window)
	for _, e := range cf.Entries {
		if e.ID == excludeID {
			continue
		}
		if e.State == stateReleased {
			continue
		}
		ts, ok := parseTS(e.TS)
		// CB-1: an UNPARSEABLE timestamp counts as IN-window (the safe
		// over-counting direction for a fail-closed component). A reset/zeroed/corrupt
		// ts must never silently drop a committed debit out of the window.
		if ok && !ts.After(cutoff) {
			continue
		}
		v, vok := new(big.Int).SetString(e.Sat, 10)
		if !vok {
			continue
		}
		total.Add(total, v)
	}
	return total
}

// prune drops released entries and committed/reserved entries older than the window
// (the journal is the permanent audit record; the counter is the working set).
func prune(cf *counterFile, now time.Time) {
	cutoff := now.Add(-window)
	kept := cf.Entries[:0]
	for _, e := range cf.Entries {
		ts, ok := parseTS(e.TS)
		// CB-1: an UNPARSEABLE timestamp is treated as IN-window (never aged), so a
		// non-released row with a corrupt ts is KEPT (and thus still counted by
		// sumWindow) rather than silently dropped — the safe direction.
		aged := ok && !ts.After(cutoff)
		if e.State == stateReleased {
			// Drop released rows that have aged out; keep recent released rows so a
			// concurrent re-sum sees a consistent ledger (cheap; pruned next window).
			// A released row with a corrupt ts is dropped (it does not count anyway).
			if aged || !ok {
				continue
			}
		}
		if aged && e.State != stateReserved {
			// A committed debit that has aged out of the window no longer counts.
			continue
		}
		kept = append(kept, e)
	}
	cf.Entries = kept
}

// findEntry locates a reservation row by id.
func (cf *counterFile) findEntry(id string) *counterEntry {
	for i := range cf.Entries {
		if cf.Entries[i].ID == id {
			return &cf.Entries[i]
		}
	}
	return nil
}

// parseTS parses RFC3339Nano/RFC3339, returning (t, true) on success. On a parse
// failure it returns (zero, false); callers treat !ok as IN-window (sumWindow
// counts the row, prune keeps a non-released row) — the safe over-counting
// direction for the fail-closed counter (CB-1).
func parseTS(s string) (time.Time, bool) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, true
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, true
	}
	return time.Time{}, false
}
