package policy

import (
	"math/big"
	"strings"
	"time"
)

// Check is one spend to evaluate (the built tx, BEFORE signing). Amounts are in
// sats. Recipient is the --to address; ChangeAddr / SelfHints carry the wallet's
// own addresses for the include_self gate (the engine fills SelfHints from the
// SEALED self_addresses snapshot — NOT the live keystore — so include_self can't be
// gamed by importing an attacker key).
type Check struct {
	Network   string
	Recipient string // the payee address (--to)
	AmountSat int64  // recipient value
	FeeSat    int64  // absolute fee
	FeeRate   int64  // sat/vB
	// ChangeAddr is the wallet-owned change address for this tx ("" when none); it
	// always passes include_self (change returns to the wallet).
	ChangeAddr string
}

// spendSat is amount + fee — the total outflow charged against max_tx and the
// rolling-24h window (fee included, anti-fee-burn).
func (c Check) spendSat() int64 { return c.AmountSat + c.FeeSat }

// Decision is the verdict of a pure Evaluate. Allowed=false carries the canonical
// policy.denied.<reason> Code, a human Reason, and structured Data (limits,
// attempted, retry_after).
type Decision struct {
	Allowed    bool
	Code       string
	Reason     string
	RetryAfter string // RFC3339 for a retryable day-limit denial
	Data       map[string]any
}

// resolvedLimits is the per-network effective limit set (default block with
// per-network overrides applied tri-state). A nil *big.Int limit means "no limit".
type resolvedLimits struct {
	maxTx       *big.Int
	maxDay      *big.Int
	maxFeeRate  *big.Int
	allowlistOn bool
	includeSelf bool
}

// Evaluate is PURE: no I/O, no lock, no clock read beyond the now parameter. It
// runs the full BTC rule set in one deterministic, table-testable function. The
// caller supplies the already-summed rolling-24h window total (spentWindowSat) and
// the clock instant, so the window POLICY lives in how the caller computes
// spentWindowSat (filter ts > now-24h).
//
// Precedence: denylist > allowlist > include_self. Then per-tx, then daily
// (rolling-24h, fee included), then fee-rate cap. The FIRST violation in precedence
// order is returned (signing halts at the first hard refusal).
func Evaluate(p Policy, req Check, spentWindowSat *big.Int, now time.Time) Decision {
	lim := resolveLimits(p, req.Network)

	// Stage 1: denylist (beats everything).
	if matchPinAddr(p.Denylist, req.Recipient) {
		return Decision{
			Allowed: false, Code: codeDeniedDenylisted,
			Reason: "recipient is on the denylist",
			Data:   map[string]any{"address": req.Recipient},
		}
	}

	// Stage 2: allowlist gate (when enabled). The recipient must be allowlisted, or
	// be a self/change address when include_self is on.
	if lim.allowlistOn {
		ok := matchPinAddr(p.Allowlist, req.Recipient)
		if !ok && lim.includeSelf {
			ok = isSelf(p, req)
		}
		if !ok {
			return Decision{
				Allowed: false, Code: codeDeniedNotAllowlist,
				Reason: "recipient is not on the allowlist (and include_self did not apply)",
				Data: map[string]any{
					"address":      req.Recipient,
					"include_self": lim.includeSelf,
				},
			}
		}
	}

	// Stage 3: per-tx limit (amount + fee).
	if lim.maxTx != nil {
		spend := big.NewInt(req.spendSat())
		if spend.Cmp(lim.maxTx) > 0 {
			return Decision{
				Allowed: false, Code: codeDeniedTxLimit,
				Reason: "spend (amount + fee) exceeds the per-tx limit",
				Data: map[string]any{
					"limit_sat":     lim.maxTx.String(),
					"attempted_sat": spend.String(),
					"network":       req.Network,
				},
			}
		}
	}

	// Stage 4: rolling-24h daily limit (fee included).
	if lim.maxDay != nil {
		window := spentWindowSat
		if window == nil {
			window = big.NewInt(0)
		}
		used := new(big.Int).Add(window, big.NewInt(req.spendSat()))
		if used.Cmp(lim.maxDay) > 0 {
			retry := now.Add(24 * time.Hour).UTC().Format(time.RFC3339)
			return Decision{
				Allowed: false, Code: codeDeniedDayLimit,
				Reason:     "spend would exceed the rolling-24h limit",
				RetryAfter: retry,
				Data: map[string]any{
					"limit_sat":     lim.maxDay.String(),
					"used_24h_sat":  window.String(),
					"attempted_sat": big.NewInt(req.spendSat()).String(),
					"retry_after":   retry,
					"network":       req.Network,
				},
			}
		}
	}

	// Stage 5: fee-rate cap (anti-fee-burn).
	if lim.maxFeeRate != nil {
		rate := big.NewInt(req.FeeRate)
		if rate.Cmp(lim.maxFeeRate) > 0 {
			return Decision{
				Allowed: false, Code: codeDeniedFeeRate,
				Reason: "fee rate exceeds the max-fee-rate cap",
				Data: map[string]any{
					"cap_sat_vb":       lim.maxFeeRate.String(),
					"attempted_sat_vb": rate.String(),
					"network":          req.Network,
				},
			}
		}
	}

	return Decision{Allowed: true}
}

// resolveLimits applies the per-network override (tri-state) over the default
// block. Default-block nil = no limit; per-network absent = inherit; per-network
// null = lift the limit.
func resolveLimits(p Policy, network string) resolvedLimits {
	d := p.Rules.Default
	r := resolvedLimits{
		maxTx:       parseSat(d.MaxTxSat),
		maxDay:      parseSat(d.MaxDaySat),
		maxFeeRate:  parseSat(d.MaxFeeRate),
		allowlistOn: boolOr(d.AllowlistOn, false),
		includeSelf: boolOr(d.IncludeSelf, false),
	}
	for _, n := range p.Rules.Networks {
		if !strings.EqualFold(n.Network, network) {
			continue
		}
		r.maxTx = overrideSat(r.maxTx, n.MaxTxSat)
		r.maxDay = overrideSat(r.maxDay, n.MaxDaySat)
		r.maxFeeRate = overrideSat(r.maxFeeRate, n.MaxFeeRate)
		if n.AllowlistOn != nil {
			r.allowlistOn = *n.AllowlistOn
		}
		if n.IncludeSelf != nil {
			r.includeSelf = *n.IncludeSelf
		}
		break
	}
	return r
}

// parseSat converts a tri-state limit pointer to a *big.Int (nil = no limit; null
// sentinel = no limit; a decimal string = the limit).
func parseSat(p *string) *big.Int {
	if p == nil || *p == nullSentinel {
		return nil
	}
	v, ok := new(big.Int).SetString(*p, 10)
	if !ok {
		return nil
	}
	return v
}

// overrideSat applies a per-network override: nil pointer = inherit current; null
// sentinel = lift the limit (nil); a value = enforce it.
func overrideSat(current *big.Int, p *string) *big.Int {
	if p == nil {
		return current // inherit
	}
	if *p == nullSentinel {
		return nil // explicit null: no limit on this network
	}
	v, ok := new(big.Int).SetString(*p, 10)
	if !ok {
		return current
	}
	return v
}

func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

// matchPinAddr reports whether dest matches any address pin (case-insensitive).
func matchPinAddr(pins []PinEntry, dest string) bool {
	for _, p := range pins {
		if p.Source == "address" && strings.EqualFold(p.Address, dest) {
			return true
		}
	}
	return false
}

// isSelf reports whether the recipient is a wallet-owned address: the tx's own
// change address, or one of the SEALED self_addresses snapshot. Comparing against
// the sealed snapshot (not the live keystore) is what stops a prompt-compromised
// agent from importing an attacker key to mint itself an allowlisted destination.
func isSelf(p Policy, req Check) bool {
	if req.ChangeAddr != "" && strings.EqualFold(req.ChangeAddr, req.Recipient) {
		return true
	}
	for _, a := range p.SelfAddresses {
		if strings.EqualFold(a, req.Recipient) {
			return true
		}
	}
	return false
}
