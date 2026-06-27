package service

import (
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcutil"

	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/fsx"
	"github.com/daxchain-io/daxib/internal/policy"
)

// The CLI flag inputs for the policy noun. Admin mutations carry the
// admin-passphrase channel (stdin/file flags; env channels resolved by §3.6).

// PolicyCheckInput is `policy check --to --amount [--fee-rate]`.
type PolicyCheckInput struct {
	To      string
	Amount  string
	FeeSat  int64
	FeeRate int64
}

// PolicyAdminInput is the bare admin-gated input (reset).
type PolicyAdminInput struct {
	AdminStdin bool
	AdminFile  string
	AnchorOut  string
}

// PolicySetInput is `policy set` — the limit/gate flags plus the admin channel.
// Each limit is a tri-state STRING: "" = unset (leave unchanged); "none" = lift the
// limit (null); a decimal sat value = enforce it. Network scopes the rule (""=the
// default block). Allowlist/IncludeSelf are tri-state via their *bool.
type PolicySetInput struct {
	MaxTxSat    string // "" unset, "none" null, "<sat>" value
	MaxDaySat   string
	MaxFeeRate  string
	Network     string
	AllowlistOn *bool
	IncludeSelf *bool

	AdminStdin bool
	AdminFile  string
	AnchorOut  string
}

// PolicyPinInput is `policy allow|deny <address>`.
type PolicyPinInput struct {
	Address string
	Label   string
	Remove  bool

	AdminStdin bool
	AdminFile  string
	AnchorOut  string
}

// PolicyRotateInput is `policy change-admin-passphrase`.
type PolicyRotateInput struct {
	AdminStdin bool
	AdminFile  string
	NewStdin   bool
	NewFile    string
	AnchorOut  string
}

// PolicyReleaseInput is `policy release <reservation-id>` (GAP-4): the admin-gated
// release of a stuck pre-signature reservation.
type PolicyReleaseInput struct {
	ReservationID string
	AdminStdin    bool
	AdminFile     string
}

// hasChange reports whether a set input carries any limit/gate change to apply on
// top of a bootstrap.
func (in PolicySetInput) hasChange() bool {
	return in.MaxTxSat != "" || in.MaxDaySat != "" || in.MaxFeeRate != "" ||
		in.AllowlistOn != nil || in.IncludeSelf != nil
}

// toChange translates the CLI flags into a policy.Change. A "" limit leaves the
// field unchanged (nil pointer); "none" lifts it (null sentinel); a value enforces
// it. The change is applied to the default block, or to a per-network override when
// Network is set.
func (in PolicySetInput) toChange(self []string, writtenBy string) policy.Change {
	lim := policy.Limits{
		MaxTxSat:    triLimit(in.MaxTxSat),
		MaxDaySat:   triLimit(in.MaxDaySat),
		MaxFeeRate:  triLimit(in.MaxFeeRate),
		AllowlistOn: in.AllowlistOn,
		IncludeSelf: in.IncludeSelf,
	}
	c := policy.Change{RefreshSelf: self, WrittenBy: writtenBy}
	if in.Network != "" {
		c.Networks = []policy.NetworkRule{{Network: in.Network, Limits: lim}}
	} else {
		c.Default = &lim
	}
	return c
}

// normalizeLimits validates + canonicalizes the limit flags to BARE sat integers
// BEFORE they reach the sealed body. The flags are documented "in sats", so each is
// a non-negative whole number of sats (an optional "sat"/"sats" suffix is tolerated
// and stripped). This closes a fail-OPEN hole: an unvalidated unit-suffixed or
// malformed limit (e.g. "100000sat", "garbage") was previously stored verbatim and
// then parsed to "no limit" at eval, silently disabling the guardrail. "" leaves a
// field unchanged; "none"/"null" lifts it. A non-integer/negative value is a usage
// error (exit 2) — never silently stored.
func (in PolicySetInput) normalizeLimits() (PolicySetInput, error) {
	out := in
	var err error
	if out.MaxTxSat, err = normSatLimit("--max-tx", in.MaxTxSat); err != nil {
		return in, err
	}
	if out.MaxDaySat, err = normSatLimit("--max-day", in.MaxDaySat); err != nil {
		return in, err
	}
	if out.MaxFeeRate, err = normSatLimit("--max-fee-rate", in.MaxFeeRate); err != nil {
		return in, err
	}
	return out, nil
}

// normSatLimit canonicalizes one "in sats" limit flag: "", "none", "null" pass
// through; otherwise it must be a non-negative whole number of sats (an optional
// "sat"/"sats" suffix is tolerated), returned as a bare decimal string. A BTC-style
// or otherwise non-integer value is a usage error rather than silently-stored garbage.
func normSatLimit(flag, s string) (string, error) {
	switch s {
	case "", "none", "null":
		return s, nil
	}
	t := strings.TrimSpace(s)
	t = strings.TrimSuffix(t, "sats")
	t = strings.TrimSuffix(t, "sat")
	t = strings.TrimSpace(t)
	v, err := strconv.ParseInt(t, 10, 64)
	if err != nil || v < 0 {
		return "", domain.Newf(domain.CodeUsage+".limit",
			"invalid %s %q: want a non-negative whole number of sats (e.g. 100000 or 100000sat), or 'none' to lift", flag, s)
	}
	return strconv.FormatInt(v, 10), nil
}

// triLimit maps a CLI limit string to a tri-state pointer: "" → nil (unchanged);
// "none"/"null" → the null sentinel (lift the limit); a decimal string → the value.
func triLimit(s string) *string {
	switch s {
	case "":
		return nil
	case "none", "null":
		v := policy.NullSentinel()
		return &v
	default:
		v := s
		return &v
	}
}

// validateAddress checks an address decodes for the active network (a bad pin is a
// usage error, not an admin/seal failure).
func (s *Service) validateAddress(addr string) error {
	params := s.chainParams()
	a, err := btcutil.DecodeAddress(addr, params)
	if err != nil || !a.IsForNet(params) {
		return domain.Newf(domain.CodeUsageBadAddress, "%q is not a valid %s address", addr, s.net)
	}
	return nil
}

// limitView flattens a policy.Limits for rendering (null/absent collapse to ""; the
// CLI does not need the writer's tri-state distinction to display the policy).
func limitView(l policy.Limits) LimitView {
	return LimitView{
		MaxTxSat:    policy.LimitString(l.MaxTxSat),
		MaxDaySat:   policy.LimitString(l.MaxDaySat),
		MaxFeeRate:  policy.LimitString(l.MaxFeeRate),
		AllowlistOn: l.AllowlistOn != nil && *l.AllowlistOn,
		IncludeSelf: l.IncludeSelf != nil && *l.IncludeSelf,
	}
}

// fsxWriteAtomic is a thin wrapper so policy_ops.go can write the --anchor-out file
// without re-importing fsx there.
func fsxWriteAtomic(path string, raw []byte) error {
	return fsx.WriteAtomic(path, raw, 0o600)
}
