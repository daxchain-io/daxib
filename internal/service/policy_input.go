package service

import (
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
