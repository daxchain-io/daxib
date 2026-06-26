package service

import (
	"context"

	"github.com/daxchain-io/daxib/internal/config"
	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/policy"
	"github.com/daxchain-io/daxib/internal/policyseal"
	"github.com/daxchain-io/daxib/internal/version"
)

// PolicyShowInput / PolicySetInput / PolicyPinInput / PolicyAdminInput carry the
// CLI flags into the service. Admin mutations carry the admin-passphrase channel
// (stdin/file); env channels are resolved by the §3.6 resolver.

// PolicyShow returns the active policy + seal status (unauthenticated, read-only).
func (s *Service) PolicyShow(ctx context.Context) (PolicyShowResult, error) {
	eng, err := s.openPolicyEngine(ctx)
	if err != nil {
		return PolicyShowResult{}, err
	}
	pol, st, serr := eng.Show()
	res := PolicyShowResult{SealStatus: st, Network: string(s.net), Present: st.Present}
	if serr != nil {
		return res, serr
	}
	if st.Present {
		res.Default = limitView(pol.Rules.Default)
		for _, n := range pol.Rules.Networks {
			res.Networks = append(res.Networks, NetworkView{Network: n.Network, LimitView: limitView(n.Limits)})
		}
		for _, p := range pol.Allowlist {
			res.Allowlist = append(res.Allowlist, PinView{Address: p.Address, Label: p.Label, AddedAt: p.AddedAt})
		}
		for _, p := range pol.Denylist {
			res.Denylist = append(res.Denylist, PinView{Address: p.Address, Label: p.Label, AddedAt: p.AddedAt})
		}
		res.SelfCount = len(pol.SelfAddresses)
	}
	return res, nil
}

// PolicyVerify reports whether policy.json verifies under the pinned anchor
// (passphrase-free). A failure returns the typed seal/rollback error (exit 8).
func (s *Service) PolicyVerify(ctx context.Context) (policy.SealStatus, error) {
	eng, err := s.openPolicyEngine(ctx)
	if err != nil {
		return policy.SealStatus{}, err
	}
	return eng.Verify()
}

// PolicyPinPrint returns the pinned anchor JSON for re-emit/diff (passphrase-free).
func (s *Service) PolicyPinPrint(ctx context.Context) (AnchorView, string, error) {
	eng, err := s.openPolicyEngine(ctx)
	if err != nil {
		return AnchorView{}, "", err
	}
	if !eng.AnchorFound() {
		return AnchorView{}, "", domain.New("policy.seal_violation", "no policy anchor is pinned")
	}
	a := eng.Anchor()
	raw, merr := a.Marshal()
	if merr != nil {
		return AnchorView{}, "", domain.Wrap("policy.seal_violation", "encoding the anchor", merr)
	}
	return anchorView(a), string(raw), nil
}

// PolicyPinVerify is the `policy pin --verify <key>` canary: does policy.json verify
// under the SUPPLIED candidate key? Passphrase-free; a non-verify is a seal_violation.
func (s *Service) PolicyPinVerify(ctx context.Context, candidate string) error {
	eng, err := s.openPolicyEngine(ctx)
	if err != nil {
		return err
	}
	return eng.VerifyUnderKey(candidate)
}

// PolicyCheck is the dry-run evaluation (`policy check --to --amount`): it resolves
// the fee rate (explicit or a flat estimate is NOT needed — the check uses the
// supplied/zero fee), runs Evaluate, and writes NO reservation. A denied check is a
// policy.denied.* error (exit 3) carried up by the caller.
func (s *Service) PolicyCheck(ctx context.Context, in PolicyCheckInput) (PolicyCheckResult, error) {
	eng, err := s.openPolicyEngine(ctx)
	if err != nil {
		return PolicyCheckResult{}, err
	}
	amountSat, perr := domain.ParseAmountToSats(in.Amount)
	if perr != nil {
		return PolicyCheckResult{}, perr
	}
	d, cerr := eng.Check(ctx, policy.Check{
		Network:   string(s.net),
		Recipient: in.To,
		AmountSat: amountSat,
		FeeSat:    in.FeeSat,
		FeeRate:   in.FeeRate,
	})
	if cerr != nil {
		return PolicyCheckResult{}, cerr
	}
	return PolicyCheckResult{
		Allowed: d.Allowed, Code: d.Code, Reason: d.Reason,
		RetryAfter: d.RetryAfter, Data: d.Data,
	}, nil
}

// PolicyCounters returns the rolling-24h usage per network (read-only).
func (s *Service) PolicyCounters(ctx context.Context) (PolicyCountersResult, error) {
	eng, err := s.openPolicyEngine(ctx)
	if err != nil {
		return PolicyCountersResult{}, err
	}
	c, cerr := eng.Counters(ctx)
	if cerr != nil {
		return PolicyCountersResult{}, cerr
	}
	return PolicyCountersResult{Counters: c}, nil
}

// PolicySet applies a `policy set` mutation under the admin passphrase. The FIRST
// set bootstraps the anchor (generate keypair+salt+watermark 0). On a writable
// config it writes the anchor; on a read-only config it returns the anchor JSON for
// out-of-band landing (--anchor-out). It refuses to replace an existing trust root.
func (s *Service) PolicySet(ctx context.Context, in PolicySetInput) (PolicyMutationResult, error) {
	// Normalize + validate the limit flags FIRST so a malformed/unit-suffixed limit
	// can never reach the sealed body (where it would fail OPEN at eval).
	in, nerr := in.normalizeLimits()
	if nerr != nil {
		return PolicyMutationResult{}, nerr
	}
	eng, err := s.openPolicyEngine(ctx)
	if err != nil {
		return PolicyMutationResult{}, err
	}
	pass, perr := s.acquireAdminPassphrase(in.AdminStdin, in.AdminFile)
	if perr != nil {
		return PolicyMutationResult{}, perr
	}
	defer pass.Zero()

	self := s.selfSnapshot(ctx)
	writtenBy := version.Get().Version

	var anchor policyseal.Anchor
	if !eng.AnchorFound() {
		// First set: bootstrap the anchor, then apply the requested limits on top.
		a, ierr := eng.InitSeal(pass, self, writtenBy)
		if ierr != nil {
			return PolicyMutationResult{}, ierr
		}
		anchor = a
		// Apply the requested change to the freshly-sealed default body.
		if in.hasChange() {
			a2, serr := eng.Set(pass, in.toChange(self, writtenBy))
			if serr != nil {
				return PolicyMutationResult{}, serr
			}
			anchor = a2
		}
	} else {
		a, serr := eng.Set(pass, in.toChange(self, writtenBy))
		if serr != nil {
			return PolicyMutationResult{}, serr
		}
		anchor = a
	}
	return s.landAnchor(ctx, anchor, in.AnchorOut)
}

// PolicyAllow / PolicyDeny add or remove an address pin under the admin passphrase.
func (s *Service) PolicyAllow(ctx context.Context, in PolicyPinInput) (PolicyMutationResult, error) {
	return s.pinMutation(ctx, in, true)
}

func (s *Service) PolicyDeny(ctx context.Context, in PolicyPinInput) (PolicyMutationResult, error) {
	return s.pinMutation(ctx, in, false)
}

func (s *Service) pinMutation(ctx context.Context, in PolicyPinInput, allow bool) (PolicyMutationResult, error) {
	// Validate the address decodes for the active network (a bad pin is a usage error).
	if !in.Remove {
		if err := s.validateAddress(in.Address); err != nil {
			return PolicyMutationResult{}, err
		}
	}
	eng, err := s.openPolicyEngine(ctx)
	if err != nil {
		return PolicyMutationResult{}, err
	}
	pass, perr := s.acquireAdminPassphrase(in.AdminStdin, in.AdminFile)
	if perr != nil {
		return PolicyMutationResult{}, perr
	}
	defer pass.Zero()
	self := s.selfSnapshot(ctx)
	writtenBy := version.Get().Version

	var anchor policyseal.Anchor
	if allow {
		anchor, err = eng.Allow(pass, policy.AllowEntry{Address: in.Address, Label: in.Label, Remove: in.Remove, RefreshSelf: self, WrittenBy: writtenBy})
	} else {
		anchor, err = eng.Deny(pass, policy.DenyEntry{Address: in.Address, Label: in.Label, Remove: in.Remove, RefreshSelf: self, WrittenBy: writtenBy})
	}
	if err != nil {
		return PolicyMutationResult{}, err
	}
	return s.landAnchor(ctx, anchor, in.AnchorOut)
}

// PolicyReset reseals a fresh default body under the existing key family (admin-gated).
func (s *Service) PolicyReset(ctx context.Context, in PolicyAdminInput) (PolicyMutationResult, error) {
	eng, err := s.openPolicyEngine(ctx)
	if err != nil {
		return PolicyMutationResult{}, err
	}
	pass, perr := s.acquireAdminPassphrase(in.AdminStdin, in.AdminFile)
	if perr != nil {
		return PolicyMutationResult{}, perr
	}
	defer pass.Zero()
	anchor, rerr := eng.Reset(pass, s.selfSnapshot(ctx), version.Get().Version)
	if rerr != nil {
		return PolicyMutationResult{}, rerr
	}
	return s.landAnchor(ctx, anchor, in.AnchorOut)
}

// PolicyChangeAdminPassphrase rotates the admin passphrase (re-seal under a new key).
func (s *Service) PolicyChangeAdminPassphrase(ctx context.Context, in PolicyRotateInput) (PolicyMutationResult, error) {
	eng, err := s.openPolicyEngine(ctx)
	if err != nil {
		return PolicyMutationResult{}, err
	}
	cur, perr := s.acquireAdminPassphrase(in.AdminStdin, in.AdminFile)
	if perr != nil {
		return PolicyMutationResult{}, perr
	}
	defer cur.Zero()
	next, nerr := s.acquireAdminNewPassphrase(in.NewStdin, in.NewFile)
	if nerr != nil {
		return PolicyMutationResult{}, nerr
	}
	defer next.Zero()
	anchor, rerr := eng.ChangeAdminPassphrase(cur, next)
	if rerr != nil {
		return PolicyMutationResult{}, rerr
	}
	return s.landAnchor(ctx, anchor, in.AnchorOut)
}

// landAnchor writes the anchor to the config dir, or — on a read-only mount — emits
// it for out-of-band landing (the K8s ConfigMap path). The policy.json is already
// written (state class) by the engine BEFORE this call (the §4.7 two-domain order:
// policy file first, anchor second).
func (s *Service) landAnchor(ctx context.Context, anchor policyseal.Anchor, anchorOut string) (PolicyMutationResult, error) {
	res := PolicyMutationResult{Anchor: anchorView(anchor), Nonce: anchor.NonceWatermark}
	raw, merr := anchor.Marshal()
	if merr != nil {
		return res, domain.Wrap("policy.seal_violation", "encoding the anchor", merr)
	}
	werr := s.writeAnchor(ctx, anchor)
	if werr == nil {
		res.AnchorWritten = true
		return res, nil
	}
	if config.AnchorIsReadOnly(werr) {
		// Read-only config mount: emit the anchor JSON for the operator/CI to land.
		res.AnchorJSON = string(raw)
		if anchorOut != "" {
			if w := s.writeAnchorOut(anchorOut, raw); w != nil {
				return res, w
			}
		}
		return res, nil
	}
	return res, werr
}

// writeAnchorOut writes the anchor JSON to a staging path (the --anchor-out target).
func (s *Service) writeAnchorOut(path string, raw []byte) error {
	if err := fsxWriteAtomic(path, raw); err != nil {
		return domain.Wrap("config.invalid", "writing --anchor-out "+path, err)
	}
	return nil
}
