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
func (s *Service) PolicyShow(ctx context.Context, p domain.Principal) (PolicyShowResult, error) {
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
func (s *Service) PolicyVerify(ctx context.Context, p domain.Principal) (policy.SealStatus, error) {
	eng, err := s.openPolicyEngine(ctx)
	if err != nil {
		return policy.SealStatus{}, err
	}
	return eng.Verify()
}

// PolicyPinPrint returns the pinned anchor JSON for re-emit/diff (passphrase-free).
func (s *Service) PolicyPinPrint(ctx context.Context, p domain.Principal) (AnchorView, string, error) {
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
func (s *Service) PolicyPinVerify(ctx context.Context, p domain.Principal, candidate string) error {
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
func (s *Service) PolicyCheck(ctx context.Context, p domain.Principal, in PolicyCheckInput) (PolicyCheckResult, error) {
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
func (s *Service) PolicyCounters(ctx context.Context, p domain.Principal) (PolicyCountersResult, error) {
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
func (s *Service) PolicySet(ctx context.Context, p domain.Principal, in PolicySetInput) (PolicyMutationResult, error) {
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
func (s *Service) PolicyAllow(ctx context.Context, p domain.Principal, in PolicyPinInput) (PolicyMutationResult, error) {
	return s.pinMutation(ctx, in, true)
}

func (s *Service) PolicyDeny(ctx context.Context, p domain.Principal, in PolicyPinInput) (PolicyMutationResult, error) {
	return s.pinMutation(ctx, in, false)
}

func (s *Service) pinMutation(ctx context.Context, in PolicyPinInput, allow bool) (PolicyMutationResult, error) {
	// Pins are per-network (validated + sealed against the active family). Guard up
	// front so resolveDestination/validateAddress never run against a silently-defaulted
	// network (chainParams("")->MainNetParams). openPolicyEngine guards too, but it runs
	// AFTER validateAddress, so an unguarded pin would otherwise render the bad_address
	// message against a defaulted network. Fail closed with usage.network_required.
	if err := s.requireNetwork(); err != nil {
		return PolicyMutationResult{}, err
	}
	// Resolve a contact NAME to its pinned address first (a raw address falls
	// through unchanged), so `policy allow <contact-name>` pins the same address a
	// `tx send --to <contact-name>` would pay. A --remove by name resolves the same
	// way so the pin can be lifted by the name it was added under.
	resolved, rerr := s.resolveDestination(ctx, in.Address)
	if rerr != nil {
		return PolicyMutationResult{}, rerr
	}
	in.Address = resolved

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
func (s *Service) PolicyReset(ctx context.Context, p domain.Principal, in PolicyAdminInput) (PolicyMutationResult, error) {
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

// PolicyChangeAdminPassphrase rotates the admin passphrase via the SI-1 crash-safe
// staged protocol. It drives the three engine phases, landing the anchor between
// them so a crash at ANY point leaves policy.json verifiable (under the OLD or NEW
// key) and the guardrails intact:
//
//	STAGE   : land the dual-key anchor (OLD + staged NEW). The commit point — once on
//	          disk, recovery rolls forward/back. policy.json still verifies (under OLD).
//	RESEAL  : reseal policy.json under the NEW key (policy.json first; anchor unchanged).
//	PROMOTE : land the final single-NEW-key anchor.
//
// A crash before STAGE lands rolls back (no anchor change). A crash after STAGE but
// before RESEAL is rolled BACK by recovery (policy.json still under OLD). A crash
// after RESEAL is rolled FORWARD by recovery (policy.json under NEW ⇒ promote). The
// limits are never wiped.
func (s *Service) PolicyChangeAdminPassphrase(ctx context.Context, p domain.Principal, in PolicyRotateInput) (PolicyMutationResult, error) {
	eng, err := s.openPolicyEngine(ctx)
	if err != nil {
		return PolicyMutationResult{}, err
	}
	// Converge any prior interrupted rotation FIRST so we never stack a new rotation on
	// a staged anchor (mirrors the keystore rotation's recover-first discipline).
	if rerr := s.recoverPolicyRotation(ctx, eng); rerr != nil {
		return PolicyMutationResult{}, rerr
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

	// ── STAGE ──: land the dual-key anchor (the commit point).
	staged, serr := eng.StageAdminRotation(cur, next)
	if serr != nil {
		return PolicyMutationResult{}, serr
	}
	if werr := s.writeAnchor(ctx, staged); werr != nil {
		// A read-only config mount cannot land the staged anchor: the rotation has NOT
		// committed (policy.json is untouched, still under OLD). Surface the typed error
		// rather than reseal into an unverifiable state.
		return PolicyMutationResult{}, werr
	}
	if ferr := firePolicyRotationFault("after_stage"); ferr != nil {
		return PolicyMutationResult{}, ferr
	}

	// ── RESEAL ──: reseal policy.json under the NEW key.
	if rerr := eng.ResealUnderStagedRotation(next); rerr != nil {
		return PolicyMutationResult{}, rerr
	}
	if ferr := firePolicyRotationFault("after_reseal"); ferr != nil {
		return PolicyMutationResult{}, ferr
	}

	// ── PROMOTE ──: land the final single-key anchor.
	promoted, perr2 := eng.PromoteAdminRotation()
	if perr2 != nil {
		return PolicyMutationResult{}, perr2
	}
	res, lerr := s.landAnchor(ctx, promoted, in.AnchorOut)
	if lerr != nil {
		return PolicyMutationResult{}, lerr
	}
	if ferr := firePolicyRotationFault("after_promote"); ferr != nil {
		return PolicyMutationResult{}, ferr
	}
	return res, nil
}

// PolicyRelease frees a STUCK pre-signature spend reservation (`policy release
// <id>`, GAP-4). It is admin-gated (the engine authenticates the admin passphrase
// against the pinned verify key) and REFUSES a committed reservation — only a stuck
// pending reservation is releasable. No anchor is mutated (the sealed body is
// untouched), so there is no anchor to land.
func (s *Service) PolicyRelease(ctx context.Context, p domain.Principal, in PolicyReleaseInput) (PolicyReleaseResult, error) {
	if in.ReservationID == "" {
		return PolicyReleaseResult{}, domain.New(domain.CodeUsage+".missing_arg", "a reservation id is required")
	}
	eng, err := s.openPolicyEngine(ctx)
	if err != nil {
		return PolicyReleaseResult{}, err
	}
	pass, perr := s.acquireAdminPassphrase(in.AdminStdin, in.AdminFile)
	if perr != nil {
		return PolicyReleaseResult{}, perr
	}
	defer pass.Zero()
	if rerr := eng.ReleaseReservation(ctx, pass, string(s.net), in.ReservationID); rerr != nil {
		return PolicyReleaseResult{}, rerr
	}
	return PolicyReleaseResult{ReservationID: in.ReservationID, Network: string(s.net), Released: true}, nil
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
