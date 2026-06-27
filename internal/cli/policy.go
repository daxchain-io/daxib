package cli

import (
	"context"
	"io"

	"github.com/spf13/cobra"

	"github.com/daxchain-io/daxib/internal/cli/render"
	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/service"
)

// newPolicyCmd builds the `policy` noun — the M5 sealed spend-limit guardrails.
// Reads (show/verify/check/counters/pin) are passphrase-free; mutations
// (set/allow/deny/reset/change-admin-passphrase) require the admin passphrase
// (independent of the keystore passphrase). The frontend never touches the policy
// engine directly — every call goes through the service boundary (the arch lattice
// forbids cli→policy).
func newPolicyCmd(ctx context.Context, rs *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage the sealed spend-limit guardrails (operator-set, agent-immutable)",
		Long: "Policy is the security spine: an operator sets spend limits an autonomous\n" +
			"agent cannot raise. Limits are sealed (Ed25519 over scrypt(admin-passphrase))\n" +
			"and pinned in a machine-only anchor. show/verify/check/counters are read-only;\n" +
			"set/allow/deny/reset/change-admin-passphrase require the admin passphrase.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(
		newPolicyShowCmd(ctx, rs),
		newPolicySetCmd(ctx, rs),
		newPolicyAllowCmd(ctx, rs),
		newPolicyDenyCmd(ctx, rs),
		newPolicyVerifyCmd(ctx, rs),
		newPolicyCheckCmd(ctx, rs),
		newPolicyCountersCmd(ctx, rs),
		newPolicyResetCmd(ctx, rs),
		newPolicyPinCmd(ctx, rs),
		newPolicyChangeAdminCmd(ctx, rs),
		newPolicyReleaseCmd(ctx, rs),
	)
	return cmd
}

// newPolicyReleaseCmd builds `policy release <reservation-id>` (GAP-4): the
// admin-gated release of a STUCK pre-signature spend reservation (reserved →
// released), so a crash that stranded a reservation does not consume the rolling-24h
// budget forever. It REFUSES a committed reservation (only a pending one is
// releasable) and requires --yes (it mutates the spend ledger).
func newPolicyReleaseCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var af adminFlags
	cmd := &cobra.Command{
		Use:   "release <reservation-id>",
		Short: "Release a stuck pending spend reservation (admin passphrase; refuses a committed one)",
		Long: "Release frees a STUCK pre-signature spend reservation so a crash between\n" +
			"reserve and settle does not strand the rolling-24h budget. It is admin-gated and\n" +
			"refuses a COMMITTED reservation (whose spend reached the chain) — only a pending\n" +
			"reservation is releasable. Requires --yes (it mutates the spend ledger).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !rs.flags.Yes {
				return domain.New(domain.CodeUsageConfirmRequired, "releasing a reservation mutates the spend ledger; pass --yes to authorize")
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.PolicyRelease(cmd.Context(), service.PolicyReleaseInput{
				ReservationID: args[0], AdminStdin: af.stdin, AdminFile: af.file,
			})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "released reservation %s on %s", res.ReservationID, res.Network)
			})
		},
	}
	af.bind(cmd)
	return cmd
}

func newPolicyShowCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show the active policy + seal status (read-only)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.PolicyShow(cmd.Context())
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				renderPolicyShow(w, m, res)
			})
		},
	}
}

func newPolicySetCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var maxTx, maxDay, maxFeeRate, network, allowlist, includeSelf, anchorOut string
	var af adminFlags
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Set spend limits / gates (admin passphrase; FIRST set bootstraps the anchor)",
		Long: "Set guardrails under the admin passphrase. Limits accept a sat amount, the\n" +
			"literal 'none' to lift the limit, or are omitted to leave unchanged. The first\n" +
			"`policy set` bootstraps the anchor (a fresh keypair + salt + watermark). On a\n" +
			"read-only config mount the new anchor JSON is emitted for out-of-band landing.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			on, ierr := triBool(allowlist)
			if ierr != nil {
				return ierr
			}
			incl, ierr := triBool(includeSelf)
			if ierr != nil {
				return ierr
			}
			res, err := svc.PolicySet(cmd.Context(), service.PolicySetInput{
				MaxTxSat: maxTx, MaxDaySat: maxDay, MaxFeeRate: maxFeeRate,
				Network: network, AllowlistOn: on, IncludeSelf: incl,
				AdminStdin: af.stdin, AdminFile: af.file, AnchorOut: anchorOut,
			})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				renderPolicyMutation(w, m, res, "policy updated")
			})
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&maxTx, "max-tx", "", "per-tx limit in sats (amount+fee); 'none' to lift")
	fl.StringVar(&maxDay, "max-day", "", "rolling-24h limit in sats (fee included); 'none' to lift")
	fl.StringVar(&maxFeeRate, "max-fee-rate", "", "max fee rate in sat/vB (anti-fee-burn); 'none' to lift")
	fl.StringVar(&network, "network", "", "scope the rule to one network (default: the default block)")
	fl.StringVar(&allowlist, "allowlist", "", "require allowlisted recipients: on|off")
	fl.StringVar(&includeSelf, "include-self", "", "let own/change addresses pass the allowlist: on|off")
	fl.StringVar(&anchorOut, "anchor-out", "", "on a read-only config mount, write the anchor JSON here")
	af.bind(cmd)
	return cmd
}

func newPolicyAllowCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var remove bool
	var label, anchorOut string
	var af adminFlags
	cmd := &cobra.Command{
		Use:   "allow <address>",
		Short: "Add (or --remove) an allowlist address pin (admin passphrase)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.PolicyAllow(cmd.Context(), service.PolicyPinInput{
				Address: args[0], Label: label, Remove: remove,
				AdminStdin: af.stdin, AdminFile: af.file, AnchorOut: anchorOut,
			})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				renderPolicyMutation(w, m, res, "allowlist updated")
			})
		},
	}
	cmd.Flags().BoolVar(&remove, "remove", false, "remove the pin instead of adding it")
	cmd.Flags().StringVar(&label, "label", "", "operator note stored with the pin")
	cmd.Flags().StringVar(&anchorOut, "anchor-out", "", "on a read-only config mount, write the anchor JSON here")
	af.bind(cmd)
	return cmd
}

func newPolicyDenyCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var remove bool
	var label, anchorOut string
	var af adminFlags
	cmd := &cobra.Command{
		Use:   "deny <address>",
		Short: "Add (or --remove) a denylist address pin (admin passphrase)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.PolicyDeny(cmd.Context(), service.PolicyPinInput{
				Address: args[0], Label: label, Remove: remove,
				AdminStdin: af.stdin, AdminFile: af.file, AnchorOut: anchorOut,
			})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				renderPolicyMutation(w, m, res, "denylist updated")
			})
		},
	}
	cmd.Flags().BoolVar(&remove, "remove", false, "remove the pin instead of adding it")
	cmd.Flags().StringVar(&label, "label", "", "operator note stored with the pin")
	cmd.Flags().StringVar(&anchorOut, "anchor-out", "", "on a read-only config mount, write the anchor JSON here")
	af.bind(cmd)
	return cmd
}

func newPolicyVerifyCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Verify policy.json under the pinned anchor (passphrase-free; exit 0/8)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			st, err := svc.PolicyVerify(cmd.Context())
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, st, func(w io.Writer) {
				if st.Present {
					render.Line(w, m, "policy verified (nonce %d, watermark %d)", st.Nonce, st.Watermark)
				} else {
					render.Line(w, m, "no policy is set (guardrails are opt-in)")
				}
			})
		},
	}
}

func newPolicyCheckCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var to, amount string
	var feeRate, feeSat int64
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Dry-run evaluate a hypothetical send (no reservation; exit 0/3)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.PolicyCheck(cmd.Context(), service.PolicyCheckInput{
				To: to, Amount: amount, FeeRate: feeRate, FeeSat: feeSat,
			})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			if !res.Allowed {
				// A denied check is a typed policy.denied.* error (exit 3).
				e := domain.New(res.Code, res.Reason)
				if res.Data != nil {
					e = domain.WithData(e, res.Data)
				}
				return e
			}
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "allowed")
			})
		},
	}
	cmd.Flags().StringVar(&to, "to", "", "recipient address")
	cmd.Flags().StringVar(&amount, "amount", "", "amount (sats or BTC, like tx send)")
	cmd.Flags().Int64Var(&feeRate, "fee-rate", 0, "assumed fee rate in sat/vB")
	cmd.Flags().Int64Var(&feeSat, "fee-sat", 0, "assumed absolute fee in sats")
	_ = cmd.MarkFlagRequired("to")
	_ = cmd.MarkFlagRequired("amount")
	return cmd
}

func newPolicyCountersCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "counters",
		Short: "Show rolling-24h spend usage per network (read-only)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.PolicyCounters(cmd.Context())
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				if len(res.Counters) == 0 {
					render.Line(w, m, "no spend recorded in the rolling-24h window")
					return
				}
				t := render.NewTable(w)
				t.Row("NETWORK", "USED_24H_SAT", "RESERVATIONS")
				for _, c := range res.Counters {
					t.Row(c.Network, c.Used24hSat, itoa(c.Reservations))
				}
				_ = t.Flush()
			})
		},
	}
}

func newPolicyResetCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var force bool
	var anchorOut string
	var af adminFlags
	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Re-seal a fresh default policy under the existing key (admin passphrase)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !force {
				return domain.New(domain.CodeUsageConfirmRequired, "policy reset is destructive; pass --force to acknowledge")
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.PolicyReset(cmd.Context(), service.PolicyAdminInput{
				AdminStdin: af.stdin, AdminFile: af.file, AnchorOut: anchorOut,
			})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				renderPolicyMutation(w, m, res, "policy reset to defaults")
			})
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "required acknowledgement (destructive)")
	cmd.Flags().StringVar(&anchorOut, "anchor-out", "", "on a read-only config mount, write the anchor JSON here")
	af.bind(cmd)
	return cmd
}

func newPolicyPinCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var verify string
	cmd := &cobra.Command{
		Use:   "pin",
		Short: "Print the pinned anchor (default) or canary-verify under a key (--verify)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			m := rs.flags.Mode()
			switch {
			case verify != "":
				if err := svc.PolicyPinVerify(cmd.Context(), verify); err != nil {
					return err
				}
				return render.Result(cmd.OutOrStdout(), m, map[string]any{"verified": true}, func(w io.Writer) {
					render.Line(w, m, "policy.json verifies under the supplied key")
				})
			default:
				view, raw, err := svc.PolicyPinPrint(cmd.Context())
				if err != nil {
					return err
				}
				return render.Result(cmd.OutOrStdout(), m, view, func(w io.Writer) {
					_, _ = io.WriteString(w, raw+"\n")
				})
			}
		},
	}
	cmd.Flags().StringVar(&verify, "verify", "", "canary: does policy.json verify under this ed25519:<key>? (exit 0/8)")
	return cmd
}

func newPolicyChangeAdminCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var anchorOut string
	var af adminFlags
	var anf adminNewFlags
	cmd := &cobra.Command{
		Use:   "change-admin-passphrase",
		Short: "Rotate the admin passphrase (re-derive + re-seal under a new key)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.PolicyChangeAdminPassphrase(cmd.Context(), service.PolicyRotateInput{
				AdminStdin: af.stdin, AdminFile: af.file,
				NewStdin: anf.stdin, NewFile: anf.file, AnchorOut: anchorOut,
			})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				renderPolicyMutation(w, m, res, "admin passphrase rotated")
			})
		},
	}
	cmd.Flags().StringVar(&anchorOut, "anchor-out", "", "on a read-only config mount, write the anchor JSON here")
	af.bind(cmd)
	anf.bind(cmd)
	return cmd
}

// ── human renderers ──────────────────────────────────────────────────────────

func renderPolicyShow(w io.Writer, m render.Mode, res service.PolicyShowResult) {
	if !res.Present {
		render.Line(w, m, "no policy is set (guardrails are opt-in; the wallet is petty-cash by default)")
		return
	}
	render.Line(w, m, "policy: nonce %d, watermark %d, written-by %s",
		res.SealStatus.Nonce, res.SealStatus.Watermark, res.SealStatus.WrittenBy)
	d := res.Default
	render.Line(w, m, "default: max-tx=%s max-day=%s max-fee-rate=%s include-self=%v",
		dash(d.MaxTxSat), dash(d.MaxDaySat), dash(d.MaxFeeRate), d.IncludeSelf)
	render.Line(w, m, "allowlist: %s", allowlistLine(d.AllowlistOn))
	for _, n := range res.Networks {
		render.Line(w, m, "  [%s] max-tx=%s max-day=%s max-fee-rate=%s allowlist=%s include-self=%v",
			n.Network, dash(n.MaxTxSat), dash(n.MaxDaySat), dash(n.MaxFeeRate), allowlistLine(n.AllowlistOn), n.IncludeSelf)
	}
	if len(res.Allowlist) > 0 {
		render.Line(w, m, "allowlist:")
		for _, p := range res.Allowlist {
			render.Line(w, m, "  + %s %s", p.Address, p.Label)
		}
	}
	if len(res.Denylist) > 0 {
		render.Line(w, m, "denylist:")
		for _, p := range res.Denylist {
			render.Line(w, m, "  - %s %s", p.Address, p.Label)
		}
	}
	render.Line(w, m, "self-addresses sealed: %d", res.SelfCount)
}

func renderPolicyMutation(w io.Writer, m render.Mode, res service.PolicyMutationResult, label string) {
	render.Line(w, m, "%s (nonce %d)", label, res.Nonce)
	if res.AnchorWritten {
		render.Line(w, m, "anchor written: %s", res.Anchor.VerifyKey)
		return
	}
	if res.AnchorJSON != "" {
		render.Line(w, m, "config is read-only — land this anchor JSON out-of-band:")
		_, _ = io.WriteString(w, res.AnchorJSON+"\n")
	}
}

func dash(s string) string {
	if s == "" {
		return "∞"
	}
	return s
}

// allowlistLine renders the allowlist gate state for `policy show`. When OFF it
// states the petty-cash default loudly so the operator is never surprised that
// sends to arbitrary addresses are permitted (limits + denylist still apply).
func allowlistLine(on bool) string {
	if on {
		return "on (sends allowed only to allowlisted/self addresses within limits)"
	}
	return "off (sends allowed to any address within limits)"
}

// triBool parses an on|off tri-state flag: "" → nil (unchanged); on/true → &true;
// off/false → &false.
func triBool(s string) (*bool, error) {
	switch s {
	case "":
		return nil, nil
	case "on", "true", "yes":
		v := true
		return &v, nil
	case "off", "false", "no":
		v := false
		return &v, nil
	default:
		return nil, domain.Newf(domain.CodeUsage+".bad_value", "expected on|off, got %q", s)
	}
}
