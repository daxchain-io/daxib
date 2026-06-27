package cli

import (
	"context"
	"io"
	"math"
	"os"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/daxchain-io/daxib/internal/cli/render"
	"github.com/daxchain-io/daxib/internal/domain"
)

// tx.go is the `tx` noun: send/speedup/cancel/status/wait/list. It is a thin host —
// it parses flags into a domain request, opens the service lazily, and funnels the
// result through renderTxOutcome (the §5.3/§5.9 contract). It binds NONE of daxie's
// EVM gas/nonce flags. A send signals opt-in RBF (nSequence=0xfffffffd) in the
// SERVICE; `tx speedup` and `tx cancel` are the BIP-125 RBF replacements that rely
// on that signal — speedup rebuilds a higher-fee replacement to the same recipient,
// cancel redirects all funds to a wallet change address (voiding the payment).

// waitFlags bundles the --wait/--confirmations/--timeout trio shared by `tx send`
// and `tx wait`.
type waitFlags struct {
	wait          bool
	confirmations uint64
	timeout       string
}

// toWaitOpts parses the wait flags into domain.WaitOpts. A bad --timeout is
// usage.bad_timeout (exit 2). Confirmations is threaded only when explicitly set.
func (wf waitFlags) toWaitOpts(cmd *cobra.Command, enabled bool) (domain.WaitOpts, error) {
	w := domain.WaitOpts{Enabled: enabled}
	if cmd.Flags().Changed("confirmations") {
		// Clamp to the int64 range (a confirmations target above math.MaxInt64 is
		// nonsensical; this also satisfies the integer-overflow lint).
		conf := wf.confirmations
		if conf > uint64(math.MaxInt64) {
			conf = uint64(math.MaxInt64)
		}
		c := int64(conf)
		w.Confirmations = &c
	}
	if wf.timeout != "" {
		d, err := time.ParseDuration(wf.timeout)
		if err != nil {
			return domain.WaitOpts{}, domain.Newf(domain.CodeUsageBadTimeout, "invalid --timeout %q: %v", wf.timeout, err)
		}
		w.Timeout = domain.Duration{D: d}
	}
	return w, nil
}

func newTxCmd(ctx context.Context, rs *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tx",
		Short: "Send Bitcoin and inspect transactions (send/status/wait/list)",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(
		newTxSendCmd(ctx, rs),
		newTxSpeedupCmd(ctx, rs),
		newTxCancelCmd(ctx, rs),
		newTxStatusCmd(ctx, rs),
		newTxWaitCmd(ctx, rs),
		newTxListCmd(ctx, rs),
		newTxAbandonCmd(ctx, rs),
	)
	return cmd
}

// newTxAbandonCmd builds `tx abandon <txid>` (GAP-1): the OPERATOR recovery for a
// signed-but-never-broadcast tx. It terminalizes the journal record `failed` (freeing
// its UTXOs from coin-selection) and releases its policy reservation — but REFUSES a
// tx with any recorded broadcast (it may still confirm). Requires --yes.
func newTxAbandonCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var wallet string
	cmd := &cobra.Command{
		Use:   "abandon <txid>",
		Short: "Abandon a never-broadcast signed tx, freeing its inputs (operator; refuses a broadcast tx)",
		Long: "Abandon recovers a signed-but-never-broadcast transaction whose inputs are\n" +
			"otherwise locked out of coin-selection forever. It terminalizes the journal\n" +
			"record as failed (freeing its UTXOs) and releases its policy reservation. It\n" +
			"REFUSES a tx that has any recorded broadcast — a broadcast tx may still confirm\n" +
			"and must never be abandoned. Requires --yes (it is irreversible).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Confirmation prompt: abandon is irreversible (it terminalizes the record
			// and frees its inputs). Prompt at a TTY without --yes; abort on anything but
			// yes; non-TTY without --yes falls through to the service gate.
			yes, cerr := confirmAbandon(cmd, args[0], rs)
			if cerr != nil {
				return cerr
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.AbandonTx(cmd.Context(), domain.AbandonRequest{
				Wallet: wallet, Txid: args[0], Yes: yes,
			})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "abandoned %s (journal %s): freed %d input(s), reservation released=%v",
					res.Txid, res.JournalID, res.FreedInputs, res.ReservationReleased)
			})
		},
	}
	cmd.Flags().StringVar(&wallet, "wallet", "", "wallet that owns the tx (default: --wallet > DAXIB_WALLET > default)")
	return cmd
}

// newTxSpeedupCmd builds `tx speedup <txid>` (RBF/BIP-125): replace an unconfirmed
// send with a higher-fee tx paying the SAME recipient.
func newTxSpeedupCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var wallet, feeRate string
	var wf waitFlags
	cmd := &cobra.Command{
		Use:   "speedup <txid>",
		Short: "Replace an unconfirmed send with a higher-fee transaction (RBF)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			waitOpts, err := wf.toWaitOpts(cmd, wf.wait)
			if err != nil {
				return err
			}
			// AF-3 confirmation prompt: a speedup re-signs and re-broadcasts a higher-fee
			// replacement (money-moving). Prompt at a TTY without --yes; abort on anything
			// but yes; non-TTY without --yes falls through to the service gate.
			yes, cerr := confirmReplace(cmd, "Speed up", args[0], feeRate, rs)
			if cerr != nil {
				return cerr
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			m := rs.flags.Mode()
			sink := render.StderrProgress(cmd.ErrOrStderr(), m.JSON)
			res, err := svc.SpeedupTx(cmd.Context(), domain.SpeedupRequest{
				Wallet: wallet, Txid: args[0], FeeRate: feeRate, Yes: yes, Wait: waitOpts,
			}, sink)
			return renderTxOutcome(cmd, m, res, err)
		},
	}
	cmd.Flags().StringVar(&wallet, "wallet", "", "wallet that owns the tx (default: --wallet > DAXIB_WALLET > default)")
	cmd.Flags().StringVar(&feeRate, "fee-rate", "", "new fee rate in sat/vByte (default: the backend FAST tier, never below original + 1 sat/vByte)")
	bindWaitFlags(cmd, &wf)
	return cmd
}

// newTxCancelCmd builds `tx cancel <txid>` (RBF/BIP-125): replace an unconfirmed
// send with a higher-fee tx that redirects ALL funds to a wallet-owned address,
// voiding the original payment.
func newTxCancelCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var wallet, feeRate string
	var wf waitFlags
	cmd := &cobra.Command{
		Use:   "cancel <txid>",
		Short: "Cancel an unconfirmed send by replacing it with a self-paying transaction (RBF)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			waitOpts, err := wf.toWaitOpts(cmd, wf.wait)
			if err != nil {
				return err
			}
			// AF-3 confirmation prompt: a cancel re-signs a higher-fee replacement that
			// voids the original payment (money-moving). Prompt at a TTY without --yes.
			yes, cerr := confirmReplace(cmd, "Cancel", args[0], feeRate, rs)
			if cerr != nil {
				return cerr
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			m := rs.flags.Mode()
			sink := render.StderrProgress(cmd.ErrOrStderr(), m.JSON)
			res, err := svc.CancelTx(cmd.Context(), domain.CancelRequest{
				Wallet: wallet, Txid: args[0], FeeRate: feeRate, Yes: yes, Wait: waitOpts,
			}, sink)
			return renderTxOutcome(cmd, m, res, err)
		},
	}
	cmd.Flags().StringVar(&wallet, "wallet", "", "wallet that owns the tx (default: --wallet > DAXIB_WALLET > default)")
	cmd.Flags().StringVar(&feeRate, "fee-rate", "", "new fee rate in sat/vByte (default: the backend FAST tier, never below original + 1 sat/vByte)")
	bindWaitFlags(cmd, &wf)
	return cmd
}

func newTxSendCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var (
		wallet, to, amount, feeRate, speed string
		dryRun                             bool
		wf                                 waitFlags
	)
	cmd := &cobra.Command{
		Use:   "send",
		Short: "Build, sign, and broadcast a Bitcoin transaction",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Validate required flags BEFORE opening the service (a missing flag is a
			// clean exit 2 with no keystore/network needed).
			if to == "" {
				return domain.New("usage.missing_to", "--to is required")
			}
			if amount == "" {
				return domain.New("usage.missing_amount", "--amount is required")
			}
			waitOpts, err := wf.toWaitOpts(cmd, wf.wait)
			if err != nil {
				return err
			}

			// AF-3 confirmation prompt: a real send moves funds, so at an interactive
			// terminal (and without --yes) show a y/N summary and abort on anything but
			// yes. A dry-run moves nothing, so it skips the prompt. --yes skips it; a
			// non-TTY without --yes falls through to the service's confirmation_required
			// gate. proceed=true => the operator authorized, so pass Yes=true downstream.
			yes := rs.flags.Yes
			if !dryRun {
				proceed, cerr := confirmTxSend(cmd.ErrOrStderr(), cmd.InOrStdin(), promptTTY(rs), rs.flags.Yes, txConfirm{
					Action:    "Send",
					Recipient: to,
					Amount:    amount,
					Fee:       feeLabel(feeRate, speed),
					Network:   promptNetworkLabel(rs),
				})
				if cerr != nil {
					return cerr
				}
				if proceed {
					yes = true
				}
			}

			req := domain.SendRequest{
				Wallet:  wallet,
				To:      to,
				Amount:  amount,
				FeeRate: feeRate,
				Speed:   speed,
				DryRun:  dryRun,
				Yes:     yes,
				Wait:    waitOpts,
			}

			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			m := rs.flags.Mode()
			sink := render.StderrProgress(cmd.ErrOrStderr(), m.JSON)
			res, err := svc.SendTx(cmd.Context(), req, sink)
			return renderTxOutcome(cmd, m, res, err)
		},
	}
	cmd.Flags().StringVar(&wallet, "wallet", "", "sender wallet (default: --wallet flag > DAXIB_WALLET > default wallet)")
	cmd.Flags().StringVar(&to, "to", "", "recipient address (bech32 P2WPKH or any standard address)")
	cmd.Flags().StringVar(&amount, "amount", "", "amount to send (<btc> e.g. 0.001, or <n>sat e.g. 150000sat)")
	cmd.Flags().StringVar(&feeRate, "fee-rate", "", "fee rate in sat/vByte (default: estimate from the backend by --speed)")
	cmd.Flags().StringVar(&speed, "speed", "", "fee tier when --fee-rate is unset (slow|normal|fast); default normal")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "build + select + estimate + preview; sign/broadcast nothing")
	bindWaitFlags(cmd, &wf)
	return cmd
}

func newTxStatusCmd(ctx context.Context, rs *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status <txid>",
		Short: "Show a transaction's status (journal + backend re-check)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.TxStatus(cmd.Context(), domain.TxStatusRequest{Txid: args[0]})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.TxResult(w, m, res)
			})
		},
	}
	return cmd
}

func newTxWaitCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var wf waitFlags
	cmd := &cobra.Command{
		Use:   "wait <txid>",
		Short: "Wait for a transaction to confirm",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			waitOpts, err := wf.toWaitOpts(cmd, true)
			if err != nil {
				return err
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			m := rs.flags.Mode()
			sink := render.StderrProgress(cmd.ErrOrStderr(), m.JSON)
			res, err := svc.WaitTx(cmd.Context(), domain.WaitRequest{
				Txid: args[0], Confirmations: waitOpts.Confirmations, Timeout: waitOpts.Timeout,
			}, sink)
			return renderTxOutcome(cmd, m, res, err)
		},
	}
	cmd.Flags().Uint64Var(&wf.confirmations, "confirmations", 1, "confirmations to wait for")
	cmd.Flags().StringVar(&wf.timeout, "timeout", "", "max wait duration (e.g. 30m); default 30m")
	return cmd
}

func newTxListCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var wallet string
	var limit int
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List journaled transactions (newest-first)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.ListTxs(cmd.Context(), domain.TxListRequest{Wallet: wallet, Limit: limit})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.TxRows(w, m, res.Txs)
			})
		},
	}
	cmd.Flags().StringVar(&wallet, "wallet", "", "filter to a wallet")
	cmd.Flags().IntVar(&limit, "limit", 0, "max rows (0 = all)")
	return cmd
}

// promptTTY reports whether the AF-3 confirmation prompt should be shown: stdin is
// an interactive terminal AND --json is off. Under --json (machine mode) we never
// prompt — a JSON-mode money mover must pass --yes explicitly, otherwise the
// service's usage.confirmation_required gate fires (we treat --json like a non-TTY so
// the structured contract is never interrupted by a human prompt). The prompt logic
// itself (confirmTxSend) takes this bool explicitly so it stays unit-testable.
func promptTTY(rs *rootState) bool {
	return !rs.flags.JSON && term.IsTerminal(int(os.Stdin.Fd()))
}

// promptNetworkLabel resolves the network shown at the confirmation prompt from the
// channels the CLI can see WITHOUT opening the service: --network flag, then
// DAXIB_NETWORK. The persisted-default rung is resolved inside the service (the cli
// may not read the config store), so when neither flag nor env is set we show
// "(default)" — the operator still sees the recipient/amount, and an unresolved
// network would fail with usage.network_required before any signing anyway.
func promptNetworkLabel(rs *rootState) string {
	if rs.flags.Network != "" {
		return rs.flags.Network
	}
	if v, ok := os.LookupEnv("DAXIB_NETWORK"); ok && v != "" {
		return v
	}
	return "(default)"
}

// feeLabel renders the fee line for the confirmation prompt from the fee flags as
// typed: an explicit --fee-rate wins; else the --speed tier; else the default
// (normal) tier. For an RBF replacement an empty fee-rate bumps to the backend FAST
// tier, so replaceFee reflects that honestly.
func feeLabel(feeRate, speed string) string {
	if feeRate != "" {
		return feeRate + " sat/vByte"
	}
	if speed != "" {
		return "backend estimate (" + speed + " tier)"
	}
	return "backend estimate (normal tier)"
}

// replaceFeeLabel is feeLabel for `tx speedup`/`tx cancel`: an unset --fee-rate
// bumps to the backend FAST tier (never below the original + 1 sat/vByte).
func replaceFeeLabel(feeRate string) string {
	if feeRate != "" {
		return feeRate + " sat/vByte"
	}
	return "backend fast estimate (at least original + 1 sat/vByte)"
}

// confirmReplace is the AF-3 confirmation gate shared by `tx speedup`/`tx cancel`.
// It shows the action, the original txid being replaced, the new fee, and the
// network, then returns the effective --yes (true once the operator confirms at the
// prompt, or when --yes was passed). A decline returns a usage.confirmation_required
// error; a non-TTY without --yes returns yes=false (the service gate fires).
func confirmReplace(cmd *cobra.Command, action, origTxid, feeRate string, rs *rootState) (yes bool, err error) {
	proceed, cerr := confirmTxSend(cmd.ErrOrStderr(), cmd.InOrStdin(), promptTTY(rs), rs.flags.Yes, txConfirm{
		Action:    action,
		Recipient: "replaces tx " + origTxid,
		Fee:       replaceFeeLabel(feeRate),
		Network:   promptNetworkLabel(rs),
	})
	if cerr != nil {
		return false, cerr
	}
	return rs.flags.Yes || proceed, nil
}

// confirmAbandon is the interactive confirmation gate for `tx abandon`. Abandon is
// irreversible (it terminalizes the journal record and frees its inputs), so at a
// TTY without --yes it MUST prompt — mirroring tx send/speedup/cancel, which all add
// a real prompt rather than relying solely on the service's non-TTY gate. It returns
// the effective --yes (true once confirmed at the prompt or when --yes was passed); a
// decline returns usage.confirmation_required, and a non-TTY without --yes returns
// yes=false so the service's confirmation_required gate fires.
func confirmAbandon(cmd *cobra.Command, txid string, rs *rootState) (yes bool, err error) {
	proceed, cerr := confirmTxSend(cmd.ErrOrStderr(), cmd.InOrStdin(), promptTTY(rs), rs.flags.Yes, txConfirm{
		Action:    "abandon (irreversible: frees inputs of a never-broadcast signed tx)",
		Recipient: "tx " + txid,
		Network:   promptNetworkLabel(rs),
	})
	if cerr != nil {
		return false, cerr
	}
	return rs.flags.Yes || proceed, nil
}

// bindWaitFlags binds --wait/--confirmations/--timeout onto a send command.
func bindWaitFlags(cmd *cobra.Command, wf *waitFlags) {
	cmd.Flags().BoolVar(&wf.wait, "wait", false, "wait for the tx to confirm before returning")
	cmd.Flags().Uint64Var(&wf.confirmations, "confirmations", 1, "confirmations to wait for (with --wait)")
	cmd.Flags().StringVar(&wf.timeout, "timeout", "", "max wait duration with --wait (e.g. 30m)")
}

// renderTxOutcome is the §5.3/§5.9 stdout contract: a populated result (a txid or
// a dry-run) emits EXACTLY ONE stdout object, then the error is returned for the
// exit code. A bare pre-broadcast error writes NOTHING to stdout (so a failed
// command never half-emits a result). A wait TIMEOUT carries both a result (with
// Resume) AND the tx.wait_timeout error → the object prints, then exit 8.
func renderTxOutcome(cmd *cobra.Command, m render.Mode, res domain.TxResult, err error) error {
	if res.Txid != "" || res.DryRun {
		_ = render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
			render.TxResult(w, m, res)
		})
	}
	return err
}
