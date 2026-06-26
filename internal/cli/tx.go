package cli

import (
	"context"
	"io"
	"math"
	"time"

	"github.com/spf13/cobra"

	"github.com/daxchain-io/daxib/internal/cli/render"
	"github.com/daxchain-io/daxib/internal/domain"
)

// tx.go is the `tx` noun: send/status/wait/list. It is a thin host — it parses
// flags into a domain request, opens the service lazily, and funnels the result
// through renderTxOutcome (the §5.3/§5.9 contract). M4 binds NONE of daxie's EVM
// gas/nonce flags and NO speedup/cancel/abandon (those are M5/RBF). A send signals
// RBF (nSequence=0xfffffffd) in the SERVICE; a future `tx speedup` depends on it.

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
		newTxStatusCmd(ctx, rs),
		newTxWaitCmd(ctx, rs),
		newTxListCmd(ctx, rs),
	)
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

			req := domain.SendRequest{
				Wallet:  wallet,
				To:      to,
				Amount:  amount,
				FeeRate: feeRate,
				Speed:   speed,
				DryRun:  dryRun,
				Yes:     rs.flags.Yes,
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
