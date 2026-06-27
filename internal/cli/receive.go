package cli

import (
	"context"
	"time"

	"github.com/daxchain-io/daxib/internal/cli/render"
	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/spf13/cobra"
)

// receive.go is the `daxib receive` command: block until the wallet's receive
// address is paid (and confirms). It is a thin host — it binds flags into a
// domain.ReceiveRequest, wires the STDOUT NDJSON stream sink (render.ReceiveStream,
// distinct from the STDERR progress sink send/wait use), and blocks on svc.Receive.
// ALL detection logic lives in service/receive.go (the arch matrix forbids this
// frontend from importing a backend).
//
// The stream contract: the receiving ADDRESS is emitted UP FRONT (the first
// listening line) so a counterparty can be handed it BEFORE the command blocks;
// under --json the stream is NDJSON on stdout; the TERMINAL line is `complete`
// (exit 0) or `timeout` (exit 8). A timeout is NOT a Go error — the service returns
// (result, nil) with result.Exit==8 and the terminal line is already on stdout, so
// this command surfaces that exit through a typed receive.timeout error the central
// funnel projects WITHOUT printing a competing stderr envelope (mirrors `tx wait`).
//
// --new derives the wallet's next receive index (a keystore meta.json write →
// requires a writable keystore). The keystore passphrase that derive needs is
// resolved INSIDE the service via the §3.6 channels (DAXIB_PASSPHRASE[_FILE] or the
// host TTY), exactly like `tx send` — the secret is never a flag value.
func newReceiveCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var (
		wallet, amount, timeoutStr, pollStr string
		newAddr                             bool
		confirmations                       uint64
	)
	cmd := &cobra.Command{
		Use:   "receive [--wallet <w>] [--new] [--amount <v>]",
		Short: "Block until the wallet's receive address is paid (and confirms)",
		Long: "Wait for inbound funds — derive/peek a receive address, hand it to the\n" +
			"counterparty, block until paid. The receiving address is emitted IMMEDIATELY\n" +
			"(before blocking). With --json the output is a line-delimited NDJSON event\n" +
			"stream on stdout (listening -> detected -> confirmed -> complete); on timeout\n" +
			"the terminal line is `timeout` (exit 8 — not a failure; re-run to resume,\n" +
			"detection is stateless). --new derives the wallet's next receive index\n" +
			"(requires a writable keystore); without it the next-unused receive address is\n" +
			"peeked. --amount is the cumulative confirmed target (omit for any-inbound);\n" +
			"--timeout DEFAULTS TO NONE (unbounded wait — set one for agents).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			req := domain.ReceiveRequest{
				Wallet: wallet,
				New:    newAddr,
				Amount: amount,
			}
			if cmd.Flags().Changed("confirmations") {
				c := confirmations
				req.Confirmations = &c
			}
			if timeoutStr != "" {
				d, perr := time.ParseDuration(timeoutStr)
				if perr != nil {
					return domain.Newf(domain.CodeUsageBadTimeout, "invalid --timeout %q: %v", timeoutStr, perr)
				}
				req.Timeout = domain.Duration{D: d}
			}
			if pollStr != "" {
				d, perr := time.ParseDuration(pollStr)
				if perr != nil {
					return domain.Newf(domain.CodeUsageBadTimeout, "invalid --poll-interval %q: %v", pollStr, perr)
				}
				req.PollInterval = domain.Duration{D: d}
			}

			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			m := rs.flags.Mode()
			// receive's stream is the PRIMARY output on STDOUT (the address up front,
			// the terminal line carrying exit) — NOT the StderrProgress sink.
			sink := render.ReceiveStream(cmd.OutOrStdout(), m.JSON)
			res, err := svc.Receive(cmd.Context(), req, sink)
			return renderReceiveOutcome(res, err)
		},
	}

	fl := cmd.Flags()
	fl.StringVar(&wallet, "wallet", "", "wallet to receive on (default: --wallet > DAXIB_WALLET > default wallet)")
	fl.BoolVar(&newAddr, "new", false, "derive a fresh receive address (requires a writable keystore)")
	fl.StringVar(&amount, "amount", "", "cumulative confirmed target: <btc> e.g. 0.001 or <n>sat; omit for any-inbound")
	fl.Uint64Var(&confirmations, "confirmations", 0, "confirmation target (default: 1)")
	fl.StringVar(&timeoutStr, "timeout", "", "bounded listen, e.g. 30m (default: none — unbounded wait)")
	fl.StringVar(&pollStr, "poll-interval", "", "backend poll cadence, e.g. 5s (default: 5s)")
	return cmd
}

// renderReceiveOutcome funnels the (ReceiveResult, error) into the exit code. A
// normal terminal outcome (complete OR timeout) is returned as (result, nil) by the
// service — the terminal line is ALREADY on stdout — so this only translates a
// timeout into a typed receive.timeout error (exit 8) WITHOUT a competing stderr
// envelope (the resume info is on stdout). A true failure funnels through unchanged.
func renderReceiveOutcome(res domain.ReceiveResult, err error) error {
	if err != nil {
		return err
	}
	if res.Exit == int(domain.ExitTimeoutPending) {
		return domain.New("receive.timeout", "listen timed out; re-run to resume")
	}
	return nil
}
