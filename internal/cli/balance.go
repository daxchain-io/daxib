package cli

import (
	"context"
	"io"

	"github.com/spf13/cobra"

	"github.com/daxchain-io/daxib/internal/cli/render"
	"github.com/daxchain-io/daxib/internal/domain"
)

// newBalanceCmd builds the `balance` command: derive the wallet's gap-window
// addresses from the stored xpub (NO passphrase), query the active backend, and
// report the confirmed / unconfirmed split in sats + BTC. --utxos enumerates the
// individual coins.
func newBalanceCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var wallet string
	var utxos bool
	cmd := &cobra.Command{
		Use:   "balance",
		Short: "Show a wallet's confirmed/unconfirmed balance (UTXO-derived)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.Balance(cmd.Context(), domain.LocalCLI(), domain.BalanceRequest{Wallet: wallet, UTXOs: utxos})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "wallet %q on %s via %s (tip %s)", res.Wallet, res.Network, res.Backend, itoa(int(res.TipHeight)))
				tbl := render.NewTable(w)
				tbl.Row("confirmed", res.ConfirmedBTC+" BTC", itoa64(res.ConfirmedSat)+" sat")
				tbl.Row("unconfirmed", res.UnconfirmedBTC+" BTC", itoa64(res.UnconfirmedSat)+" sat")
				tbl.Row("total", res.TotalBTC+" BTC", itoa64(res.TotalSat)+" sat")
				_ = tbl.Flush()
				if utxos && len(res.UTXOs) > 0 {
					render.Line(w, m, "")
					writeUTXOTable(w, m, res.UTXOs)
				}
			})
		},
	}
	cmd.Flags().StringVar(&wallet, "wallet", "", "wallet name (default: --wallet flag > DAXIB_WALLET > default wallet)")
	cmd.Flags().BoolVar(&utxos, "utxos", false, "enumerate the individual UTXOs")
	return cmd
}

// newUTXOCmd builds the `utxo` noun (list): the per-UTXO breakdown for coin
// control. v1 ships only `list`; freeze/unfreeze/lock land with the tx pipeline.
func newUTXOCmd(ctx context.Context, rs *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "utxo",
		Short: "Inspect a wallet's unspent transaction outputs",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newUTXOListCmd(ctx, rs))
	return cmd
}

func newUTXOListCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var wallet string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List a wallet's UTXOs (outpoint, address, value, confirmations)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.UTXOList(cmd.Context(), domain.LocalCLI(), domain.UTXOListRequest{Wallet: wallet})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "wallet %q on %s via %s (tip %s)", res.Wallet, res.Network, res.Backend, itoa(int(res.TipHeight)))
				writeUTXOTable(w, m, res.UTXOs)
				render.Line(w, m, "total %s BTC (%s sat)", res.TotalBTC, itoa64(res.TotalSat))
			})
		},
	}
	cmd.Flags().StringVar(&wallet, "wallet", "", "wallet name (default: --wallet flag > DAXIB_WALLET > default wallet)")
	return cmd
}

// writeUTXOTable renders a UTXO row table shared by `balance --utxos` and
// `utxo list`.
func writeUTXOTable(w io.Writer, m render.Mode, rows []domain.UTXORow) {
	tbl := render.NewTable(w)
	if !m.Quiet {
		tbl.Row("OUTPOINT", "ADDRESS", "VALUE_BTC", "VALUE_SAT", "CONFIRMATIONS")
	}
	for _, u := range rows {
		tbl.Row(u.Outpoint, u.Address, u.ValueBTC, itoa64(u.ValueSat), itoa64(u.Confirmations))
	}
	_ = tbl.Flush()
}
