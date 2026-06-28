package cli

import (
	"context"
	"io"

	"github.com/spf13/cobra"

	"github.com/daxchain-io/daxib/internal/cli/render"
	"github.com/daxchain-io/daxib/internal/domain"
)

// newAddressCmd builds the `address` noun (new/list). These derive child
// addresses from the wallet's stored neutered xpub, so they need NO passphrase.
func newAddressCmd(ctx context.Context, rs *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "address",
		Short: "Derive and list wallet addresses (BIP-84 native SegWit)",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(
		newAddressNewCmd(ctx, rs),
		newAddressListCmd(ctx, rs),
	)
	return cmd
}

func newAddressNewCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var wallet string
	var change bool
	cmd := &cobra.Command{
		Use:   "new",
		Short: "Allocate the next receive (or --change) address",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.AddressNew(cmd.Context(), domain.LocalCLI(), domain.AddressNewRequest{
				Wallet: wallet, Change: change,
			})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				// The address IS the essential output, so it prints regardless of
				// --quiet (render.Line would suppress it).
				_, _ = io.WriteString(w, res.Address+"\n")
			})
		},
	}
	cmd.Flags().StringVar(&wallet, "wallet", "", "wallet name (default: --wallet flag > DAXIB_WALLET > default wallet)")
	cmd.Flags().BoolVar(&change, "change", false, "allocate an internal (change) address instead of a receive address")
	return cmd
}

func newAddressListCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var wallet string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List a wallet's derived addresses",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.AddressList(cmd.Context(), domain.LocalCLI(), domain.AddressListRequest{Wallet: wallet})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				tbl := render.NewTable(w)
				if !m.Quiet {
					tbl.Row("REF", "ADDRESS", "CREATED")
				}
				for _, a := range res.Addresses {
					tbl.Row(a.Ref, a.Address, a.CreatedAt)
				}
				_ = tbl.Flush()
			})
		},
	}
	cmd.Flags().StringVar(&wallet, "wallet", "", "wallet name (default: --wallet flag > DAXIB_WALLET > default wallet)")
	return cmd
}
