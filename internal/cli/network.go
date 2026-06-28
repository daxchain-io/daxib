package cli

import (
	"context"
	"io"

	"github.com/daxchain-io/daxib/internal/cli/render"
	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/spf13/cobra"
)

// network.go is the `daxib network use|show|list` noun (GAP-3) — the surface that
// SELECTS and INTROSPECTS the active network so an unqualified command never
// silently defaults to mainnet (AF-1, the OWNER decision: no silent default
// anywhere).
//
//   - `network use <net>` persists the active-network default (config
//     defaults.network — the third resolution rung, below --network and
//     DAXIB_NETWORK). An empty/`none`/`clear` arg clears it. Needs a --config /
//     DAXIB_CONFIG path (backend.not_configured otherwise).
//   - `network show` prints the resolved network and its SOURCE (flag/env/config/
//     unset). When nothing is selected it reports "unset" — a network-requiring op
//     would then fail with usage.network_required (exit 2).
//   - `network list` enumerates the five well-known networks.
//
// show/list are network-INDEPENDENT (they answer "what is the active network"), so
// they work even when none is selected.
func newNetworkCmd(ctx context.Context, rs *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "network",
		Short: "Select and inspect the active Bitcoin network",
		Long: "Resolve the active network without a silent default. The active network is\n" +
			"resolved as: --network flag > DAXIB_NETWORK env > the persisted default\n" +
			"(`network use`) > ERROR. A network-requiring command with none selected fails\n" +
			"with usage.network_required (exit 2) — daxib never silently picks mainnet.\n\n" +
			"  network use <net>   persist the default (mainnet/testnet/testnet4/signet/regtest)\n" +
			"  network show        print the resolved network + its source\n" +
			"  network list        list the five supported networks",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(
		newNetworkUseCmd(ctx, rs),
		newNetworkShowCmd(ctx, rs),
		newNetworkListCmd(ctx, rs),
	)
	return cmd
}

func newNetworkUseCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "use <net>",
		Short: "Persist the default active network (config defaults.network)",
		Long: "Write the persisted active-network default into config.toml (the third\n" +
			"resolution rung). <net> is one of mainnet/testnet/testnet4/signet/regtest;\n" +
			"`none` / `clear` / an empty value clears the default. Requires a --config /\n" +
			"DAXIB_CONFIG path. A --network flag or DAXIB_NETWORK still overrides this\n" +
			"persisted default for a single call.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			net := args[0]
			if net == "none" || net == "clear" {
				net = ""
			}
			res, err := svc.NetworkUse(cmd.Context(), domain.LocalCLI(), net)
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				if res.Cleared {
					render.Line(w, m, "persisted default network cleared")
					return
				}
				render.Line(w, m, "persisted default network set to %s", res.Network)
			})
		},
	}
}

func newNetworkShowCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Print the resolved active network and its source",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.NetworkShow(cmd.Context(), domain.LocalCLI())
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				if !res.Resolved {
					render.Line(w, m, "no network selected (source: unset)")
					render.Line(w, m, "select one with --network <net>, DAXIB_NETWORK, or `daxib network use <net>`")
					if res.Persisted != "" {
						render.Line(w, m, "persisted default: %s (not active — re-check config)", res.Persisted)
					}
					return
				}
				render.Line(w, m, "active network: %s (source: %s)", res.Network, res.Source)
				if res.Persisted != "" && res.Source != "config" {
					render.Line(w, m, "persisted default: %s", res.Persisted)
				}
			})
		},
	}
}

func newNetworkListCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the five supported Bitcoin networks",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.NetworkList(cmd.Context(), domain.LocalCLI())
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				tbl := render.NewTable(w)
				if !m.Quiet {
					tbl.Row("NETWORK", "COIN_TYPE", "ACTIVE")
				}
				for _, n := range res.Networks {
					active := ""
					if n.Active {
						active = "*"
					}
					tbl.Row(n.Network, itoa(int(n.CoinType)), active)
				}
				_ = tbl.Flush()
			})
		},
	}
}
