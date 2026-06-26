// Package cli is Frontend 1: the Cobra command tree. It is a thin host — it
// parses flags/env/stdin into service request structs, opens the service, and
// renders results. It imports ONLY service, domain, version, and its own render
// subpackage — never a provider (the arch matrix enforces this as a failing
// test). Business logic physically cannot live here.
//
// One file per noun. M1 ships only `version` (the compiling-skeleton milestone);
// later milestones add wallet/descriptor/address/balance/utxo/tx/psbt/fee/
// receive/policy/mcp per docs/PLAN.md §4.
package cli

import (
	"context"

	"github.com/spf13/cobra"
)

// rootState is the single FlagValues the root binds and every command reads
// through the *cobra.Command's context. It is created per Execute call (no
// global state).
type rootState struct {
	flags FlagValues
}

// newRootCmd builds the root command tree with all global persistent flags bound
// onto rs.flags. The caller (Execute) runs it. SilenceErrors/SilenceUsage are
// set so the central registry in render.go owns all error→exit mapping; Cobra
// never prints an error itself.
func newRootCmd(ctx context.Context, rs *rootState) *cobra.Command {
	root := &cobra.Command{
		Use:   "daxib",
		Short: "Daxib — the Bitcoin wallet for AI",
		Long: "Daxib is an agent-first Bitcoin CLI wallet: non-interactive flags/env/stdin,\n" +
			"--json output, deterministic exit codes, and a built-in MCP server.",
		SilenceErrors: true, // the registry in render.go prints errors, not Cobra
		SilenceUsage:  true, // usage on error is noise for agents; --help still works
		// Cobra's default completion command would shadow our future explicit one;
		// disable the built-in so the documented surface stays exact.
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
		// No Run on the root: bare `daxib` prints help and exits 0 (cmd.Help returns
		// nil), matching daxie parity.
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	root.SetFlagErrorFunc(flagErrorFunc)

	pf := root.PersistentFlags()
	pf.BoolVar(&rs.flags.JSON, "json", false, "machine-readable JSON output")
	pf.BoolVar(&rs.flags.Quiet, "quiet", false, "suppress non-essential human output")
	pf.StringVar(&rs.flags.Network, "network", "", "Bitcoin network (mainnet/testnet/signet/regtest); overrides the configured default")
	pf.StringVar(&rs.flags.Backend, "backend", "", "backend endpoint name (bitcoind RPC / Electrum / Esplora); overrides the network's default for this call")
	pf.StringVar(&rs.flags.Config, "config", "", "config directory holding config.toml (default: platform XDG path)")
	pf.StringVar(&rs.flags.Keystore, "keystore", "", "keystore directory (default: platform data path)")
	pf.StringVar(&rs.flags.StateDir, "state-dir", "", "mutable state directory (default: platform state path)")
	pf.BoolVarP(&rs.flags.Yes, "yes", "y", false, "skip confirmations; required for mutating ops when non-interactive")

	root.AddCommand(
		newVersionCmd(rs),      // M1
		newWalletCmd(ctx, rs),  // M2: keys + HD wallet
		newAddressCmd(ctx, rs), // M2: BIP-84 address derivation
		newBackendCmd(ctx, rs), // M3: backend provider (bitcoind RPC / Esplora)
		newBalanceCmd(ctx, rs), // M3: UTXO-derived balance
		newUTXOCmd(ctx, rs),    // M3: utxo list
		newTxCmd(ctx, rs),      // M4: tx send/status/wait/list (the send pipeline)
		newFeeCmd(ctx, rs),     // M4: fee estimates + recommendation
		// descriptor/psbt/receive/policy/mcp land in later milestones
		// (docs/PLAN.md §4, §8).
	)

	return root
}
