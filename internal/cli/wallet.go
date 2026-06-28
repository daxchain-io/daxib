package cli

import (
	"context"
	"io"

	"github.com/spf13/cobra"

	"github.com/daxchain-io/daxib/internal/cli/render"
	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/service"
)

// newWalletCmd builds the `wallet` noun (create/import/list/show/export). It is
// operator-only: no MCP tool is registered for any of these in v1 (the agent gets
// move-funds + read, never key creation/export).
func newWalletCmd(ctx context.Context, rs *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "wallet",
		Short: "Manage HD wallets (create, import, list, show, export)",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(
		newWalletCreateCmd(ctx, rs),
		newWalletImportCmd(ctx, rs),
		newWalletListCmd(ctx, rs),
		newWalletShowCmd(ctx, rs),
		newWalletExportCmd(ctx, rs),
		newWalletUpgradeCmd(ctx, rs),
	)
	return cmd
}

func newWalletCreateCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var words int
	var bind bool
	var pf passphraseFlags
	var cf confirmFlags
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new HD wallet (generates a fresh mnemonic, shown ONCE)",
		Long: "Generate a fresh BIP-39 mnemonic, show it ONCE, and encrypt it into the\n" +
			"keystore. RECORD THE MNEMONIC: it is the only backup and is never shown\n" +
			"again. On the first wallet, the keystore passphrase is confirmed by\n" +
			"double-entry (a typo cannot fork the keystore).\n\n" +
			"By default the wallet is NETWORK-AGNOSTIC: one wallet works on every\n" +
			"network (--network only picks which HRP the printed receive address uses).\n" +
			"Pass --bind to lock the wallet to a single network (the resolved\n" +
			"--network), refusing ops on any other.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := preflightMnemonicDisplay(rs.flags.Yes, rs.flags.Mode().JSON); err != nil {
				return err
			}
			network, err := flagNetwork(rs)
			if err != nil {
				return err
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.WalletCreate(cmd.Context(), domain.LocalCLI(), domain.WalletCreateRequest{
				Name: args[0], Words: words, Network: network, Bind: bind, Yes: rs.flags.Yes,
			}, service.WalletCreateInput{
				PassphraseStdin: pf.stdin, PassphraseFile: pf.file,
				ConfirmStdin: cf.stdin, ConfirmFile: cf.file,
			})
			if err != nil {
				return err
			}

			m := rs.flags.Mode()
			disp, cerr := mnemonicCeremony(cmd.ErrOrStderr(), cmd.InOrStdin(), rs.flags.Yes, m.JSON, res.Mnemonic, res.BIP39Passphrase)
			if cerr != nil {
				return cerr
			}
			if !disp.echoInResult {
				res.Mnemonic = ""
				res.BIP39Passphrase = ""
				res.Sensitive = false
			}

			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "wallet %q created (%s) — %s", res.Name, res.WalletID, scopeLabel(res.Scope, res.Network))
				if res.Receive0Address != "" {
					render.Line(w, m, "receive %s -> %s", res.Receive0, res.Receive0Address)
				} else {
					render.Line(w, m, "(no network selected — sample address omitted; select one with --network or `daxib network use`)")
				}
				if disp.echoInResult {
					render.Line(w, m, "")
					render.Line(w, m, "RECORD THIS MNEMONIC — it is shown only once:")
					_, _ = io.WriteString(w, res.Mnemonic+"\n")
					if res.BIP39Passphrase != "" {
						_, _ = io.WriteString(w, "bip39-passphrase: "+res.BIP39Passphrase+"\n")
					}
				}
			})
		},
	}
	cmd.Flags().IntVar(&words, "words", 12, "mnemonic length: 12 or 24")
	cmd.Flags().BoolVar(&bind, "bind", false, "lock the wallet to the active --network (default: network-agnostic)")
	pf.bind(cmd)
	cf.bind(cmd)
	return cmd
}

func newWalletImportCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var bind bool
	var pf passphraseFlags
	var cf confirmFlags
	var mf mnemonicFlags
	var bf bip39Flags
	cmd := &cobra.Command{
		Use:   "import <name>",
		Short: "Import an existing BIP-39 mnemonic",
		Long: "Import a BIP-39 mnemonic (NFKD-normalized, checksum-validated). The\n" +
			"mnemonic arrives via --mnemonic-stdin / --mnemonic-file (never a flag\n" +
			"value). An optional BIP-39 passphrase (25th word) via --bip39-passphrase-*.\n\n" +
			"By default the wallet is NETWORK-AGNOSTIC (works on every network); pass\n" +
			"--bind to lock it to the active --network.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			network, err := flagNetwork(rs)
			if err != nil {
				return err
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.WalletImport(cmd.Context(), domain.LocalCLI(), domain.WalletImportRequest{
				Name: args[0], Network: network, Bind: bind, Yes: rs.flags.Yes,
			}, service.WalletImportInput{
				MnemonicStdin: mf.stdin, MnemonicFile: mf.file,
				BIP39Stdin: bf.stdin, BIP39File: bf.file,
				PassphraseStdin: pf.stdin, PassphraseFile: pf.file,
				ConfirmStdin: cf.stdin, ConfirmFile: cf.file,
			})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "wallet %q imported (%s) — %s", res.Name, res.WalletID, scopeLabel(res.Scope, res.Network))
				if res.Receive0Address != "" {
					_, _ = io.WriteString(w, res.Receive0+" "+res.Receive0Address+"\n")
				}
			})
		},
	}
	cmd.Flags().BoolVar(&bind, "bind", false, "lock the wallet to the active --network (default: network-agnostic)")
	pf.bind(cmd)
	cf.bind(cmd)
	mf.bind(cmd)
	bf.bind(cmd)
	return cmd
}

// scopeLabel renders a wallet's scope for human output: "agnostic" or
// "bound to <net>".
func scopeLabel(scope string, net domain.Network) string {
	if scope == "bound" {
		return "bound to " + string(net)
	}
	return "agnostic"
}

func newWalletListCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List wallets (names, networks, address counts)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.WalletList(cmd.Context(), domain.LocalCLI(), domain.WalletListRequest{})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				tbl := render.NewTable(w)
				if !m.Quiet {
					tbl.Row("NAME", "WALLET_ID", "SCOPE", "NETWORK", "ADDRESSES", "DEFAULT", "CREATED")
				}
				for _, wl := range res.Wallets {
					def := ""
					if wl.Default {
						def = "*"
					}
					tbl.Row(wl.Name, wl.WalletID, scopeColumn(wl.Scope, wl.Network), string(wl.Network), itoa(wl.Addresses), def, wl.CreatedAt)
				}
				_ = tbl.Flush()
			})
		},
	}
}

func newWalletShowCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show a wallet's detail (xpub, watermarks, address count)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.WalletShow(cmd.Context(), domain.LocalCLI(), domain.WalletShowRequest{Name: args[0]})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				tbl := render.NewTable(w)
				tbl.Row("name", res.Name)
				tbl.Row("wallet_id", res.WalletID)
				tbl.Row("scope", scopeColumn(res.Scope, res.Network))
				tbl.Row("network", string(res.Network))
				tbl.Row("coin_type", itoa(int(res.CoinType)))
				tbl.Row("path_prefix", res.PathPrefix)
				tbl.Row("account_xpub", res.AccountXpub)
				tbl.Row("next_receive", itoa(int(res.NextReceive)))
				tbl.Row("next_change", itoa(int(res.NextChange)))
				tbl.Row("addresses", itoa(res.Addresses))
				tbl.Row("created_at", res.CreatedAt)
				_ = tbl.Flush()
			})
		},
	}
}

func newWalletExportCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var pf passphraseFlags
	cmd := &cobra.Command{
		Use:   "export <name>",
		Short: "Export a wallet's mnemonic (operator-only; needs the passphrase)",
		Long: "Print the wallet's BIP-39 mnemonic and optional passphrase under explicit\n" +
			"labels. Operator-only — the agent's MCP surface never exposes this.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.WalletExport(cmd.Context(), domain.LocalCLI(), domain.WalletExportRequest{
				Name: args[0], Yes: rs.flags.Yes,
			}, service.WalletExportInput{PassphraseStdin: pf.stdin, PassphraseFile: pf.file})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "wallet %q (%s):", res.Name, res.WalletID)
				_, _ = io.WriteString(w, "mnemonic: "+res.Mnemonic+"\n")
				if res.BIP39Passphrase != "" {
					_, _ = io.WriteString(w, "bip39-passphrase: "+res.BIP39Passphrase+"\n")
				}
			})
		},
	}
	pf.bind(cmd)
	return cmd
}

// scopeColumn renders the wallet-list/show SCOPE column: "agnostic" or
// "bound:<net>".
func scopeColumn(scope string, net domain.Network) string {
	if scope == "bound" {
		return "bound:" + string(net)
	}
	return "agnostic"
}

func newWalletUpgradeCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var pf passphraseFlags
	cmd := &cobra.Command{
		Use:   "upgrade <name>",
		Short: "Promote a bound (or legacy) wallet to network-agnostic",
		Long: "Derive the missing coin_type account key (one-time passphrase) so a wallet\n" +
			"that was created with --bind — or migrated from an older keystore — works\n" +
			"on every network. An already-agnostic wallet is a no-op error.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.WalletUpgrade(cmd.Context(), domain.LocalCLI(), domain.WalletUpgradeRequest{
				Name: args[0], Yes: rs.flags.Yes,
			}, service.WalletUpgradeInput{PassphraseStdin: pf.stdin, PassphraseFile: pf.file})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "wallet %q upgraded (%s) — now %s", res.Name, res.WalletID, scopeLabel(res.Scope, res.Network))
			})
		},
	}
	pf.bind(cmd)
	return cmd
}
