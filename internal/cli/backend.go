package cli

import (
	"context"
	"io"

	"github.com/spf13/cobra"

	"github.com/daxchain-io/daxib/internal/cli/render"
	"github.com/daxchain-io/daxib/internal/domain"
)

// newBackendCmd builds the `backend` noun (add/list/use/test/remove): the Bitcoin
// backend endpoint set (bitcoind RPC / Esplora). It mirrors daxie's `rpc` command
// idioms, swapping the Ethereum endpoint for a typed Bitcoin backend. Endpoints
// are stored in the config file with ${env:}/${file:} secret references kept RAW.
func newBackendCmd(ctx context.Context, rs *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "backend",
		Short: "Manage Bitcoin backends (bitcoind RPC / Esplora)",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(
		newBackendAddCmd(ctx, rs),
		newBackendListCmd(ctx, rs),
		newBackendUseCmd(ctx, rs),
		newBackendTestCmd(ctx, rs),
		newBackendRemoveCmd(ctx, rs),
	)
	return cmd
}

func newBackendAddCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var network, typ, url, rpcuser, rpcpassword, rpccookie string
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a named backend endpoint bound to a network",
		Long: "Add a Bitcoin backend endpoint. --type core is a bitcoind JSON-RPC node\n" +
			"(auth: --rpcuser/--rpcpassword or --rpccookie); --type esplora is a REST\n" +
			"server. Secrets should be ${env:VAR} / ${file:/path} references — they are\n" +
			"stored RAW and resolved only at dial time, never persisted resolved.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			network, err := flagNetworkOrDefault(rs, network)
			if err != nil {
				return err
			}
			bt, err := domain.ParseBackendType(typ)
			if err != nil {
				return err
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, warnings, err := svc.BackendAdd(cmd.Context(), domain.LocalCLI(), domain.BackendAddRequest{
				Name: args[0], Network: network, Type: bt, URL: url,
				RPCUser: rpcuser, RPCPassword: rpcpassword, RPCCookie: rpccookie,
			})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			for _, w := range warnings {
				_, _ = io.WriteString(cmd.ErrOrStderr(), "warning: "+w+"\n")
			}
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "backend %q added (%s) on %s", res.Name, res.Type, res.Network)
				_, _ = io.WriteString(w, res.URL+"\n")
			})
		},
	}
	cmd.Flags().StringVar(&network, "network", "", "network this backend serves (default: active --network)")
	cmd.Flags().StringVar(&typ, "type", "", "backend type: core (bitcoind RPC) or esplora (REST)")
	cmd.Flags().StringVar(&url, "url", "", "endpoint URL (Core: JSON-RPC; Esplora: REST base)")
	cmd.Flags().StringVar(&rpcuser, "rpcuser", "", "Core RPC username (${env:}/${file:} ref or literal)")
	cmd.Flags().StringVar(&rpcpassword, "rpcpassword", "", "Core RPC password (${env:}/${file:} ref — avoid literals)")
	cmd.Flags().StringVar(&rpccookie, "rpccookie", "", "path to a bitcoind .cookie file (alternative to rpcuser/rpcpassword)")
	return cmd
}

func newBackendListCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List configured backends (masked URLs)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.BackendList(cmd.Context(), domain.LocalCLI(), domain.BackendListRequest{})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				tbl := render.NewTable(w)
				if !m.Quiet {
					tbl.Row("NAME", "NETWORK", "TYPE", "URL", "DEFAULT")
				}
				for _, b := range res.Backends {
					def := ""
					if b.Default {
						def = "*"
					}
					tbl.Row(b.Name, string(b.Network), string(b.Type), b.URL, def)
				}
				_ = tbl.Flush()
			})
		},
	}
}

func newBackendUseCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "use <name>",
		Short: "Make a backend the default for its network",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.BackendUse(cmd.Context(), domain.LocalCLI(), domain.BackendUseRequest{Name: args[0]})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "backend %q is now the default for %s", res.Name, res.Network)
			})
		},
	}
}

func newBackendTestCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "test [name]",
		Short: "Dial a backend and report its tip height + latency",
		Long: "Dial the named backend (or the active network's default) and call\n" +
			"TipHeight, reporting the observed block height and round-trip latency.\n" +
			"A dead endpoint exits 6 (backend.unreachable).",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := ""
			if len(args) == 1 {
				name = args[0]
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.BackendTest(cmd.Context(), domain.LocalCLI(), domain.BackendTestRequest{Name: name})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "backend %q (%s, %s) on %s", res.Name, res.Type, res.URL, res.Network)
				render.Line(w, m, "tip height %s, latency %sms", itoa(int(res.TipHeight)), itoa(int(res.LatencyMS)))
				if m.Quiet {
					_, _ = io.WriteString(w, itoa(int(res.TipHeight))+"\n")
				}
			})
		},
	}
}

func newBackendRemoveCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove a backend (clears any network default that pointed at it)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.BackendRemove(cmd.Context(), domain.LocalCLI(), domain.BackendRemoveRequest{Name: args[0]})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "backend %q removed", res.Name)
				if res.ClearedFor != "" {
					render.Line(w, m, "cleared the default backend for %s", res.ClearedFor)
				}
			})
		},
	}
}
