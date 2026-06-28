package cli

import (
	"context"
	"io"

	"github.com/daxchain-io/daxib/internal/cli/render"
	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/spf13/cobra"
)

// config.go is the `daxib config get|set|list` noun: the generic operator-config
// surface over config.toml (the per-network default-backend selection). The named
// [backend.<name>] endpoint objects are managed by the `backend` noun; the
// policy.* subtree is REJECTED here (it lives in the sealed anchor, set only via
// `daxib policy` — the carve-out daxie also enforces).
//
// Exit codes: 0 ok; 2 (usage) for a rejected policy.* set / bad key / bad value;
// 10 (ref.not_found) for an unknown key on get; 10 (config.read_only) for a set
// against a read-only config mount; 10 (backend.not_configured) when no --config
// path is set.
func newConfigCmd(ctx context.Context, rs *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Get, set, and list operator config keys",
		Long: "Inspect and modify operator settings in config.toml.\n\n" +
			"Named backend endpoints are managed with `daxib backend`. Policy keys (spend\n" +
			"limits, allowlists) are NOT managed here — they live in the sealed policy file,\n" +
			"set only via `daxib policy` with the admin passphrase. `config set policy.<key>`\n" +
			"is rejected.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(
		newConfigListCmd(ctx, rs),
		newConfigGetCmd(ctx, rs),
		newConfigSetCmd(ctx, rs),
	)
	return cmd
}

func newConfigListCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all operator config keys with their effective values",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.ConfigList(cmd.Context(), domain.LocalCLI())
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				tbl := render.NewTable(w)
				if !m.Quiet {
					tbl.Row("KEY", "VALUE", "SOURCE")
				}
				for _, kv := range res.Entries {
					tbl.Row(kv.Key, kv.Value, kv.Source)
				}
				_ = tbl.Flush()
			})
		},
	}
}

func newConfigGetCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "get <key>",
		Short: "Print one config key's effective value",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.ConfigGet(cmd.Context(), domain.LocalCLI(), domain.ConfigGetRequest{Key: args[0]})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			// --json emits {key,value}; human prints the bare value (a clean scalar).
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				_, _ = io.WriteString(w, res.Value+"\n")
			})
		},
	}
}

func newConfigSetCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set one config key (targeted config.toml rewrite)",
		Long: "Write one operator key into config.toml via an atomic, locked rewrite.\n\n" +
			"Settable keys: networks.<network>.default-backend (the endpoint dialed when no\n" +
			"--backend override is given; an empty value clears it). policy.* keys are\n" +
			"rejected. A read-only config mount fails with config.read_only (exit 10).",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.ConfigSet(cmd.Context(), domain.LocalCLI(), domain.ConfigSetRequest{Key: args[0], Value: args[1]})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "set %s = %s", res.Key, res.Value)
			})
		},
	}
}
