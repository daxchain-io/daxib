package cli

import (
	"io"

	"github.com/daxchain-io/daxib/internal/cli/render"
	"github.com/daxchain-io/daxib/internal/version"
	"github.com/spf13/cobra"
)

// newVersionCmd builds `daxib version`.
//
// Human: a one-line "daxib <ver> (commit <c>, built <d>)".
// --json: {"version":..,"commit":..,"date":..} (version.Info marshaled).
// No service is opened — version reads only the ldflags-injected build stamp, so
// it runs in any environment.
//
// Exit codes: 0 always (no failure mode).
func newVersionCmd(rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version, commit, and build date",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			info := version.Get()
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, info, func(w io.Writer) {
				// The version line IS the essential output of `daxib version`, so it
				// must print regardless of --quiet. render.Line is for non-essential
				// chatter only and returns early under --quiet, which would suppress
				// the whole result — that is exactly the bug we avoid here.
				_, _ = io.WriteString(w, info.String()+"\n")
			})
		},
	}
}
