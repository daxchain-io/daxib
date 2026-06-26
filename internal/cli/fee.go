package cli

import (
	"context"
	"io"

	"github.com/spf13/cobra"

	"github.com/daxchain-io/daxib/internal/cli/render"
	"github.com/daxchain-io/daxib/internal/domain"
)

// newFeeCmd builds the `fee` noun (the Bitcoin analog of daxie's `gas`): a pure
// read of the active backend's sat/vByte estimates by speed tier, with the 1
// sat/vB relay floor and the --speed-selected recommendation. No signing.
func newFeeCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var speed string
	cmd := &cobra.Command{
		Use:   "fee",
		Short: "Show backend fee estimates (sat/vB) and a recommendation",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.Fee(cmd.Context(), domain.FeeRequest{Speed: speed})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.FeeQuotes(w, m, res)
			})
		},
	}
	cmd.Flags().StringVar(&speed, "speed", "", "fee tier to recommend (slow|normal|fast); default normal")
	return cmd
}
