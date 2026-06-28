package cli

import (
	"context"
	"io"

	"github.com/daxchain-io/daxib/internal/cli/render"
	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/spf13/cobra"
)

// convert.go is the `daxib convert <amount> [<to-unit>]` utility: float-free
// sat↔BTC conversion so an agent never hand-rolls the 10^8 satoshi math. The
// amount carries its source unit as a suffix ("0.001btc", "150000sat") or is a
// bare BTC number (the sendtoaddress convention); an optional second positional
// names the target unit (sat|btc), defaulting to the OTHER unit.
//
// It is a thin host over svc.Convert (a PURE use case — no keystore, no backend,
// no network), so it runs in any environment. Exit codes: 0 ok; 2 (usage) for a
// bad unit or an unparseable amount (both funnel through the usage.* family).
//
// Output:
//   - human: the converted value alone on stdout (e.g. `daxib convert 0.001btc`
//     prints `100000`) — a clean scalar `$(daxib convert …)` captures directly.
//   - --json: the full domain.ConvertResult {input,sat,btc,from,to,value}.
func newConvertCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "convert <amount> [sat|btc]",
		Short: "Convert an amount between satoshis and BTC",
		Long: "Convert a Bitcoin amount between satoshis and BTC, float-free. The amount\n" +
			"carries its source unit as a suffix; an optional second argument names the\n" +
			"target unit (sat|btc) and defaults to the other unit.\n\n" +
			"A leading '-' is parsed by the shell/flag layer as a flag; pass a literal\n" +
			"'--' first so a negative amount reaches the parser (and is rejected as a bad\n" +
			"amount): `daxib convert -- -1sat`.\n\nExamples:\n" +
			"  daxib convert 0.001btc        # 100000\n" +
			"  daxib convert 100000sat       # 0.00100000\n" +
			"  daxib convert 0.5             # 50000000   (a bare number is BTC)\n" +
			"  daxib convert 100000sat btc --json\n" +
			"  daxib convert -- -1sat        # rejected: amounts must be non-negative",
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			to := ""
			if len(args) == 2 {
				to = args[1]
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.Convert(cmd.Context(), domain.LocalCLI(), domain.ConvertRequest{Amount: args[0], To: to})
			if err != nil {
				return err
			}

			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				// Human output is the bare value so `$(daxib convert …)` captures a clean
				// scalar; --quiet has no further effect (the value is essential output).
				_, _ = io.WriteString(w, res.Value+"\n")
			})
		},
	}
}
