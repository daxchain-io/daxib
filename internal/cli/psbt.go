package cli

import (
	"context"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/daxchain-io/daxib/internal/cli/render"
	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/service"
)

// psbt.go is the `psbt` noun: create/sign/combine/finalize/extract/broadcast/decode
// (BIP-174). It is a thin host — it resolves the PSBT input (a positional base64
// arg, --psbt-file, or --psbt-stdin), binds flags into the SAME domain request the
// MCP frontend binds, calls the service method, and renders. The policy chokepoint
// is in the service's PSBTSign (the ONLY path to keys.SignInputs runs through
// eng.Reserve); a PSBT is NOT a secret, so it may arrive as a flag value / arg.
//
// OUTPUT: the base64 PSBT (or the raw tx hex for extract) goes to stdout (one line),
// so `psbt create ... | psbt sign --psbt-stdin` pipes; --out writes the artifact to
// a file; --quiet prints the bare value.

func newPsbtCmd(ctx context.Context, rs *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "psbt",
		Short: "Build, sign, combine, finalize, extract, broadcast, and inspect PSBTs (BIP-174)",
		Long: "Partially-Signed Bitcoin Transactions (BIP-174). `psbt create` builds an\n" +
			"unsigned PSBT spending this wallet's coins; `psbt sign` enforces the sealed\n" +
			"spend policy before attaching signatures (the SAME chokepoint as `tx send`);\n" +
			"`psbt broadcast` finalizes + extracts + submits. combine/finalize/extract/decode\n" +
			"are pure plumbing for air-gapped and multisig flows.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(
		newPsbtCreateCmd(ctx, rs),
		newPsbtSignCmd(ctx, rs),
		newPsbtCombineCmd(ctx, rs),
		newPsbtFinalizeCmd(ctx, rs),
		newPsbtExtractCmd(ctx, rs),
		newPsbtBroadcastCmd(ctx, rs),
		newPsbtDecodeCmd(ctx, rs),
	)
	return cmd
}

// psbtInputFlags binds the shared PSBT-input flags (--psbt-file / --psbt-stdin) and
// the --out output-file flag onto a command.
type psbtInputFlags struct {
	file  string
	stdin bool
	out   string
}

func (f *psbtInputFlags) bind(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.StringVar(&f.file, "psbt-file", "", "read the PSBT from a file")
	fl.BoolVar(&f.stdin, "psbt-stdin", false, "read the PSBT from stdin (the air-gapped pipe)")
	fl.StringVar(&f.out, "out", "", "write the resulting PSBT/tx to a file instead of stdout")
}

// resolvePSBT reads the PSBT from EXACTLY ONE of: a positional base64 arg
// (bitcoind-idiomatic default), --psbt-file, or --psbt-stdin. None is
// usage.psbt_required; more than one is usage.cli.
func resolvePSBT(cmd *cobra.Command, args []string, f psbtInputFlags) (string, error) {
	count := 0
	if len(args) > 0 {
		count++
	}
	if f.file != "" {
		count++
	}
	if f.stdin {
		count++
	}
	switch {
	case count == 0:
		return "", domain.New(domain.CodePSBTRequired,
			"a PSBT is required: pass it as an argument, --psbt-file, or --psbt-stdin")
	case count > 1:
		return "", domain.New("usage.cli",
			"pass exactly one of a positional PSBT, --psbt-file, or --psbt-stdin")
	}
	if len(args) > 0 {
		return args[0], nil
	}
	if f.stdin {
		b, err := io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return "", domain.Wrap("usage.cli", "reading the PSBT from stdin", err)
		}
		return string(b), nil
	}
	b, err := os.ReadFile(f.file) // #nosec G304 -- a user-supplied PSBT file path is the point
	if err != nil {
		return "", domain.Wrap("usage.cli", "reading the PSBT file", err)
	}
	return string(b), nil
}

// emitPSBT renders a PSBTResult, writing the base64/hex to --out when set.
func emitPSBT(cmd *cobra.Command, m render.Mode, out string, res domain.PSBTResult) error {
	if out != "" {
		artifact := res.PSBT
		if artifact == "" {
			artifact = res.RawTxHex
		}
		if werr := os.WriteFile(out, []byte(artifact+"\n"), 0o600); werr != nil {
			return domain.Wrap(domain.CodeStateCorrupt, "writing the output file", werr)
		}
		// Still emit the structured/JSON envelope (minus the bare value already on disk).
		return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
			render.Line(w, m, "wrote %s", out)
		})
	}
	return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
		render.PSBT(w, m, res)
	})
}

func newPsbtCreateCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var wallet, to, amount, feeRate, speed, out string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Build an UNSIGNED PSBT spending the wallet's coins to --to/--amount (no signing, no policy)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if to == "" {
				return domain.New("usage.missing_to", "--to is required")
			}
			if amount == "" {
				return domain.New("usage.missing_amount", "--amount is required")
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.PSBTCreate(cmd.Context(), domain.LocalCLI(), domain.PSBTCreateRequest{
				Wallet: wallet, To: to, Amount: amount, FeeRate: feeRate, Speed: speed,
			})
			if err != nil {
				return err
			}
			return emitPSBT(cmd, rs.flags.Mode(), out, res)
		},
	}
	cmd.Flags().StringVar(&wallet, "wallet", "", "sender wallet (default: --wallet > DAXIB_WALLET > default)")
	cmd.Flags().StringVar(&to, "to", "", "recipient address (bech32 P2WPKH or any standard address)")
	cmd.Flags().StringVar(&amount, "amount", "", "amount to send (<btc> e.g. 0.001, or <n>sat e.g. 150000sat)")
	cmd.Flags().StringVar(&feeRate, "fee-rate", "", "fee rate in sat/vByte (default: estimate from the backend by --speed)")
	cmd.Flags().StringVar(&speed, "speed", "", "fee tier when --fee-rate is unset (slow|normal|fast); default normal")
	cmd.Flags().StringVar(&out, "out", "", "write the PSBT to a file instead of stdout")
	return cmd
}

func newPsbtSignCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var wallet string
	var pin psbtInputFlags
	var pf passphraseFlags
	cmd := &cobra.Command{
		Use:   "sign [psbt]",
		Short: "Sign the wallet-owned inputs of a PSBT — enforces the sealed spend policy FIRST",
		Long: "Decode a PSBT, detect this wallet's owned inputs by script match, re-verify\n" +
			"their values against the backend, then RESERVE the net wallet outflow against\n" +
			"the sealed spend policy (per-tx / rolling-24h / fee-rate / allowlist) BEFORE a\n" +
			"single byte is signed — a denied or over-limit sign produces NO signature. The\n" +
			"updated PSBT is emitted (not finalized — co-signers can still add sigs). Needs\n" +
			"the keystore passphrase (--passphrase-* / DAXIB_PASSPHRASE[_FILE]). --yes is\n" +
			"required when non-interactive (signing authorizes a spend).",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			b64, err := resolvePSBT(cmd, args, pin)
			if err != nil {
				return err
			}
			// AF-3 confirmation: signing authorizes a spend. Prompt at a TTY without --yes.
			proceed, cerr := confirmTxSend(cmd.ErrOrStderr(), cmd.InOrStdin(), promptTTY(rs), rs.flags.Yes, txConfirm{
				Action:    "Sign PSBT (authorizes the wallet's net outflow)",
				Recipient: "PSBT inputs owned by this wallet",
				Network:   promptNetworkLabel(rs),
			})
			if cerr != nil {
				return cerr
			}
			yes := rs.flags.Yes || proceed
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.PSBTSign(cmd.Context(), domain.LocalCLI(),
				domain.PSBTSignRequest{PSBT: b64, Wallet: wallet, Yes: yes},
				service.PSBTSignInput{PassphraseStdin: pf.stdin, PassphraseFile: pf.file})
			if err != nil {
				return err
			}
			return emitPSBT(cmd, rs.flags.Mode(), pin.out, res)
		},
	}
	cmd.Flags().StringVar(&wallet, "wallet", "", "wallet whose owned inputs to sign (default: --wallet > DAXIB_WALLET > default)")
	pin.bind(cmd)
	pf.bind(cmd)
	return cmd
}

func newPsbtCombineCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var files []string
	var out string
	cmd := &cobra.Command{
		Use:   "combine [psbt...]",
		Short: "Merge PSBTs that share the same unsigned tx (unions PartialSigs); pure",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			parts := append([]string{}, args...)
			for _, f := range files {
				b, rerr := os.ReadFile(f) // #nosec G304 -- a user-supplied PSBT file path is the point
				if rerr != nil {
					return domain.Wrap("usage.cli", "reading a PSBT file", rerr)
				}
				parts = append(parts, string(b))
			}
			if len(parts) == 0 {
				return domain.New(domain.CodePSBTRequired, "combine needs at least one PSBT (as args or --psbt-file)")
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.PSBTCombine(cmd.Context(), domain.LocalCLI(), domain.PSBTCombineRequest{PSBTs: parts})
			if err != nil {
				return err
			}
			return emitPSBT(cmd, rs.flags.Mode(), out, res)
		},
	}
	cmd.Flags().StringArrayVar(&files, "psbt-file", nil, "read a PSBT from a file (repeatable)")
	cmd.Flags().StringVar(&out, "out", "", "write the combined PSBT to a file instead of stdout")
	return cmd
}

func newPsbtFinalizeCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var pin psbtInputFlags
	cmd := &cobra.Command{
		Use:   "finalize [psbt]",
		Short: "Finalize a PSBT (assemble the witness from its PartialSigs); pure",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			b64, err := resolvePSBT(cmd, args, pin)
			if err != nil {
				return err
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.PSBTFinalize(cmd.Context(), domain.LocalCLI(), domain.PSBTFinalizeRequest{PSBT: b64})
			if err != nil {
				return err
			}
			return emitPSBT(cmd, rs.flags.Mode(), pin.out, res)
		},
	}
	pin.bind(cmd)
	return cmd
}

func newPsbtExtractCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var pin psbtInputFlags
	cmd := &cobra.Command{
		Use:   "extract [psbt]",
		Short: "Extract the raw network transaction (hex) from a complete PSBT; pure",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			b64, err := resolvePSBT(cmd, args, pin)
			if err != nil {
				return err
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.PSBTExtract(cmd.Context(), domain.LocalCLI(), domain.PSBTExtractRequest{PSBT: b64})
			if err != nil {
				return err
			}
			return emitPSBT(cmd, rs.flags.Mode(), pin.out, res)
		},
	}
	pin.bind(cmd)
	return cmd
}

func newPsbtBroadcastCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var wallet string
	var pin psbtInputFlags
	cmd := &cobra.Command{
		Use:   "broadcast [psbt]",
		Short: "Finalize + extract + broadcast a PSBT (the only PSBT verb that hits the network)",
		Long: "Finalize-if-needed, extract the raw tx, and broadcast it through the backend,\n" +
			"reusing the send broadcast tail (journal + commit the spend reservation taken at\n" +
			"sign time, cross-linked by txid). --yes is required when non-interactive.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			b64, err := resolvePSBT(cmd, args, pin)
			if err != nil {
				return err
			}
			proceed, cerr := confirmTxSend(cmd.ErrOrStderr(), cmd.InOrStdin(), promptTTY(rs), rs.flags.Yes, txConfirm{
				Action:    "Broadcast PSBT",
				Recipient: "the PSBT's recipients",
				Network:   promptNetworkLabel(rs),
			})
			if cerr != nil {
				return cerr
			}
			yes := rs.flags.Yes || proceed
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			m := rs.flags.Mode()
			sink := render.StderrProgress(cmd.ErrOrStderr(), m.JSON)
			res, err := svc.PSBTBroadcast(cmd.Context(), domain.LocalCLI(),
				domain.PSBTBroadcastRequest{PSBT: b64, Wallet: wallet, Yes: yes}, sink)
			return renderTxOutcome(cmd, m, res, err)
		},
	}
	cmd.Flags().StringVar(&wallet, "wallet", "", "wallet that owns the PSBT (default: --wallet > DAXIB_WALLET > default)")
	pin.bind(cmd)
	return cmd
}

func newPsbtDecodeCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var wallet string
	var pin psbtInputFlags
	cmd := &cobra.Command{
		Use:   "decode [psbt]",
		Short: "Inspect a PSBT: inputs/outputs/fee/which-are-mine/signed/complete (read-only)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			b64, err := resolvePSBT(cmd, args, pin)
			if err != nil {
				return err
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.PSBTDecode(cmd.Context(), domain.LocalCLI(), domain.PSBTDecodeRequest{PSBT: b64, Wallet: wallet})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.PSBT(w, m, res)
			})
		},
	}
	cmd.Flags().StringVar(&wallet, "wallet", "", "wallet to annotate which inputs/outputs are mine (default: --wallet > DAXIB_WALLET > default)")
	pin.bind(cmd)
	return cmd
}
