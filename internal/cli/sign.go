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

// sign.go is the `daxib sign message` command: BIP-322 "simple" message signing
// for a wallet's P2WPKH address. It needs the keystore passphrase to unlock the
// address's key. The signature is the base64 BIP-322 witness, which `verify`
// checks passphrase-free.

func newSignCmd(ctx context.Context, rs *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign a message with a wallet address's key (BIP-322)",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newSignMessageCmd(ctx, rs))
	return cmd
}

func newSignMessageCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var wallet string
	var message, messageFile string
	var messageStdin bool
	var pf passphraseFlags
	cmd := &cobra.Command{
		Use:   "message <address|wallet/branch/index>",
		Short: "BIP-322 sign a message with the address's key",
		Long: "Sign a message with the private key behind a P2WPKH address using BIP-322\n" +
			"\"simple\". The signing target is an address OR a <wallet>/<branch>/<index>\n" +
			"ref. The message arrives via --message, --message-file, or --message-stdin.\n" +
			"Unlocking the key needs the keystore passphrase (--passphrase-* /\n" +
			"DAXIB_PASSPHRASE[_FILE]). The base64 signature is verifiable with `daxib\n" +
			"verify` (no passphrase).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			msg, err := resolveMessage(cmd, message, messageFile, messageStdin)
			if err != nil {
				return err
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.MessageSign(cmd.Context(),
				domain.MessageSignRequest{Wallet: wallet, Ref: args[0], Yes: rs.flags.Yes},
				service.MessageSignInput{
					Message:         msg,
					PassphraseStdin: pf.stdin,
					PassphraseFile:  pf.file,
				})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				if !m.Quiet {
					tbl := render.NewTable(w)
					tbl.Row("address", res.Address)
					tbl.Row("format", res.Format)
					tbl.Row("signature", res.Signature)
					_ = tbl.Flush()
					return
				}
				// --quiet: the signature is the essential output; print it bare.
				_, _ = io.WriteString(w, res.Signature+"\n")
			})
		},
	}
	cmd.Flags().StringVar(&wallet, "wallet", "", "wallet name to scope the address lookup (default: --wallet flag > DAXIB_WALLET)")
	cmd.Flags().StringVar(&message, "message", "", "the message to sign (inline)")
	cmd.Flags().StringVar(&messageFile, "message-file", "", "read the message from a file")
	cmd.Flags().BoolVar(&messageStdin, "message-stdin", false, "read the message from stdin")
	pf.bind(cmd)
	return cmd
}

// resolveMessage reads the message from exactly one of --message / --message-file /
// --message-stdin. A missing source is usage.message_required; more than one is a
// usage error. The message is NOT a secret, so a flag VALUE is allowed (unlike a
// passphrase).
func resolveMessage(cmd *cobra.Command, inline, file string, stdin bool) ([]byte, error) {
	count := 0
	if cmd.Flags().Changed("message") {
		count++
	}
	if file != "" {
		count++
	}
	if stdin {
		count++
	}
	switch {
	case count == 0:
		return nil, domain.New(domain.CodeMessageRequired,
			"a message is required: pass --message, --message-file, or --message-stdin")
	case count > 1:
		return nil, domain.New("usage.cli",
			"pass exactly one of --message, --message-file, or --message-stdin")
	}
	if cmd.Flags().Changed("message") {
		return []byte(inline), nil
	}
	if stdin {
		b, err := io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return nil, domain.Wrap("usage.cli", "reading the message from stdin", err)
		}
		return b, nil
	}
	b, err := os.ReadFile(file) // #nosec G304 -- a user-supplied message file path is the point
	if err != nil {
		return nil, domain.Wrap("usage.cli", "reading the message file", err)
	}
	return b, nil
}
