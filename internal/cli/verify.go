package cli

import (
	"context"
	"io"

	"github.com/spf13/cobra"

	"github.com/daxchain-io/daxib/internal/cli/render"
	"github.com/daxchain-io/daxib/internal/domain"
)

// verify.go is the `daxib verify` command: passphrase-free BIP-322 verification of
// a (--address, --message, --signature) triple. An INVALID signature is a
// successful verification with valid=false (exit 0), so an agent branches on the
// field, not the exit code; only a malformed input is a non-zero error.

func newVerifyCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var address, message, messageFile, signature string
	var messageStdin bool
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a BIP-322 message signature (no passphrase)",
		Long: "Verify a BIP-322 \"simple\" signature for an address + message. Passphrase-\n" +
			"free: it only reconstructs the BIP-322 virtual transactions and runs the\n" +
			"script engine. A signature that is well-formed but does not match returns\n" +
			"valid=false with exit 0 (not an error) — branch on the field. The message\n" +
			"arrives via --message, --message-file, or --message-stdin.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			msg, err := resolveMessage(cmd, message, messageFile, messageStdin)
			if err != nil {
				return err
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.MessageVerify(cmd.Context(), domain.LocalCLI(), domain.MessageVerifyRequest{
				Address:   address,
				Message:   string(msg),
				Signature: signature,
			})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				// The verdict IS the essential output, so it prints regardless of
				// --quiet (render.Line would suppress it).
				verdict := "invalid"
				if res.Valid {
					verdict = "valid"
				}
				_, _ = io.WriteString(w, verdict+"\n")
			})
		},
	}
	cmd.Flags().StringVar(&address, "address", "", "the P2WPKH address that signed the message")
	cmd.Flags().StringVar(&message, "message", "", "the signed message (inline)")
	cmd.Flags().StringVar(&messageFile, "message-file", "", "read the signed message from a file")
	cmd.Flags().BoolVar(&messageStdin, "message-stdin", false, "read the signed message from stdin")
	cmd.Flags().StringVar(&signature, "signature", "", "the base64 BIP-322 signature to verify")
	return cmd
}
