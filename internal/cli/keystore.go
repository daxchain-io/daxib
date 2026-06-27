package cli

import (
	"context"
	"io"

	"github.com/spf13/cobra"

	"github.com/daxchain-io/daxib/internal/cli/render"
	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/service"
)

// keystore.go is the `daxib keystore` command tree: change-passphrase (operator-
// only atomic re-encryption, §3.8) and info (read-only). Neither is exposed as an
// MCP tool — an agent never re-encrypts or introspects the keystore's KDF.

func newKeystoreCmd(ctx context.Context, rs *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keystore",
		Short: "Keystore maintenance (re-encrypt under a new passphrase, info)",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(
		newKeystoreChangePassphraseCmd(ctx, rs),
		newKeystoreInfoCmd(ctx, rs),
	)
	return cmd
}

func newKeystoreChangePassphraseCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var pf passphraseFlags // the OLD passphrase (--passphrase-*)
	var nf newPassphraseFlags
	cmd := &cobra.Command{
		Use:   "change-passphrase",
		Short: "Re-encrypt the keystore under a new passphrase (atomic, crash-safe)",
		Long: "Re-encrypt every keystore secret (the verifier and every wallet blob) under\n" +
			"a new passphrase. The rotation is atomic and crash-safe: a crash leaves the\n" +
			"all-old or all-new keystore, never a mix (the next open rolls forward or back).\n\n" +
			"Old passphrase: --passphrase-* / DAXIB_PASSPHRASE[_FILE].\n" +
			"New passphrase: --new-passphrase-* / DAXIB_NEW_PASSPHRASE[_FILE]\n" +
			"  (confirmed via --new-passphrase-confirm-* / DAXIB_NEW_PASSPHRASE_CONFIRM[_FILE]).\n\n" +
			"Operator-only — no MCP tool exposes this. Rotating under a running `mcp serve`\n" +
			"requires restarting it.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.KeystoreChangePassphrase(cmd.Context(),
				domain.KeystoreChangePassphraseRequest{Yes: rs.flags.Yes},
				service.KeystoreChangePassphraseInput{
					OldStdin: pf.stdin, OldFile: pf.file,
					NewStdin: nf.stdin, NewFile: nf.file,
					NewConfirmStdin: nf.confirmStdin, NewConfirmFile: nf.confirmFile,
				})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "keystore re-encrypted: %s file(s) rotated", itoa(res.RotatedFiles))
			})
		},
	}
	pf.bind(cmd)
	nf.bind(cmd)
	return cmd
}

func newKeystoreInfoCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "info",
		Short: "Show keystore path, format, KDF, and wallet count (read-only)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.KeystoreInfo(cmd.Context(), domain.KeystoreInfoRequest{})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				tbl := render.NewTable(w)
				tbl.Row("path", res.Path)
				tbl.Row("format", itoa(res.Format))
				tbl.Row("initialized", boolWord(res.Initialized))
				tbl.Row("wallets", itoa(res.Wallets))
				tbl.Row("kdf", res.KDF)
				tbl.Row("scrypt_n", itoa(res.ScryptN))
				_ = tbl.Flush()
			})
		},
	}
}

// boolWord renders a bool as "yes"/"no" for human keystore/info tables.
func boolWord(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
