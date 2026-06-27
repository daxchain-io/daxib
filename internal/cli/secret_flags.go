package cli

import "github.com/spf13/cobra"

// The secret-flag groups bind the §3.6 non-interactive secret-source flags onto a
// command. Each is a small struct the command embeds; bind() registers the flag
// pair. Secrets NEVER arrive as a flag VALUE (only --*-stdin / --*-file), so a
// passphrase or mnemonic cannot leak into a process listing or shell history.

type passphraseFlags struct {
	stdin bool
	file  string
}

func (f *passphraseFlags) bind(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.BoolVar(&f.stdin, "passphrase-stdin", false, "read the keystore passphrase from stdin")
	fl.StringVar(&f.file, "passphrase-file", "", "read the keystore passphrase from a file (perms checked)")
}

type confirmFlags struct {
	stdin bool
	file  string
}

func (f *confirmFlags) bind(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.BoolVar(&f.stdin, "passphrase-confirm-stdin", false, "first-init only: confirm the new keystore passphrase from stdin")
	fl.StringVar(&f.file, "passphrase-confirm-file", "", "first-init only: confirm the new keystore passphrase from a file")
}

type mnemonicFlags struct {
	stdin bool
	file  string
}

func (f *mnemonicFlags) bind(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.BoolVar(&f.stdin, "mnemonic-stdin", false, "read the BIP-39 mnemonic from stdin")
	fl.StringVar(&f.file, "mnemonic-file", "", "read the BIP-39 mnemonic from a file (perms checked)")
}

type bip39Flags struct {
	stdin bool
	file  string
}

func (f *bip39Flags) bind(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.BoolVar(&f.stdin, "bip39-passphrase-stdin", false, "read the optional BIP-39 passphrase (25th word) from stdin")
	fl.StringVar(&f.file, "bip39-passphrase-file", "", "read the optional BIP-39 passphrase (25th word) from a file")
}

// adminFlags binds the ADMIN-passphrase channel for policy mutations. The admin
// secret is INDEPENDENT of the keystore passphrase (distinct flags + env) and never
// arrives as a flag VALUE — only via stdin/file (or DAXIB_ADMIN_PASSPHRASE[_FILE]).
type adminFlags struct {
	stdin bool
	file  string
}

func (f *adminFlags) bind(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.BoolVar(&f.stdin, "admin-passphrase-stdin", false, "read the policy admin passphrase from stdin")
	fl.StringVar(&f.file, "admin-passphrase-file", "", "read the policy admin passphrase from a file (perms checked)")
}

// adminNewFlags binds the NEW admin-passphrase channel for change-admin-passphrase.
type adminNewFlags struct {
	stdin bool
	file  string
}

func (f *adminNewFlags) bind(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.BoolVar(&f.stdin, "new-admin-passphrase-stdin", false, "read the NEW policy admin passphrase from stdin")
	fl.StringVar(&f.file, "new-admin-passphrase-file", "", "read the NEW policy admin passphrase from a file")
}

// newPassphraseFlags binds the NEW keystore-passphrase channel (+ its mandatory
// confirmation) for `keystore change-passphrase`. The new passphrase is INDEPENDENT
// of the old --passphrase-* channel and never arrives as a flag VALUE.
type newPassphraseFlags struct {
	stdin        bool
	file         string
	confirmStdin bool
	confirmFile  string
}

func (f *newPassphraseFlags) bind(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.BoolVar(&f.stdin, "new-passphrase-stdin", false, "read the NEW keystore passphrase from stdin")
	fl.StringVar(&f.file, "new-passphrase-file", "", "read the NEW keystore passphrase from a file (perms checked)")
	fl.BoolVar(&f.confirmStdin, "new-passphrase-confirm-stdin", false, "confirm the NEW keystore passphrase from stdin")
	fl.StringVar(&f.confirmFile, "new-passphrase-confirm-file", "", "confirm the NEW keystore passphrase from a file")
}
