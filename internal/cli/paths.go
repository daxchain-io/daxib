package cli

import (
	"os"
	"path/filepath"
)

// daxibHome returns the root of daxib's default on-disk home: a single "~/.daxib"
// dotfolder under the user's home directory that holds the config, keystore, and
// state classes as subpaths. daxib deliberately diverges from the platform
// XDG/AppData convention — and from daxie's ~/.config/daxie — in favor of one
// discoverable, easy-to-back-up directory. A best-effort relative ".daxib"
// fallback covers the rare case where the home directory cannot be determined.
//
// All three defaults below are overridable: --keystore / DAXIB_KEYSTORE,
// --config / DAXIB_CONFIG, and --state-dir / DAXIB_STATE_DIR take precedence over
// the ~/.daxib layout (resolved in open.go).
func daxibHome() string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".daxib")
	}
	return ".daxib"
}

// defaultKeystoreDir is "~/.daxib/keystore" — the encrypted keystore (wallet
// blobs + verifier) — used when neither --keystore nor DAXIB_KEYSTORE is set.
func defaultKeystoreDir() string {
	return filepath.Join(daxibHome(), "keystore")
}

// defaultStateDir is "~/.daxib/state" — the mutable-state class (the tx journal +
// send/journal locks) — used when neither --state-dir nor DAXIB_STATE_DIR is set.
func defaultStateDir() string {
	return filepath.Join(daxibHome(), "state")
}

// defaultConfigDir is "~/.daxib" — the config state-class DIRECTORY holding
// config.toml today and, on the forward path, the sealed policy anchor — used
// when neither --config nor DAXIB_CONFIG is set. --config / DAXIB_CONFIG denote
// the DIRECTORY, not a file (daxie ConfigDir parity). The keystore and state
// subdirs live beneath it, so the whole wallet is one self-contained ~/.daxib tree.
func defaultConfigDir() string {
	return daxibHome()
}
