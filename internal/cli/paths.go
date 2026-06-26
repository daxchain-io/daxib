package cli

import (
	"os"
	"path/filepath"
)

// defaultKeystoreDir returns the OS-appropriate default keystore directory when
// neither --keystore nor DAXIB_KEYSTORE is set. It follows the platform data-dir
// convention (XDG on Linux, ~/Library on macOS, %AppData% on Windows) under a
// "daxib/keystore" subpath. A best-effort fallback to "./.daxib/keystore" covers
// the rare case where the home/data dir cannot be determined.
func defaultKeystoreDir() string {
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "daxib", "keystore")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".daxib", "keystore")
	}
	return filepath.Join(".daxib", "keystore")
}

// defaultStateDir returns the OS-appropriate default mutable-state DIRECTORY (the
// state class holding the tx journal + send/journal locks) when neither
// --state-dir nor DAXIB_STATE_DIR is set. It mirrors the keystore/config layout —
// a "daxib/state" subpath under the platform data dir — with a best-effort
// "./.daxib/state" fallback.
func defaultStateDir() string {
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "daxib", "state")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".daxib", "state")
	}
	return filepath.Join(".daxib", "state")
}

// defaultConfigDir returns the OS-appropriate default config DIRECTORY (the config
// state class) when neither --config nor DAXIB_CONFIG is set. It mirrors daxie's
// ConfigDir: the directory holds config.toml today and, on the forward path, the
// sealed policy anchor — so --config / DAXIB_CONFIG denote the DIRECTORY, not a
// file. It follows the platform config-dir convention (XDG on Linux, ~/Library on
// macOS, %AppData% on Windows) under a "daxib" subpath, with a best-effort
// "./.daxib" fallback.
func defaultConfigDir() string {
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "daxib")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".daxib")
	}
	return ".daxib"
}
