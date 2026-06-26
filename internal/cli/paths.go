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
