//go:build !windows

package fsx

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/daxchain-io/daxib/internal/domain"
)

// perms_unix_test.go exercises the §7.9 POSIX permission rule: 0600 passes,
// world/group-write modes are rejected with keystore.perms_insecure (exit 12),
// and a missing file is a hard error.

func writeMode(t *testing.T, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %#o: %v", mode, err)
	}
	return path
}

func TestCheckPermsAccepts0600(t *testing.T) {
	if err := CheckPerms(writeMode(t, 0o600)); err != nil {
		t.Errorf("0600 rejected: %v", err)
	}
}

func TestCheckPermsRejectsInsecureModes(t *testing.T) {
	for _, mode := range []os.FileMode{0o604, 0o620, 0o666, 0o640 | 0o002} {
		path := writeMode(t, mode)
		err := CheckPerms(path)
		if err == nil {
			t.Errorf("mode %#o accepted, want rejection", mode)
			continue
		}
		var de *domain.Error
		if !errors.As(err, &de) {
			t.Errorf("mode %#o: error %v is not a *domain.Error", mode, err)
			continue
		}
		if de.Code != "keystore.perms_insecure" {
			t.Errorf("mode %#o code = %q, want keystore.perms_insecure", mode, de.Code)
		}
		if de.Exit != domain.ExitIntegrity {
			t.Errorf("mode %#o exit = %d, want %d (INTEGRITY)", mode, de.Exit, domain.ExitIntegrity)
		}
	}
}

func TestCheckPermsMissingFileErrors(t *testing.T) {
	if err := CheckPerms(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Errorf("missing file accepted, want a hard error")
	}
}

// TestCheckPermsSkipEnv asserts DAXIB_SKIP_PERM_CHECK=1 disables the check (the
// documented escape hatch for filesystems that cannot represent POSIX modes).
func TestCheckPermsSkipEnv(t *testing.T) {
	path := writeMode(t, 0o666) // would normally be rejected
	orig := lookupEnvFn
	lookupEnvFn = func(k string) (string, bool) {
		if k == skipPermCheckEnv {
			return "1", true
		}
		return "", false
	}
	t.Cleanup(func() { lookupEnvFn = orig })
	if err := CheckPerms(path); err != nil {
		t.Errorf("skip-check did not disable the perm check: %v", err)
	}
}
