package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// policy_test.go is the CLI-surface harness for the M5 policy noun: it drives the
// real Cobra tree end to end (set bootstraps the anchor → show --json → check →
// verify), exercising the admin-passphrase resolver, the exit-code mapping, and the
// --json shapes. The admin KDF runs light (DAXIB_KDF_LIGHT, set by isolateKeystore)
// so the scrypt bootstrap stays fast.

// isolatePolicy points the config + state dirs at temp dirs and wires the admin
// passphrase env channel, on top of the keystore isolation.
func isolatePolicy(t *testing.T) (configDir, stateDir string) {
	t.Helper()
	isolateKeystore(t)
	configDir = t.TempDir()
	stateDir = t.TempDir()
	t.Setenv("DAXIB_CONFIG", configDir)
	t.Setenv("DAXIB_STATE_DIR", stateDir)
	t.Setenv("DAXIB_ADMIN_PASSPHRASE", "admin-secret-123")
	t.Setenv("DAXIB_NETWORK", "regtest")
	return configDir, stateDir
}

func TestPolicySetBootstrapsAndShows(t *testing.T) {
	configDir, stateDir := isolatePolicy(t)

	// First `policy set` bootstraps the anchor + writes a sealed policy.json.
	_, stderr, code := execCLI(t, "policy", "set",
		"--max-tx", "100000", "--max-fee-rate", "50", "--network", "regtest", "--allowlist", "off")
	if code != 0 {
		t.Fatalf("policy set exit=%d, want 0:\n%s", code, stderr)
	}

	// The anchor landed in the CONFIG dir; policy.json in the STATE dir.
	if !fileExists(filepath.Join(configDir, "policy-anchor.json")) {
		t.Errorf("policy-anchor.json not in the config dir")
	}
	if !fileExists(filepath.Join(stateDir, "policy.json")) {
		t.Errorf("policy.json not in the state dir")
	}

	// policy show --json verifies and reports the seal.
	stdout, _, code := execCLI(t, "--json", "policy", "show")
	if code != 0 {
		t.Fatalf("policy show exit=%d:\n%s", code, stdout)
	}
	var show struct {
		Present bool `json:"present"`
		Seal    struct {
			Verified bool `json:"verified"`
		} `json:"seal"`
	}
	if err := json.Unmarshal([]byte(stdout), &show); err != nil {
		t.Fatalf("show json: %v\n%s", err, stdout)
	}
	if !show.Present || !show.Seal.Verified {
		t.Fatalf("policy not present/verified: %s", stdout)
	}

	// policy verify is passphrase-free and exits 0.
	if _, _, vcode := execCLI(t, "policy", "verify"); vcode != 0 {
		t.Fatalf("policy verify exit=%d, want 0", vcode)
	}
}

func TestPolicyCheckOverLimitExits3(t *testing.T) {
	isolatePolicy(t)
	// Set a tiny per-tx cap.
	if _, stderr, code := execCLI(t, "policy", "set",
		"--max-tx", "1000", "--network", "regtest", "--allowlist", "off"); code != 0 {
		t.Fatalf("policy set exit=%d:\n%s", code, stderr)
	}
	// A check well over the per-tx cap is denied with exit 3.
	_, stderr, code := execCLI(t, "policy", "check",
		"--to", "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", "--amount", "1", "--fee-rate", "5")
	if code != 3 {
		t.Fatalf("over-limit check exit=%d, want 3:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "policy.denied") {
		t.Errorf("expected policy.denied code:\n%s", stderr)
	}
}

func TestPolicyWrongAdminPassphraseExits4(t *testing.T) {
	isolatePolicy(t)
	if _, stderr, code := execCLI(t, "policy", "set", "--max-tx", "1000", "--allowlist", "off"); code != 0 {
		t.Fatalf("bootstrap set exit=%d:\n%s", code, stderr)
	}
	// A second set with the WRONG admin passphrase is policy.admin_auth (exit 4).
	t.Setenv("DAXIB_ADMIN_PASSPHRASE", "WRONG")
	_, stderr, code := execCLI(t, "policy", "set", "--max-tx", "5000", "--allowlist", "off")
	if code != 4 {
		t.Fatalf("wrong admin passphrase exit=%d, want 4:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "policy.admin_auth") {
		t.Errorf("expected policy.admin_auth:\n%s", stderr)
	}
}

func TestPolicyShowNoPolicyPermissive(t *testing.T) {
	isolatePolicy(t)
	// No `policy set` yet: show reports no policy (opt-in), exit 0.
	stdout, _, code := execCLI(t, "--json", "policy", "show")
	if code != 0 {
		t.Fatalf("policy show (no policy) exit=%d:\n%s", code, stdout)
	}
	if !strings.Contains(stdout, `"present": false`) {
		t.Errorf("expected present:false with no policy:\n%s", stdout)
	}
}
