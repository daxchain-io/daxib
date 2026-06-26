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

// TestPolicyDefaultAllowlistOff is the KNOWN-4/DLC-2 regression: a bare `policy
// set` (no --allowlist flag) must leave the allowlist OFF (petty-cash default), so
// a send to ANY address within limits is ALLOWED while the denylist + limits stay
// enforced. It also pins the human `policy show` off-message.
func TestPolicyDefaultAllowlistOff(t *testing.T) {
	isolatePolicy(t)

	// Bootstrap WITHOUT --allowlist: the default must be off.
	if _, stderr, code := execCLI(t, "policy", "set",
		"--max-tx", "100000", "--network", "regtest"); code != 0 {
		t.Fatalf("bare policy set exit=%d, want 0:\n%s", code, stderr)
	}

	// policy show --json reports allowlist_enabled:false on the default block.
	stdout, _, code := execCLI(t, "--json", "policy", "show")
	if code != 0 {
		t.Fatalf("policy show exit=%d:\n%s", code, stdout)
	}
	var show struct {
		Default struct {
			AllowlistOn bool `json:"allowlist_enabled"`
		} `json:"default"`
	}
	if err := json.Unmarshal([]byte(stdout), &show); err != nil {
		t.Fatalf("show json: %v\n%s", err, stdout)
	}
	if show.Default.AllowlistOn {
		t.Fatalf("bare `policy set` yielded allowlist_enabled=true; KNOWN-4 wants OFF by default:\n%s", stdout)
	}

	// The human render states the off-message loudly.
	human, _, hcode := execCLI(t, "policy", "show")
	if hcode != 0 {
		t.Fatalf("policy show (human) exit=%d:\n%s", hcode, human)
	}
	if !strings.Contains(human, "allowlist: off (sends allowed to any address within limits)") {
		t.Errorf("policy show should state the allowlist-off message:\n%s", human)
	}

	// A `policy check` to a NON-allowlisted address within limits is ALLOWED (exit
	// 0) — the allowlist gate is off, but the per-tx limit still applies.
	if _, stderr, ccode := execCLI(t, "policy", "check",
		"--to", "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", "--amount", "1000sat", "--fee-rate", "5"); ccode != 0 {
		t.Fatalf("check to non-allowlisted addr within limits exit=%d, want 0 (allowlist off):\n%s", ccode, stderr)
	}

	// The denylist is STILL enforced even with the allowlist off.
	if _, stderr, dcode := execCLI(t, "policy", "deny",
		"bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"); dcode != 0 {
		t.Fatalf("policy deny exit=%d:\n%s", dcode, stderr)
	}
	if _, _, ccode := execCLI(t, "policy", "check",
		"--to", "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", "--amount", "1000sat", "--fee-rate", "5"); ccode != 3 {
		t.Fatalf("denylisted check exit=%d, want 3 (denylist enforced regardless of allowlist)", ccode)
	}
}

// TestPolicyAllowDenyCommands is the TC-6 coverage for `policy allow`/`policy deny`:
// the allow pin shows up in `policy show`, a bad address is a clean usage exit 2.
func TestPolicyAllowDenyCommands(t *testing.T) {
	isolatePolicy(t)
	const addr = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"

	// Bootstrap a policy first (allow needs a sealed anchor).
	if _, stderr, code := execCLI(t, "policy", "set", "--max-tx", "100000", "--network", "regtest"); code != 0 {
		t.Fatalf("policy set exit=%d:\n%s", code, stderr)
	}
	if _, stderr, code := execCLI(t, "policy", "allow", addr, "--label", "exchange"); code != 0 {
		t.Fatalf("policy allow exit=%d:\n%s", code, stderr)
	}
	stdout, _, code := execCLI(t, "policy", "show")
	if code != 0 {
		t.Fatalf("policy show exit=%d:\n%s", code, stdout)
	}
	if !strings.Contains(stdout, addr) {
		t.Errorf("policy show does not list the allowed address:\n%s", stdout)
	}

	if _, stderr, code := execCLI(t, "policy", "deny", addr); code != 0 {
		t.Fatalf("policy deny exit=%d:\n%s", code, stderr)
	}

	// A bad address to `policy allow` is a clean usage error (exit 2).
	if _, _, code := execCLI(t, "policy", "allow", "not-a-valid-address"); code != 2 {
		t.Fatalf("policy allow <bad-addr> exit=%d, want 2", code)
	}
}

// TestPolicyChangeAdminPassphraseCmd is the TC-6 coverage for
// `policy change-admin-passphrase`: after a rotation a follow-up mutation needs the
// NEW passphrase, and `policy verify` exits 0 on the resealed policy.
func TestPolicyChangeAdminPassphraseCmd(t *testing.T) {
	isolatePolicy(t) // sets DAXIB_ADMIN_PASSPHRASE=admin-secret-123

	if _, stderr, code := execCLI(t, "policy", "set", "--max-tx", "100000", "--network", "regtest"); code != 0 {
		t.Fatalf("policy set exit=%d:\n%s", code, stderr)
	}

	// Rotate to a new admin passphrase via the env channel.
	t.Setenv("DAXIB_ADMIN_NEW_PASSPHRASE", "rotated-admin-456")
	if _, stderr, code := execCLI(t, "policy", "change-admin-passphrase"); code != 0 {
		t.Fatalf("change-admin-passphrase exit=%d:\n%s", code, stderr)
	}

	// `policy verify` is passphrase-free and exits 0 on the resealed policy.
	if _, _, code := execCLI(t, "policy", "verify"); code != 0 {
		t.Fatalf("policy verify after rotation exit=%d, want 0", code)
	}

	// The OLD admin passphrase no longer authenticates a mutation (admin_auth, exit 4).
	t.Setenv("DAXIB_ADMIN_NEW_PASSPHRASE", "")
	if _, _, code := execCLI(t, "policy", "set", "--max-tx", "200000", "--network", "regtest"); code != 4 {
		t.Fatalf("mutation under the OLD passphrase exit=%d, want 4 (admin_auth)", code)
	}

	// The NEW admin passphrase DOES authenticate a follow-up mutation.
	t.Setenv("DAXIB_ADMIN_PASSPHRASE", "rotated-admin-456")
	if _, stderr, code := execCLI(t, "policy", "set", "--max-tx", "200000", "--network", "regtest"); code != 0 {
		t.Fatalf("mutation under the NEW passphrase exit=%d, want 0:\n%s", code, stderr)
	}
}
