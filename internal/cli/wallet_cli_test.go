package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/daxchain-io/daxib/internal/domain"
)

const canonicalMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

const (
	canonReceive0 = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu" // m/84'/0'/0'/0/0
	canonReceive1 = "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g" // m/84'/0'/0'/0/1
)

// importVec imports the canonical BIP-84 vector via --mnemonic-file as an
// AGNOSTIC wallet (the default) and fails the test on a non-zero exit. --network
// is the display hint here.
func importVec(t *testing.T, name, network string) {
	t.Helper()
	mf := mnemonicFile(t)
	if _, stderr, code := execCLI(t, "wallet", "import", name, "--mnemonic-file", mf, "--network", network); code != 0 {
		t.Fatalf("import %s exit = %d:\n%s", name, code, stderr)
	}
}

// importVecBound imports the canonical vector as a BOUND wallet locked to network.
func importVecBound(t *testing.T, name, network string) {
	t.Helper()
	mf := mnemonicFile(t)
	if _, stderr, code := execCLI(t, "wallet", "import", name, "--mnemonic-file", mf, "--network", network, "--bind"); code != 0 {
		t.Fatalf("import bound %s exit = %d:\n%s", name, code, stderr)
	}
}

// TestWalletImportCLI imports the canonical BIP-84 vector and asserts the
// receive0 address and JSON shape through the real CLI funnel.
func TestWalletImportCLI(t *testing.T) {
	isolateKeystore(t)
	mf := mnemonicFile(t)
	out, stderr, code := execCLI(t,
		"wallet", "import", "vec", "--mnemonic-file", mf, "--network", "mainnet", "--json")
	if code != 0 {
		t.Fatalf("import exit = %d, want 0:\n%s\n%s", code, out, stderr)
	}
	var res domain.WalletImportResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("import --json invalid: %v (%q)", err, out)
	}
	if res.Receive0Address != canonReceive0 {
		t.Errorf("import receive0 = %q, want %q", res.Receive0Address, canonReceive0)
	}
	if res.Network != domain.NetworkMainnet {
		t.Errorf("network = %q, want mainnet", res.Network)
	}
}

// TestWalletCreateCLIJSON asserts `wallet create --json --yes` carries the
// once-only mnemonic in the structured result with sensitive:true.
func TestWalletCreateCLIJSON(t *testing.T) {
	isolateKeystore(t)
	out, _, code := execCLI(t, "wallet", "create", "treasury", "--network", "regtest", "--json", "--yes")
	if code != 0 {
		t.Fatalf("create exit = %d, want 0:\n%s", code, out)
	}
	var res domain.WalletCreateResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("create --json invalid: %v (%q)", err, out)
	}
	if !res.Sensitive || res.Mnemonic == "" {
		t.Errorf("create --json must carry the sensitive mnemonic: %+v", res)
	}
	if n := len(strings.Fields(res.Mnemonic)); n != 12 {
		t.Errorf("mnemonic word count = %d, want 12", n)
	}
	if res.Network != domain.NetworkRegtest {
		t.Errorf("network = %q, want regtest", res.Network)
	}
}

// TestWalletCreateCLIJSONNoYes is the regression guard for the json-tty fix:
// `wallet create --json` (no --yes) must emit the mnemonic through the JSON
// result (sensitive:true), not silently drop it onto stderr.
func TestWalletCreateCLIJSONNoYes(t *testing.T) {
	isolateKeystore(t)
	out, stderr, code := execCLI(t, "wallet", "create", "ops", "--network", "regtest", "--json")
	if code != 0 {
		t.Fatalf("create --json (no --yes) exit = %d, want 0:\n%s\n%s", code, out, stderr)
	}
	var res domain.WalletCreateResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("create --json invalid: %v (%q)", err, out)
	}
	if !res.Sensitive || res.Mnemonic == "" {
		t.Errorf("--json create must carry the mnemonic in the structured result: %+v", res)
	}
	// The seed must NOT have been dumped as free-form prose on stderr.
	if strings.Contains(stderr, "RECORD THIS MNEMONIC") {
		t.Errorf("--json create leaked the human ceremony to stderr: %q", stderr)
	}
}

// TestWalletCreateHumanYes asserts the human (non-json) --yes path keeps the
// mnemonic in stdout once with the record-it notice.
func TestWalletCreateHumanYes(t *testing.T) {
	isolateKeystore(t)
	out, _, code := execCLI(t, "wallet", "create", "treasury", "--network", "regtest", "--yes")
	if code != 0 {
		t.Fatalf("create exit = %d, want 0", code)
	}
	if !strings.Contains(out, "RECORD THIS MNEMONIC") {
		t.Errorf("human create missing the record-it notice:\n%s", out)
	}
}

// TestWalletCreateHumanNoYesNoTTYExit2 asserts the no-yes/no-json/no-TTY preflight
// refusal (usage.confirmation_required, exit 2). The test process stdin is not a
// terminal, so this is the no-channel branch.
func TestWalletCreateHumanNoYesNoTTYExit2(t *testing.T) {
	isolateKeystore(t)
	_, _, code := execCLI(t, "wallet", "create", "noyes", "--network", "regtest")
	if code != int(domain.ExitUsage) {
		t.Fatalf("no-yes/no-json/no-TTY create exit = %d, want 2 (USAGE)", code)
	}
}

// TestWalletListShowCLI asserts list/show through the CLI after an import.
func TestWalletListShowCLI(t *testing.T) {
	isolateKeystore(t)
	importVec(t, "vec", "mainnet")

	out, _, code := execCLI(t, "wallet", "list", "--json")
	if code != 0 {
		t.Fatalf("list exit %d:\n%s", code, out)
	}
	var lr domain.WalletListResult
	if err := json.Unmarshal([]byte(out), &lr); err != nil {
		t.Fatalf("list json: %v (%q)", err, out)
	}
	if len(lr.Wallets) != 1 || lr.Wallets[0].Name != "vec" {
		t.Fatalf("list = %+v, want one wallet 'vec'", lr.Wallets)
	}
	if lr.Default != "vec" {
		t.Errorf("list default = %q, want vec", lr.Default)
	}

	out, _, code = execCLI(t, "wallet", "show", "vec", "--json")
	if code != 0 {
		t.Fatalf("show exit %d:\n%s", code, out)
	}
	var sr domain.WalletShowResult
	if err := json.Unmarshal([]byte(out), &sr); err != nil {
		t.Fatalf("show json: %v", err)
	}
	if sr.PathPrefix != "m/84'/0'/0'" {
		t.Errorf("path prefix = %q, want m/84'/0'/0'", sr.PathPrefix)
	}
}

// TestWalletExportCLI round-trips the imported mnemonic via export.
func TestWalletExportCLI(t *testing.T) {
	isolateKeystore(t)
	importVec(t, "vec", "mainnet")
	out, _, code := execCLI(t, "wallet", "export", "vec", "--json")
	if code != 0 {
		t.Fatalf("export exit %d:\n%s", code, out)
	}
	var res domain.WalletExportResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("export json: %v (%q)", err, out)
	}
	if res.Mnemonic != canonicalMnemonic || !res.Sensitive {
		t.Errorf("export = %+v, want the canonical mnemonic with sensitive:true", res)
	}
}

// TestWalletImportBadMnemonicExit2 asserts an invalid mnemonic fails
// mnemonic.invalid (exit 2).
func TestWalletImportBadMnemonicExit2(t *testing.T) {
	isolateKeystore(t)
	mf := writeTempFile(t, "bad", "not a valid mnemonic at all here please")
	_, stderr, code := execCLI(t,
		"wallet", "import", "bad", "--mnemonic-file", mf, "--network", "mainnet", "--json")
	if code != int(domain.ExitUsage) {
		t.Fatalf("bad-mnemonic exit = %d, want 2 (USAGE)", code)
	}
	if !strings.Contains(stderr, "mnemonic.invalid") {
		t.Errorf("error envelope missing mnemonic.invalid: %q", stderr)
	}
}

// TestWalletExportWrongPassphraseExit4 asserts a wrong passphrase yields
// keystore.bad_passphrase (exit 4) through the CLI.
func TestWalletExportWrongPassphraseExit4(t *testing.T) {
	isolateKeystore(t)
	importVec(t, "vec", "mainnet")
	// Override the passphrase env with a wrong value for the export.
	t.Setenv("DAXIB_PASSPHRASE", "wrong-pass")
	_, stderr, code := execCLI(t, "wallet", "export", "vec", "--json")
	if code != int(domain.ExitAuth) {
		t.Fatalf("wrong-pass export exit = %d, want 4 (AUTH)", code)
	}
	if !strings.Contains(stderr, "keystore.bad_passphrase") {
		t.Errorf("error envelope missing keystore.bad_passphrase: %q", stderr)
	}
}

// TestWalletShowUnknownExit10 asserts an unknown wallet name yields exit 10.
func TestWalletShowUnknownExit10(t *testing.T) {
	isolateKeystore(t)
	if _, _, code := execCLI(t, "wallet", "create", "w", "--network", "regtest", "--yes"); code != 0 {
		t.Fatalf("create exit %d", code)
	}
	_, _, code := execCLI(t, "wallet", "show", "nope", "--json")
	if code != int(domain.ExitNotFound) {
		t.Fatalf("show unknown exit = %d, want 10 (NOT_FOUND)", code)
	}
}

// TestWalletImportMissingMnemonicExit2 is the CLI-level regression guard for the
// label-aware resolver fix: import with no --mnemonic-* source and no TTY must
// fail mnemonic.required (exit 2), with an error that does not call the missing
// mnemonic a "passphrase".
func TestWalletImportMissingMnemonicExit2(t *testing.T) {
	isolateKeystore(t)
	_, stderr, code := execCLI(t, "wallet", "import", "nomnem", "--network", "mainnet", "--json")
	if code != int(domain.ExitUsage) {
		t.Fatalf("missing-mnemonic exit = %d, want 2 (USAGE), not the auth class", code)
	}
	if !strings.Contains(stderr, "mnemonic.required") {
		t.Errorf("error envelope missing mnemonic.required: %q", stderr)
	}
	if strings.Contains(strings.ToLower(stderr), "passphrase") {
		t.Errorf("missing-mnemonic error wrongly mentions 'passphrase': %q", stderr)
	}
}
