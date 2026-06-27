package cli

import (
	"encoding/json"
	"testing"

	"github.com/daxchain-io/daxib/internal/domain"
)

// keystore_cli_test.go drives `keystore info` and `keystore change-passphrase`
// through the Cobra funnel.

// TestKeystoreInfoCLI imports a wallet and reads the keystore summary.
func TestKeystoreInfoCLI(t *testing.T) {
	isolateKeystore(t)
	importVec(t, "vec", "mainnet")

	out, stderr, code := execCLI(t, "keystore", "info", "--json")
	if code != 0 {
		t.Fatalf("keystore info exit = %d, want 0:\n%s\n%s", code, out, stderr)
	}
	var res domain.KeystoreInfoResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("info --json invalid: %v (%q)", err, out)
	}
	if !res.Initialized {
		t.Error("Initialized = false, want true")
	}
	if res.Wallets != 1 {
		t.Errorf("wallets = %d, want 1", res.Wallets)
	}
	if res.KDF != "scrypt" {
		t.Errorf("kdf = %q, want scrypt", res.KDF)
	}
}

// TestKeystoreChangePassphraseCLI rotates the keystore through the CLI, then proves
// the NEW passphrase exports the wallet (and the OLD env no longer does).
func TestKeystoreChangePassphraseCLI(t *testing.T) {
	isolateKeystore(t) // sets DAXIB_PASSPHRASE[_CONFIRM] = unit-test-passphrase-123
	importVec(t, "vec", "mainnet")

	// Provide the NEW passphrase + its confirmation via env.
	t.Setenv("DAXIB_NEW_PASSPHRASE", "rotated-passphrase-456")
	t.Setenv("DAXIB_NEW_PASSPHRASE_CONFIRM", "rotated-passphrase-456")

	out, stderr, code := execCLI(t, "keystore", "change-passphrase", "--json")
	if code != 0 {
		t.Fatalf("change-passphrase exit = %d, want 0:\n%s\n%s", code, out, stderr)
	}
	var res domain.KeystoreChangePassphraseResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("change-passphrase --json invalid: %v (%q)", err, out)
	}
	if res.RotatedFiles != 2 { // verifier + 1 wallet
		t.Fatalf("rotated %d files, want 2", res.RotatedFiles)
	}

	// NEW passphrase exports the wallet (override the unlock env to the new value).
	t.Setenv("DAXIB_PASSPHRASE", "rotated-passphrase-456")
	eout, estderr, ecode := execCLI(t, "wallet", "export", "vec", "--json", "--yes")
	if ecode != 0 {
		t.Fatalf("export under NEW passphrase exit = %d, want 0:\n%s\n%s", ecode, eout, estderr)
	}
	var exp domain.WalletExportResult
	if err := json.Unmarshal([]byte(eout), &exp); err != nil {
		t.Fatalf("export --json invalid: %v", err)
	}
	if exp.Mnemonic != canonicalMnemonic {
		t.Fatal("exported mnemonic mismatch after rotation")
	}

	// OLD passphrase no longer unlocks (exit 4, keystore.bad_passphrase).
	t.Setenv("DAXIB_PASSPHRASE", "unit-test-passphrase-123")
	_, _, oldCode := execCLI(t, "wallet", "export", "vec", "--json", "--yes")
	if oldCode != int(domain.ExitAuth) {
		t.Fatalf("export under OLD passphrase exit = %d, want %d (auth)", oldCode, domain.ExitAuth)
	}
}

// TestKeystoreChangePassphraseConfirmGateCLI proves a rotation with no new-passphrase
// confirmation channel and no TTY fails closed (exit 2, keystore.confirm_required).
func TestKeystoreChangePassphraseConfirmGateCLI(t *testing.T) {
	isolateKeystore(t)
	importVec(t, "vec", "mainnet")
	t.Setenv("DAXIB_NEW_PASSPHRASE", "rotated-passphrase-456")
	// No DAXIB_NEW_PASSPHRASE_CONFIRM and no TTY → fail closed.

	_, stderr, code := execCLI(t, "keystore", "change-passphrase", "--json")
	if code != int(domain.ExitUsage) {
		t.Fatalf("confirm-gate exit = %d, want %d (usage)\n%s", code, domain.ExitUsage, stderr)
	}
}
