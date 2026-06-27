package service

import (
	"context"
	"testing"

	"github.com/daxchain-io/daxib/internal/domain"
)

// keystore_test.go exercises the service's keystore change-passphrase + info use
// cases: the new-passphrase confirmation gate, a successful rotation that lets the
// NEW passphrase unlock a wallet while the OLD fails, and the read-only info shape.

// TestServiceKeystoreChangePassphrase rotates a two-wallet keystore and proves the
// NEW passphrase unlocks an export while the OLD no longer does.
func TestServiceKeystoreChangePassphrase(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	// Seed a wallet under the old passphrase.
	svc1 := openServiceAt(t, dir, map[string]string{
		"DAXIB_PASSPHRASE":         "old-pass-12345678",
		"DAXIB_PASSPHRASE_CONFIRM": "old-pass-12345678",
	}, msgMnemonic)
	if _, err := svc1.WalletImport(ctx, domain.WalletImportRequest{Name: "vec"}, WalletImportInput{MnemonicStdin: true}); err != nil {
		t.Fatalf("WalletImport: %v", err)
	}
	_ = svc1.Close()

	// Rotate: old via DAXIB_PASSPHRASE, new via DAXIB_NEW_PASSPHRASE[_CONFIRM].
	svc2 := openServiceAt(t, dir, map[string]string{
		"DAXIB_PASSPHRASE":             "old-pass-12345678",
		"DAXIB_NEW_PASSPHRASE":         "new-pass-87654321",
		"DAXIB_NEW_PASSPHRASE_CONFIRM": "new-pass-87654321",
	}, "")
	res, err := svc2.KeystoreChangePassphrase(ctx, domain.KeystoreChangePassphraseRequest{}, KeystoreChangePassphraseInput{})
	if err != nil {
		t.Fatalf("KeystoreChangePassphrase: %v", err)
	}
	if res.RotatedFiles != 2 { // verifier + 1 wallet
		t.Fatalf("rotated %d files, want 2", res.RotatedFiles)
	}
	_ = svc2.Close()

	// NEW passphrase exports the wallet.
	svcNew := openServiceAt(t, dir, map[string]string{"DAXIB_PASSPHRASE": "new-pass-87654321"}, "")
	defer func() { _ = svcNew.Close() }()
	exp, err := svcNew.WalletExport(ctx, domain.WalletExportRequest{Name: "vec"}, WalletExportInput{})
	if err != nil {
		t.Fatalf("WalletExport under NEW passphrase: %v", err)
	}
	if exp.Mnemonic != msgMnemonic {
		t.Fatalf("exported mnemonic mismatch after rotation")
	}

	// OLD passphrase no longer exports.
	svcOld := openServiceAt(t, dir, map[string]string{"DAXIB_PASSPHRASE": "old-pass-12345678"}, "")
	defer func() { _ = svcOld.Close() }()
	if _, oerr := svcOld.WalletExport(ctx, domain.WalletExportRequest{Name: "vec"}, WalletExportInput{}); oerr == nil {
		t.Fatal("OLD passphrase still exports after rotation")
	}
}

// TestServiceKeystoreChangePassphraseConfirmGate proves a non-interactive rotation
// with NO new-passphrase confirmation channel fails CLOSED (keystore.confirm_required,
// exit 2) rather than silently re-encrypting onto an unconfirmed passphrase.
func TestServiceKeystoreChangePassphraseConfirmGate(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	svc1 := openServiceAt(t, dir, map[string]string{
		"DAXIB_PASSPHRASE":         "old-pass-12345678",
		"DAXIB_PASSPHRASE_CONFIRM": "old-pass-12345678",
	}, msgMnemonic)
	if _, err := svc1.WalletImport(ctx, domain.WalletImportRequest{Name: "vec"}, WalletImportInput{MnemonicStdin: true}); err != nil {
		t.Fatalf("WalletImport: %v", err)
	}
	_ = svc1.Close()

	// New passphrase provided, but NO confirmation channel and NO TTY → fail closed.
	svc2 := openServiceAt(t, dir, map[string]string{
		"DAXIB_PASSPHRASE":     "old-pass-12345678",
		"DAXIB_NEW_PASSPHRASE": "new-pass-87654321",
	}, "")
	defer func() { _ = svc2.Close() }()
	_, err := svc2.KeystoreChangePassphrase(ctx, domain.KeystoreChangePassphraseRequest{}, KeystoreChangePassphraseInput{})
	if err == nil {
		t.Fatal("rotation succeeded with no confirmation channel and no TTY")
	}
	if c := code(t, err); c != "keystore.confirm_required" {
		t.Fatalf("confirm-gate code=%s, want keystore.confirm_required", c)
	}
}

// TestServiceKeystoreChangePassphraseConfirmMismatch proves a mismatched
// new-passphrase confirmation is rejected (keystore.confirm_required).
func TestServiceKeystoreChangePassphraseConfirmMismatch(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	svc1 := openServiceAt(t, dir, map[string]string{
		"DAXIB_PASSPHRASE":         "old-pass-12345678",
		"DAXIB_PASSPHRASE_CONFIRM": "old-pass-12345678",
	}, msgMnemonic)
	if _, err := svc1.WalletImport(ctx, domain.WalletImportRequest{Name: "vec"}, WalletImportInput{MnemonicStdin: true}); err != nil {
		t.Fatalf("WalletImport: %v", err)
	}
	_ = svc1.Close()

	svc2 := openServiceAt(t, dir, map[string]string{
		"DAXIB_PASSPHRASE":             "old-pass-12345678",
		"DAXIB_NEW_PASSPHRASE":         "new-pass-87654321",
		"DAXIB_NEW_PASSPHRASE_CONFIRM": "DIFFERENT-87654321",
	}, "")
	defer func() { _ = svc2.Close() }()
	_, err := svc2.KeystoreChangePassphrase(ctx, domain.KeystoreChangePassphraseRequest{}, KeystoreChangePassphraseInput{})
	if err == nil {
		t.Fatal("rotation succeeded with a mismatched confirmation")
	}
	if c := code(t, err); c != "keystore.confirm_required" {
		t.Fatalf("mismatch code=%s, want keystore.confirm_required", c)
	}
}

// TestServiceKeystoreInfo reports the read-only summary.
func TestServiceKeystoreInfo(t *testing.T) {
	svc, done := importMsgWallet(t)
	defer done()
	info, err := svc.KeystoreInfo(context.Background(), domain.KeystoreInfoRequest{})
	if err != nil {
		t.Fatalf("KeystoreInfo: %v", err)
	}
	if !info.Initialized {
		t.Error("Initialized = false, want true")
	}
	if info.Wallets != 1 {
		t.Errorf("wallets = %d, want 1", info.Wallets)
	}
	if info.KDF != "scrypt" {
		t.Errorf("kdf = %q, want scrypt", info.KDF)
	}
}
