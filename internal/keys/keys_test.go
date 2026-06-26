package keys

import (
	"context"
	"errors"
	"testing"

	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/secret"
)

// openLight opens a keystore in a temp dir at the test scrypt cost (light) so the
// crypto stays fast.
func openLight(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), Options{Dir: t.TempDir(), Light: true})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func pass(s string) *secret.Bytes { return secret.NewString(s) }

// codeOf extracts the dotted domain code from an error.
func codeOf(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	var de *domain.Error
	if !errors.As(err, &de) {
		t.Fatalf("error %v is not a *domain.Error", err)
	}
	return de.Code
}

// TestCreateListShowRoundtrip is the create→list→show happy path: a wallet is
// created, appears in the list, derives the canonical first receive address, and
// shows consistent watermarks.
func TestCreateListShowRoundtrip(t *testing.T) {
	s := openLight(t)
	ctx := context.Background()
	p, c := pass("hunter2-correct"), pass("hunter2-correct")

	res, err := s.CreateWallet(ctx, "vec", 12, domain.NetworkMainnet, p, c)
	if err != nil {
		t.Fatalf("CreateWallet: %v", err)
	}
	defer res.Mnemonic.Zero()
	if res.WalletID == "" {
		t.Fatal("CreateWallet returned an empty wallet id")
	}
	if res.Mnemonic == nil || res.Mnemonic.Len() == 0 {
		t.Fatal("CreateWallet did not return the once-only mnemonic")
	}
	if res.AccountXpub == "" {
		t.Fatal("CreateWallet did not return an account xpub")
	}

	wallets, err := s.ListWallets(ctx)
	if err != nil {
		t.Fatalf("ListWallets: %v", err)
	}
	if len(wallets) != 1 || wallets[0].Name != "vec" {
		t.Fatalf("ListWallets = %+v, want one wallet named vec", wallets)
	}
	if !wallets[0].Default {
		t.Fatal("first wallet should be the default wallet")
	}

	w, err := s.ShowWallet(ctx, "vec")
	if err != nil {
		t.Fatalf("ShowWallet: %v", err)
	}
	if w.NextReceive != 1 || w.NextChange != 0 {
		t.Fatalf("ShowWallet watermarks = (recv %d, change %d), want (1, 0)", w.NextReceive, w.NextChange)
	}
	if w.Addresses != 1 {
		t.Fatalf("ShowWallet addresses = %d, want 1 (the auto-derived 0/0)", w.Addresses)
	}

	// The auto-derived receive 0/0 must be present in the address list.
	_, addrs, err := s.ListAddresses(ctx, "vec")
	if err != nil {
		t.Fatalf("ListAddresses: %v", err)
	}
	if len(addrs) != 1 || addrs[0].Address == "" {
		t.Fatalf("ListAddresses = %+v, want the single 0/0 address", addrs)
	}
}

// TestDeriveNextAdvancesWatermark confirms DeriveNext allocates monotonically and
// records the address (no passphrase needed).
func TestDeriveNextAdvancesWatermark(t *testing.T) {
	s := openLight(t)
	ctx := context.Background()
	p, c := pass("pw-correct-horse"), pass("pw-correct-horse")
	if _, err := s.CreateWallet(ctx, "vec", 12, domain.NetworkMainnet, p, c); err != nil {
		t.Fatalf("CreateWallet: %v", err)
	}

	d1, err := s.DeriveNext(ctx, "vec", domain.BranchReceive)
	if err != nil {
		t.Fatalf("DeriveNext receive: %v", err)
	}
	if d1.Index != 1 { // 0 was auto-derived on create
		t.Fatalf("first DeriveNext index = %d, want 1", d1.Index)
	}
	d2, err := s.DeriveNext(ctx, "vec", domain.BranchChange)
	if err != nil {
		t.Fatalf("DeriveNext change: %v", err)
	}
	if d2.Index != 0 || d2.Branch != domain.BranchChange {
		t.Fatalf("first change DeriveNext = (idx %d, branch %d), want (0, change)", d2.Index, d2.Branch)
	}

	w, err := s.ShowWallet(ctx, "vec")
	if err != nil {
		t.Fatalf("ShowWallet: %v", err)
	}
	if w.NextReceive != 2 || w.NextChange != 1 {
		t.Fatalf("watermarks = (recv %d, change %d), want (2, 1)", w.NextReceive, w.NextChange)
	}
}

// TestImportCanonicalVector imports the canonical mnemonic and asserts the
// recorded first receive address matches the BIP-84 vector.
func TestImportCanonicalVector(t *testing.T) {
	s := openLight(t)
	ctx := context.Background()
	p, c := pass("pw"), pass("pw")
	mn := secret.NewString(canonicalMnemonic)
	res, err := s.ImportWallet(ctx, "vec", domain.NetworkMainnet, mn, nil, p, c)
	if err != nil {
		t.Fatalf("ImportWallet: %v", err)
	}
	if res.Receive0Address != "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu" {
		t.Fatalf("imported first receive = %q, want the canonical 0/0 vector", res.Receive0Address)
	}
}

// TestWrongPassphrase asserts that verifying / adding material with a wrong
// passphrase fails with keystore.bad_passphrase (exit 4 via the registry).
func TestWrongPassphrase(t *testing.T) {
	s := openLight(t)
	ctx := context.Background()
	// First init with the correct passphrase.
	if _, err := s.CreateWallet(ctx, "vec", 12, domain.NetworkMainnet, pass("right"), pass("right")); err != nil {
		t.Fatalf("CreateWallet: %v", err)
	}
	// A second wallet under a WRONG passphrase must be rejected at the verifier.
	_, err := s.CreateWallet(ctx, "other", 12, domain.NetworkMainnet, pass("wrong"), pass("wrong"))
	if got := codeOf(t, err); got != CodeKeystoreBadPassphrase {
		t.Fatalf("wrong-passphrase create code = %q, want %q", got, CodeKeystoreBadPassphrase)
	}
	// Export under a wrong passphrase is likewise bad_passphrase.
	_, _, _, err = s.ExportWallet(ctx, "vec", pass("nope"))
	if got := codeOf(t, err); got != CodeKeystoreBadPassphrase {
		t.Fatalf("wrong-passphrase export code = %q, want %q", got, CodeKeystoreBadPassphrase)
	}
}

// TestExportRoundtrip confirms a created wallet's mnemonic round-trips through
// export (operator-only, needs the passphrase).
func TestExportRoundtrip(t *testing.T) {
	s := openLight(t)
	ctx := context.Background()
	res, err := s.ImportWallet(ctx, "vec", domain.NetworkMainnet, secret.NewString(canonicalMnemonic), nil, pass("pw"), pass("pw"))
	if err != nil {
		t.Fatalf("ImportWallet: %v", err)
	}
	_ = res
	_, mn, bip, err := s.ExportWallet(ctx, "vec", pass("pw"))
	if err != nil {
		t.Fatalf("ExportWallet: %v", err)
	}
	defer mn.Zero()
	defer bip.Zero()
	if string(mn.Reveal()) != canonicalMnemonic {
		t.Fatalf("exported mnemonic = %q, want the imported sentence", string(mn.Reveal()))
	}
	if bip.Len() != 0 {
		t.Fatalf("exported bip39 passphrase should be empty, got len %d", bip.Len())
	}
}

// TestBadChecksumImport asserts a mnemonic with a bad BIP-39 checksum is rejected
// hard with mnemonic.invalid (exit 2).
func TestBadChecksumImport(t *testing.T) {
	s := openLight(t)
	ctx := context.Background()
	// "abandon" x12 has a bad checksum (the canonical valid form ends in "about").
	bad := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
	_, err := s.ImportWallet(ctx, "vec", domain.NetworkMainnet, secret.NewString(bad), nil, pass("pw"), pass("pw"))
	if got := codeOf(t, err); got != CodeMnemonicInvalid {
		t.Fatalf("bad-checksum import code = %q, want %q", got, CodeMnemonicInvalid)
	}
}

// TestConfirmRequiredOnFirstInit asserts that a first init with no confirmation
// fails closed with keystore.confirm_required (never a hang), and that a
// mismatched confirmation is likewise rejected.
func TestConfirmRequiredOnFirstInit(t *testing.T) {
	s := openLight(t)
	ctx := context.Background()
	// No confirmation at all.
	_, err := s.CreateWallet(ctx, "vec", 12, domain.NetworkMainnet, pass("pw"), nil)
	if got := codeOf(t, err); got != CodeKeystoreConfirmRequired {
		t.Fatalf("missing-confirm code = %q, want %q", got, CodeKeystoreConfirmRequired)
	}
	// Mismatched confirmation.
	_, err = s.CreateWallet(ctx, "vec", 12, domain.NetworkMainnet, pass("pw"), pass("different"))
	if got := codeOf(t, err); got != CodeKeystoreConfirmRequired {
		t.Fatalf("mismatched-confirm code = %q, want %q", got, CodeKeystoreConfirmRequired)
	}
}

// TestDuplicateWalletName asserts a second wallet with the same name fails with
// wallet.exists (exit 2).
func TestDuplicateWalletName(t *testing.T) {
	s := openLight(t)
	ctx := context.Background()
	if _, err := s.CreateWallet(ctx, "vec", 12, domain.NetworkMainnet, pass("pw"), pass("pw")); err != nil {
		t.Fatalf("CreateWallet: %v", err)
	}
	_, err := s.CreateWallet(ctx, "vec", 12, domain.NetworkMainnet, pass("pw"), nil)
	if got := codeOf(t, err); got != CodeWalletExists {
		t.Fatalf("duplicate-name code = %q, want %q", got, CodeWalletExists)
	}
}

// TestWordsValidation asserts only 12/24 are accepted.
func TestWordsValidation(t *testing.T) {
	s := openLight(t)
	ctx := context.Background()
	_, err := s.CreateWallet(ctx, "vec", 15, domain.NetworkMainnet, pass("pw"), pass("pw"))
	if got := codeOf(t, err); got != CodeUsageWords {
		t.Fatalf("bad --words code = %q, want %q", got, CodeUsageWords)
	}
}

// TestProductionKeystoreNotDowngradable asserts a keystore created at the
// production cost cannot be reopened in light mode (the manifest's light flag is
// authoritative, preventing a silent scrypt downgrade).
func TestProductionKeystoreNotDowngradable(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	// Create at production cost (Light:false). Use a tiny op so the test stays
	// reasonable — one verifier seal at N=2^18 is ~a second, acceptable for one
	// guard test.
	prod, err := Open(ctx, Options{Dir: dir, Light: false})
	if err != nil {
		t.Fatalf("Open prod: %v", err)
	}
	if _, err := prod.CreateWallet(ctx, "vec", 12, domain.NetworkMainnet, pass("pw"), pass("pw")); err != nil {
		t.Fatalf("CreateWallet prod: %v", err)
	}
	_ = prod.Close()

	// Reopen requesting light; the store must adopt the manifest's (false) flag.
	reopened, err := Open(ctx, Options{Dir: dir, Light: true})
	if err != nil {
		t.Fatalf("Open reopened: %v", err)
	}
	if reopened.light {
		t.Fatal("a production keystore was downgraded to light on reopen (scrypt downgrade)")
	}
	_ = reopened.Close()
}
