package service

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/daxchain-io/daxib/internal/domain"
)

// newTestService opens a service over a temp keystore at the light scrypt cost,
// with the given env map and stdin payload. secrets are supplied via env so no
// real TTY is needed.
func newTestService(t *testing.T, env map[string]string, stdin string) (*Service, func()) {
	t.Helper()
	dir := t.TempDir()
	env2 := map[string]string{}
	for k, v := range env {
		env2[k] = v
	}
	env2["DAXIB_KEYSTORE"] = dir
	env2["DAXIB_KDF_LIGHT"] = "1"

	svc, err := Open(context.Background(), Options{
		Keystore: dir,
		Network:  "mainnet",
		KDFLight: true,
		Secret: SecretIO{
			Stdin:     bytes.NewBufferString(stdin),
			LookupEnv: func(k string) (string, bool) { v, ok := env2[k]; return v, ok },
			IsTTY:     func() bool { return false },
			Prompt:    func(string) ([]byte, error) { return nil, errors.New("no TTY in test") },
		},
	})
	if err != nil {
		t.Fatalf("service.Open: %v", err)
	}
	return svc, func() { _ = svc.Close() }
}

func code(t *testing.T, err error) string {
	t.Helper()
	var de *domain.Error
	if !errors.As(err, &de) {
		t.Fatalf("error %v is not a *domain.Error", err)
	}
	return de.Code
}

// TestServiceWalletImportListNew exercises the import→address-list→address-new
// flow through the service with the canonical mnemonic, asserting the BIP-84
// vectors appear at the service boundary.
func TestServiceWalletImportListNew(t *testing.T) {
	const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	svc, done := newTestService(t, map[string]string{
		"DAXIB_PASSPHRASE":         "test-pass-12345678",
		"DAXIB_PASSPHRASE_CONFIRM": "test-pass-12345678",
	}, mnemonic)
	defer done()
	ctx := context.Background()

	imp, err := svc.WalletImport(ctx, domain.WalletImportRequest{Name: "vec"}, WalletImportInput{MnemonicStdin: true})
	if err != nil {
		t.Fatalf("WalletImport: %v", err)
	}
	if imp.Receive0Address != "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu" {
		t.Fatalf("import receive0 = %q, want canonical 0/0", imp.Receive0Address)
	}

	list, err := svc.AddressList(ctx, domain.AddressListRequest{Wallet: "vec"})
	if err != nil {
		t.Fatalf("AddressList: %v", err)
	}
	if len(list.Addresses) != 1 || list.Addresses[0].Address != "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu" {
		t.Fatalf("AddressList = %+v, want the single canonical 0/0", list.Addresses)
	}

	next, err := svc.AddressNew(ctx, domain.AddressNewRequest{Wallet: "vec"})
	if err != nil {
		t.Fatalf("AddressNew: %v", err)
	}
	if next.Address != "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g" {
		t.Fatalf("AddressNew = %q, want canonical 0/1", next.Address)
	}
}

// TestServiceWrongPassphrase asserts a second wallet under a wrong passphrase
// fails with keystore.bad_passphrase at the service boundary.
func TestServiceWrongPassphrase(t *testing.T) {
	svc, done := newTestService(t, map[string]string{
		"DAXIB_PASSPHRASE":         "right-pass-12345678",
		"DAXIB_PASSPHRASE_CONFIRM": "right-pass-12345678",
	}, "")
	defer done()
	ctx := context.Background()

	if _, err := svc.WalletCreate(ctx, domain.WalletCreateRequest{Name: "vec", Words: 12, Yes: true}, WalletCreateInput{}); err != nil {
		t.Fatalf("WalletCreate: %v", err)
	}

	// Reopen with a wrong passphrase env and try to create another wallet.
	dir := svc.opts.Keystore
	_ = svc.Close()
	wrong, err := Open(ctx, Options{
		Keystore: dir, Network: "mainnet", KDFLight: true,
		Secret: SecretIO{
			Stdin:     bytes.NewBufferString(""),
			LookupEnv: envLookup{"DAXIB_PASSPHRASE": "wrong-pass", "DAXIB_KEYSTORE": dir, "DAXIB_KDF_LIGHT": "1"}.lookup,
			IsTTY:     func() bool { return false },
		},
	})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = wrong.Close() }()
	_, err = wrong.WalletCreate(ctx, domain.WalletCreateRequest{Name: "other", Words: 12, Yes: true}, WalletCreateInput{})
	if got := code(t, err); got != "keystore.bad_passphrase" {
		t.Fatalf("wrong-passphrase code = %q, want keystore.bad_passphrase", got)
	}
}

// TestServiceConfirmRequired asserts first init with no confirm + no TTY fails
// closed with keystore.confirm_required (never a hang).
func TestServiceConfirmRequired(t *testing.T) {
	svc, done := newTestService(t, map[string]string{
		"DAXIB_PASSPHRASE": "lonely-pass-1234", // no CONFIRM set
	}, "")
	defer done()
	_, err := svc.WalletCreate(context.Background(), domain.WalletCreateRequest{Name: "vec", Words: 12, Yes: true}, WalletCreateInput{})
	if got := code(t, err); got != "keystore.confirm_required" {
		t.Fatalf("no-confirm code = %q, want keystore.confirm_required", got)
	}
}

// TestServiceNetworkMismatch asserts address ops on a wallet bound to a different
// network than the active one are refused with usage.network_mismatch.
func TestServiceNetworkMismatch(t *testing.T) {
	const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	svc, done := newTestService(t, map[string]string{
		"DAXIB_PASSPHRASE":         "test-pass-12345678",
		"DAXIB_PASSPHRASE_CONFIRM": "test-pass-12345678",
	}, mnemonic)
	defer done()
	ctx := context.Background()

	// Import a TESTNET wallet while the service's active network is mainnet.
	if _, err := svc.WalletImport(ctx, domain.WalletImportRequest{Name: "tnet", Network: domain.NetworkTestnet}, WalletImportInput{MnemonicStdin: true}); err != nil {
		t.Fatalf("WalletImport testnet: %v", err)
	}
	// address new on the mainnet-active service must refuse the testnet wallet.
	_, err := svc.AddressNew(ctx, domain.AddressNewRequest{Wallet: "tnet"})
	if got := code(t, err); got != "usage.network_mismatch" {
		t.Fatalf("network-mismatch code = %q, want usage.network_mismatch", got)
	}
}

// TestServiceWalletListShowExport exercises the thin service wrappers
// (WalletList/WalletShow/WalletExport) at the service boundary: list aggregates
// the default flag, show reports the watermarks, and export round-trips the
// imported mnemonic with Sensitive=true.
func TestServiceWalletListShowExport(t *testing.T) {
	const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	svc, done := newTestService(t, map[string]string{
		"DAXIB_PASSPHRASE":         "test-pass-12345678",
		"DAXIB_PASSPHRASE_CONFIRM": "test-pass-12345678",
	}, mnemonic)
	defer done()
	ctx := context.Background()

	if _, err := svc.WalletImport(ctx, domain.WalletImportRequest{Name: "vec"}, WalletImportInput{MnemonicStdin: true}); err != nil {
		t.Fatalf("WalletImport: %v", err)
	}
	// Allocate one more receive address so the watermark advances past 0.
	if _, err := svc.AddressNew(ctx, domain.AddressNewRequest{Wallet: "vec"}); err != nil {
		t.Fatalf("AddressNew: %v", err)
	}

	list, err := svc.WalletList(ctx, domain.WalletListRequest{})
	if err != nil {
		t.Fatalf("WalletList: %v", err)
	}
	if len(list.Wallets) != 1 || list.Wallets[0].Name != "vec" {
		t.Fatalf("WalletList = %+v, want one wallet 'vec'", list.Wallets)
	}
	if list.Default != "vec" || !list.Wallets[0].Default {
		t.Errorf("WalletList default = %q (entry.Default=%v), want vec/true", list.Default, list.Wallets[0].Default)
	}

	show, err := svc.WalletShow(ctx, domain.WalletShowRequest{Name: "vec"})
	if err != nil {
		t.Fatalf("WalletShow: %v", err)
	}
	if show.NextReceive != 2 || show.NextChange != 0 {
		t.Errorf("WalletShow next_receive/next_change = %d/%d, want 2/0", show.NextReceive, show.NextChange)
	}
	if show.Addresses != 2 {
		t.Errorf("WalletShow addresses = %d, want 2", show.Addresses)
	}

	exp, err := svc.WalletExport(ctx, domain.WalletExportRequest{Name: "vec"}, WalletExportInput{})
	if err != nil {
		t.Fatalf("WalletExport: %v", err)
	}
	if !exp.Sensitive {
		t.Errorf("WalletExport Sensitive = false, want true")
	}
	if exp.Mnemonic != mnemonic {
		t.Errorf("WalletExport mnemonic = %q, want the imported canonical mnemonic", exp.Mnemonic)
	}
}

// TestServiceWalletExportWrongPassphrase asserts export with a wrong passphrase
// fails with keystore.bad_passphrase through the service boundary.
func TestServiceWalletExportWrongPassphrase(t *testing.T) {
	const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	svc, done := newTestService(t, map[string]string{
		"DAXIB_PASSPHRASE":         "right-pass-12345678",
		"DAXIB_PASSPHRASE_CONFIRM": "right-pass-12345678",
	}, mnemonic)
	defer done()
	ctx := context.Background()

	if _, err := svc.WalletImport(ctx, domain.WalletImportRequest{Name: "vec"}, WalletImportInput{MnemonicStdin: true}); err != nil {
		t.Fatalf("WalletImport: %v", err)
	}

	dir := svc.opts.Keystore
	_ = svc.Close()
	wrong, err := Open(ctx, Options{
		Keystore: dir, Network: "mainnet", KDFLight: true,
		Secret: SecretIO{
			Stdin:     bytes.NewBufferString(""),
			LookupEnv: envLookup{"DAXIB_PASSPHRASE": "wrong-pass", "DAXIB_KEYSTORE": dir, "DAXIB_KDF_LIGHT": "1"}.lookup,
			IsTTY:     func() bool { return false },
		},
	})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = wrong.Close() }()
	_, err = wrong.WalletExport(ctx, domain.WalletExportRequest{Name: "vec"}, WalletExportInput{})
	if got := code(t, err); got != "keystore.bad_passphrase" {
		t.Fatalf("export wrong-passphrase code = %q, want keystore.bad_passphrase", got)
	}
}

// TestServiceDefaultWalletResolution pins the default-wallet precedence: with no
// explicit --wallet and no active override, AddressNew resolves to the default
// wallet; on a fresh keystore it fails wallet.not_found (exit 10).
func TestServiceDefaultWalletResolution(t *testing.T) {
	const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	svc, done := newTestService(t, map[string]string{
		"DAXIB_PASSPHRASE":         "test-pass-12345678",
		"DAXIB_PASSPHRASE_CONFIRM": "test-pass-12345678",
	}, mnemonic)
	defer done()
	ctx := context.Background()

	if _, err := svc.WalletImport(ctx, domain.WalletImportRequest{Name: "vec"}, WalletImportInput{MnemonicStdin: true}); err != nil {
		t.Fatalf("WalletImport: %v", err)
	}
	// No Wallet on the request → resolves to the default ('vec').
	next, err := svc.AddressNew(ctx, domain.AddressNewRequest{})
	if err != nil {
		t.Fatalf("AddressNew default: %v", err)
	}
	if next.Wallet != "vec" {
		t.Errorf("default-resolved wallet = %q, want vec", next.Wallet)
	}
	if next.Address != "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g" {
		t.Errorf("default 0/1 = %q, want canonical", next.Address)
	}
}

// TestServiceNoDefaultWallet asserts a fresh keystore with no wallet and no
// --wallet fails wallet.not_found.
func TestServiceNoDefaultWallet(t *testing.T) {
	svc, done := newTestService(t, map[string]string{}, "")
	defer done()
	_, err := svc.AddressNew(context.Background(), domain.AddressNewRequest{})
	if got := code(t, err); got != "wallet.not_found" {
		t.Fatalf("no-default code = %q, want wallet.not_found", got)
	}
}

// TestServiceMnemonicRequiredLabelAware asserts the in-scope missing-mnemonic
// live path (import with no --mnemonic-stdin, no TTY) fails with the label-aware
// usage code (mnemonic.required, exit 2), not the keystore auth class — the
// regression guard for the resolver fix at the service boundary.
func TestServiceMnemonicRequiredLabelAware(t *testing.T) {
	svc, done := newTestService(t, map[string]string{
		"DAXIB_PASSPHRASE":         "test-pass-12345678",
		"DAXIB_PASSPHRASE_CONFIRM": "test-pass-12345678",
	}, "") // empty stdin, MnemonicStdin not set
	defer done()
	_, err := svc.WalletImport(context.Background(), domain.WalletImportRequest{Name: "nomnem"}, WalletImportInput{})
	var de *domain.Error
	if !errors.As(err, &de) {
		t.Fatalf("error %v is not a *domain.Error", err)
	}
	if de.Code != domain.CodeMnemonicRequired {
		t.Fatalf("missing-mnemonic code = %q, want %q", de.Code, domain.CodeMnemonicRequired)
	}
	if de.Exit != domain.ExitUsage {
		t.Errorf("missing-mnemonic exit = %d, want %d (USAGE)", de.Exit, domain.ExitUsage)
	}
	if strings.Contains(strings.ToLower(de.Msg), "passphrase") {
		t.Errorf("missing-mnemonic message wrongly says 'passphrase': %q", de.Msg)
	}
}

// lookup adapts a map to the LookupEnv signature.
type envLookup map[string]string

func (e envLookup) lookup(k string) (string, bool) { v, ok := e[k]; return v, ok }
