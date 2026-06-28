package service

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/daxchain-io/daxib/internal/domain"
)

// canonicalMnemonic is the standard BIP-39 test vector; its mainnet receive 0 is
// bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu (BIP-84 §example).
const canonicalMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
const canonicalReceive0 = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"

// newConfiguredService opens a service over a temp keystore AND a temp config
// file, with an Esplora backend registered + selected for mainnet. It returns the
// service and a teardown.
func newConfiguredService(t *testing.T, esploraURL string) (*Service, func()) {
	t.Helper()
	keystoreDir := t.TempDir()
	configDir := t.TempDir() // the config DIRECTORY; the store joins config.toml inside
	env := map[string]string{
		"DAXIB_KEYSTORE":           keystoreDir,
		"DAXIB_KDF_LIGHT":          "1",
		"DAXIB_PASSPHRASE":         "test-pass-12345678",
		"DAXIB_PASSPHRASE_CONFIRM": "test-pass-12345678",
	}
	svc, err := Open(context.Background(), Options{
		Keystore: keystoreDir,
		Config:   configDir,
		Network:  "mainnet",
		KDFLight: true,
		Secret: SecretIO{
			Stdin:     strings.NewReader(canonicalMnemonic),
			LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok },
			IsTTY:     func() bool { return false },
			Prompt:    func(string) ([]byte, error) { return nil, io.EOF },
		},
	})
	if err != nil {
		t.Fatalf("service.Open: %v", err)
	}

	// Register + select the httptest Esplora backend for mainnet.
	if _, _, err := svc.BackendAdd(context.Background(), domain.LocalCLI(), domain.BackendAddRequest{
		Name: "test-esplora", Network: "mainnet", Type: domain.BackendEsplora, URL: esploraURL,
	}); err != nil {
		t.Fatalf("BackendAdd: %v", err)
	}
	if _, err := svc.BackendUse(context.Background(), domain.LocalCLI(), domain.BackendUseRequest{Name: "test-esplora"}); err != nil {
		t.Fatalf("BackendUse: %v", err)
	}
	return svc, func() { _ = svc.Close() }
}

// importCanonical imports the canonical-vector wallet (mnemonic from stdin).
func importCanonical(t *testing.T, svc *Service, name string) {
	t.Helper()
	if _, err := svc.WalletImport(context.Background(), domain.LocalCLI(),
		domain.WalletImportRequest{Name: name, Network: "mainnet"},
		WalletImportInput{MnemonicStdin: true}); err != nil {
		t.Fatalf("WalletImport: %v", err)
	}
}

// TestBalanceIntegration_Esplora is the load-bearing M3 balance test: it imports
// the canonical-vector wallet (receive 0 = bc1qcr8…fyu), stands up an httptest
// Esplora server returning a known 150000-sat confirmed UTXO for that address, and
// asserts `balance` reports the correct confirmed total — proving the full
// keys→config→backend→aggregate path with no live node.
func TestBalanceIntegration_Esplora(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/blocks/tip/height":
			_, _ = io.WriteString(w, "800000")
		case "/address/" + canonicalReceive0 + "/utxo":
			// One confirmed 150000-sat UTXO at height 799991 (=> 10 confirmations).
			_, _ = io.WriteString(w, `[{"txid":"aa","vout":0,"value":150000,"status":{"confirmed":true,"block_height":799991}}]`)
		default:
			_, _ = io.WriteString(w, "[]") // every other gap-window address is empty
		}
	}))
	defer srv.Close()

	svc, done := newConfiguredService(t, srv.URL)
	defer done()
	importCanonical(t, svc, "vec")

	res, err := svc.Balance(context.Background(), domain.LocalCLI(), domain.BalanceRequest{Wallet: "vec", UTXOs: true})
	if err != nil {
		t.Fatalf("Balance: %v", err)
	}
	if res.ConfirmedSat != 150000 {
		t.Fatalf("ConfirmedSat = %d, want 150000", res.ConfirmedSat)
	}
	if res.UnconfirmedSat != 0 {
		t.Fatalf("UnconfirmedSat = %d, want 0", res.UnconfirmedSat)
	}
	if res.TotalSat != 150000 || res.ConfirmedBTC != "0.00150000" {
		t.Fatalf("Total = %d (%s BTC), want 150000 (0.00150000)", res.TotalSat, res.ConfirmedBTC)
	}
	if res.Backend != "test-esplora" {
		t.Fatalf("Backend = %q, want test-esplora", res.Backend)
	}
	if len(res.UTXOs) != 1 || res.UTXOs[0].Outpoint != "aa:0" || res.UTXOs[0].Address != canonicalReceive0 {
		t.Fatalf("UTXOs = %+v, want one aa:0 on the canonical address", res.UTXOs)
	}
	if res.UTXOs[0].Confirmations != 10 {
		t.Fatalf("UTXO confirmations = %d, want 10", res.UTXOs[0].Confirmations)
	}
}

// TestUTXOListIntegration_Esplora proves `utxo list` returns the per-UTXO
// breakdown for the canonical wallet.
func TestUTXOListIntegration_Esplora(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/blocks/tip/height":
			_, _ = io.WriteString(w, "800000")
		case "/address/" + canonicalReceive0 + "/utxo":
			_, _ = io.WriteString(w, `[{"txid":"aa","vout":0,"value":150000,"status":{"confirmed":true,"block_height":799991}}]`)
		default:
			_, _ = io.WriteString(w, "[]")
		}
	}))
	defer srv.Close()

	svc, done := newConfiguredService(t, srv.URL)
	defer done()
	importCanonical(t, svc, "vec")

	res, err := svc.UTXOList(context.Background(), domain.LocalCLI(), domain.UTXOListRequest{Wallet: "vec"})
	if err != nil {
		t.Fatalf("UTXOList: %v", err)
	}
	if len(res.UTXOs) != 1 || res.TotalSat != 150000 {
		t.Fatalf("UTXOList = %+v, want one UTXO totalling 150000", res)
	}
}

// TestBackendTest_HappyPath proves `backend test` dials the httptest Esplora and
// reports the tip height + a latency.
func TestBackendTest_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/blocks/tip/height" {
			_, _ = io.WriteString(w, "812345")
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	svc, done := newConfiguredService(t, srv.URL)
	defer done()

	res, err := svc.BackendTest(context.Background(), domain.LocalCLI(), domain.BackendTestRequest{Name: "test-esplora"})
	if err != nil {
		t.Fatalf("BackendTest: %v", err)
	}
	if res.TipHeight != 812345 {
		t.Fatalf("TipHeight = %d, want 812345", res.TipHeight)
	}
	if res.Type != domain.BackendEsplora || res.Network != "mainnet" {
		t.Fatalf("res = %+v, want esplora/mainnet", res)
	}
}
