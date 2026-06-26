package service

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/daxchain-io/daxib/internal/backend"
	"github.com/daxchain-io/daxib/internal/backend/fake"
	"github.com/daxchain-io/daxib/internal/domain"
)

// newFakeBackendService opens a service whose backend dialer returns the supplied
// fake, with the canonical wallet importable and an esplora endpoint selected for
// mainnet. The fake lets the balance/aggregation path run with no HTTP at all.
func newFakeBackendService(t *testing.T, fc *fake.Client) (*Service, func()) {
	t.Helper()
	keystoreDir := t.TempDir()
	configDir := t.TempDir() // the config DIRECTORY; the store joins config.toml inside
	env := map[string]string{
		"DAXIB_PASSPHRASE":         "test-pass-12345678",
		"DAXIB_PASSPHRASE_CONFIRM": "test-pass-12345678",
	}
	svc, err := Open(context.Background(), Options{
		Keystore: keystoreDir,
		Config:   configDir,
		Network:  "mainnet",
		KDFLight: true,
		Dial: func(ctx context.Context, o backend.Options) (backend.Client, error) {
			return fc, nil
		},
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
	if _, _, err := svc.BackendAdd(context.Background(), domain.BackendAddRequest{
		Name: "fakebk", Network: "mainnet", Type: domain.BackendEsplora, URL: "http://fake",
	}); err != nil {
		t.Fatalf("BackendAdd: %v", err)
	}
	if _, err := svc.BackendUse(context.Background(), domain.BackendUseRequest{Name: "fakebk"}); err != nil {
		t.Fatalf("BackendUse: %v", err)
	}
	return svc, func() { _ = svc.Close() }
}

// TestBalance_WithFake proves the confirmed/unconfirmed aggregation through the
// fake backend.Client (the load-bearing service test seam).
func TestBalance_WithFake(t *testing.T) {
	fc := fake.New()
	fc.Tip = 800000
	fc.UTXOsByAddr[canonicalReceive0] = []domain.UTXO{
		{Txid: "aa", Vout: 0, Address: canonicalReceive0, ValueSat: 100000, Height: 799000, Confirmations: 1001},
		{Txid: "bb", Vout: 0, Address: canonicalReceive0, ValueSat: 7000, Height: 0, Confirmations: 0},
	}

	svc, done := newFakeBackendService(t, fc)
	defer done()
	importCanonical(t, svc, "vec")

	res, err := svc.Balance(context.Background(), domain.BalanceRequest{Wallet: "vec"})
	if err != nil {
		t.Fatalf("Balance: %v", err)
	}
	if res.ConfirmedSat != 100000 || res.UnconfirmedSat != 7000 || res.TotalSat != 107000 {
		t.Fatalf("balance = %+v, want confirmed=100000 unconfirmed=7000 total=107000", res)
	}
	// The fake must have been asked for the gap-window address set including the
	// canonical receive 0.
	calls := fc.CallsFor("UTXOs")
	if len(calls) != 1 {
		t.Fatalf("UTXOs called %d times, want 1", len(calls))
	}
	addrs, _ := calls[0].Args[0].([]string)
	if !contains(addrs, canonicalReceive0) {
		t.Fatalf("scan set %v did not include the canonical receive 0", addrs)
	}
}

// TestBalance_NotConfigured proves balance with no backend configured for the
// network is backend.not_configured (exit 10), not a crash.
func TestBalance_NotConfigured(t *testing.T) {
	keystoreDir := t.TempDir()
	env := map[string]string{
		"DAXIB_PASSPHRASE":         "test-pass-12345678",
		"DAXIB_PASSPHRASE_CONFIRM": "test-pass-12345678",
	}
	svc, err := Open(context.Background(), Options{
		Keystore: keystoreDir,
		Config:   t.TempDir(), // empty config DIRECTORY
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
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = svc.Close() }()
	importCanonical(t, svc, "vec")

	_, err = svc.Balance(context.Background(), domain.BalanceRequest{Wallet: "vec"})
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != domain.CodeBackendNotConfigured {
		t.Fatalf("err = %v, want backend.not_configured", err)
	}
	if de.Exit != domain.ExitNotFound {
		t.Fatalf("exit = %d, want %d", de.Exit, domain.ExitNotFound)
	}
}

// TestBackendTest_DialErrorPropagates proves a backend-unreachable dial error
// (exit 6) propagates through BackendTest.
func TestBackendTest_DialErrorPropagates(t *testing.T) {
	fc := fake.New()
	fc.Err = domain.New(domain.CodeBackendUnreachable, "nothing listening")

	svc, done := newFakeBackendService(t, fc)
	defer done()

	_, err := svc.BackendTest(context.Background(), domain.BackendTestRequest{Name: "fakebk"})
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != domain.CodeBackendUnreachable {
		t.Fatalf("err = %v, want backend.unreachable", err)
	}
	if de.Exit != domain.ExitNetwork {
		t.Fatalf("exit = %d, want %d (network)", de.Exit, domain.ExitNetwork)
	}
}

// TestResolveSecretRef_ThroughBackendOptions proves the service resolves a
// ${env:} rpcpassword at dial time (and never persists it). It registers a core
// backend with a ${env:} password and checks the dialer receives the resolved
// value.
func TestResolveSecretRef_ThroughBackendOptions(t *testing.T) {
	keystoreDir := t.TempDir()
	env := map[string]string{
		"DAXIB_PASSPHRASE":         "test-pass-12345678",
		"DAXIB_PASSPHRASE_CONFIRM": "test-pass-12345678",
		"NODE_RPC_PASS":            "resolved-secret",
	}
	var gotPass string
	svc, err := Open(context.Background(), Options{
		Keystore: keystoreDir,
		Config:   t.TempDir(), // config DIRECTORY
		Network:  "regtest",
		KDFLight: true,
		Dial: func(ctx context.Context, o backend.Options) (backend.Client, error) {
			gotPass = o.RPCPassword
			fc := fake.New()
			fc.Tip = 1
			return fc, nil
		},
		Secret: SecretIO{
			Stdin:     strings.NewReader(""),
			LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok },
			IsTTY:     func() bool { return false },
			Prompt:    func(string) ([]byte, error) { return nil, io.EOF },
		},
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = svc.Close() }()

	if _, _, err := svc.BackendAdd(context.Background(), domain.BackendAddRequest{
		Name: "core1", Network: "regtest", Type: domain.BackendCore,
		URL: "http://127.0.0.1:18443", RPCUser: "x", RPCPassword: "${env:NODE_RPC_PASS}",
	}); err != nil {
		t.Fatalf("BackendAdd: %v", err)
	}
	if _, err := svc.BackendTest(context.Background(), domain.BackendTestRequest{Name: "core1"}); err != nil {
		t.Fatalf("BackendTest: %v", err)
	}
	if gotPass != "resolved-secret" {
		t.Fatalf("dialer saw rpcpassword %q, want the resolved ${env:} value", gotPass)
	}
}

func contains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}
