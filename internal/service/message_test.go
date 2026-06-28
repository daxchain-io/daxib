package service

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/daxchain-io/daxib/internal/domain"
)

var errTestNoTTY = errors.New("no TTY in test")

func bytesReader(s string) io.Reader { return bytes.NewBufferString(s) }

// message_test.go exercises the service's BIP-322 sign/verify use cases end to end:
// import a wallet, sign a message for its receive-0 address, then verify the
// resulting signature passphrase-free; plus the negative paths.

const msgMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
const msgReceive0 = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"

func importMsgWallet(t *testing.T) (*Service, func()) {
	t.Helper()
	svc, done := newTestService(t, map[string]string{
		"DAXIB_PASSPHRASE":         "test-pass-12345678",
		"DAXIB_PASSPHRASE_CONFIRM": "test-pass-12345678",
	}, msgMnemonic)
	if _, err := svc.WalletImport(context.Background(), domain.LocalCLI(), domain.WalletImportRequest{Name: "vec"}, WalletImportInput{MnemonicStdin: true}); err != nil {
		done()
		t.Fatalf("WalletImport: %v", err)
	}
	return svc, done
}

// TestServiceSignVerifyRoundtrip signs a message by address and verifies it.
func TestServiceSignVerifyRoundtrip(t *testing.T) {
	svc, done := importMsgWallet(t)
	defer done()
	ctx := context.Background()

	sig, err := svc.MessageSign(ctx, domain.LocalCLI(),
		domain.MessageSignRequest{Ref: msgReceive0, Message: "hello daxib"},
		MessageSignInput{Message: []byte("hello daxib")})
	if err != nil {
		t.Fatalf("MessageSign: %v", err)
	}
	if sig.Address != msgReceive0 {
		t.Errorf("signed address = %q, want %q", sig.Address, msgReceive0)
	}
	if sig.Format != "bip322-simple" {
		t.Errorf("format = %q, want bip322-simple", sig.Format)
	}

	ver, err := svc.MessageVerify(ctx, domain.LocalCLI(), domain.MessageVerifyRequest{
		Address: msgReceive0, Message: "hello daxib", Signature: sig.Signature,
	})
	if err != nil {
		t.Fatalf("MessageVerify: %v", err)
	}
	if !ver.Valid {
		t.Fatal("verify of a freshly-signed message returned valid=false")
	}
}

// TestServiceSignByRef signs via a "<wallet>/<branch>/<index>" ref instead of a
// raw address, then verifies against the resolved address.
func TestServiceSignByRef(t *testing.T) {
	svc, done := importMsgWallet(t)
	defer done()
	ctx := context.Background()

	sig, err := svc.MessageSign(ctx, domain.LocalCLI(),
		domain.MessageSignRequest{Ref: "vec/0/0", Message: "via ref"},
		MessageSignInput{Message: []byte("via ref")})
	if err != nil {
		t.Fatalf("MessageSign by ref: %v", err)
	}
	if sig.Address != msgReceive0 {
		t.Fatalf("ref resolved to %q, want %q", sig.Address, msgReceive0)
	}
	ver, err := svc.MessageVerify(ctx, domain.LocalCLI(), domain.MessageVerifyRequest{
		Address: sig.Address, Message: "via ref", Signature: sig.Signature,
	})
	if err != nil {
		t.Fatalf("MessageVerify: %v", err)
	}
	if !ver.Valid {
		t.Fatal("ref-signed message did not verify")
	}
}

// TestServiceVerifyInvalidIsNotError proves a well-formed-but-wrong signature is a
// successful verify with valid=false (not an error → exit 0).
func TestServiceVerifyInvalidIsNotError(t *testing.T) {
	svc, done := importMsgWallet(t)
	defer done()
	ctx := context.Background()

	sig, err := svc.MessageSign(ctx, domain.LocalCLI(),
		domain.MessageSignRequest{Ref: msgReceive0, Message: "original"},
		MessageSignInput{Message: []byte("original")})
	if err != nil {
		t.Fatalf("MessageSign: %v", err)
	}
	// Verify against a DIFFERENT message: well-formed signature, wrong message.
	ver, verr := svc.MessageVerify(ctx, domain.LocalCLI(), domain.MessageVerifyRequest{
		Address: msgReceive0, Message: "tampered", Signature: sig.Signature,
	})
	if verr != nil {
		t.Fatalf("MessageVerify returned an error for a mismatch (should be valid=false): %v", verr)
	}
	if ver.Valid {
		t.Fatal("verify of a mismatched message returned valid=true")
	}
}

// TestServiceVerifyBadSignature proves a non-base64 / undecodable signature is a
// usage.bad_signature error (exit 2).
func TestServiceVerifyBadSignature(t *testing.T) {
	svc, done := importMsgWallet(t)
	defer done()
	ctx := context.Background()

	_, err := svc.MessageVerify(ctx, domain.LocalCLI(), domain.MessageVerifyRequest{
		Address: msgReceive0, Message: "m", Signature: "!!!not base64!!!",
	})
	if err == nil {
		t.Fatal("MessageVerify accepted a non-base64 signature")
	}
	if c := code(t, err); c != domain.CodeBadSignature {
		t.Fatalf("bad-signature code=%s, want %s", c, domain.CodeBadSignature)
	}
}

// TestServiceSignBadAddress proves a malformed ref is usage.bad_address (exit 2).
func TestServiceSignBadAddress(t *testing.T) {
	svc, done := importMsgWallet(t)
	defer done()
	ctx := context.Background()

	_, err := svc.MessageSign(ctx, domain.LocalCLI(),
		domain.MessageSignRequest{Ref: "not-an-address", Message: "m"},
		MessageSignInput{Message: []byte("m")})
	if err == nil {
		t.Fatal("MessageSign accepted a malformed ref")
	}
	if c := code(t, err); c != domain.CodeUsageBadAddress {
		t.Fatalf("bad-ref code=%s, want %s", c, domain.CodeUsageBadAddress)
	}
}

// TestServiceSignWrongPassphrase proves a wrong keystore passphrase fails closed
// (keystore.bad_passphrase, exit 4) at the service boundary.
func TestServiceSignWrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	// First service imports the wallet under the correct passphrase.
	svc1 := openServiceAt(t, dir, map[string]string{
		"DAXIB_PASSPHRASE":         "test-pass-12345678",
		"DAXIB_PASSPHRASE_CONFIRM": "test-pass-12345678",
	}, msgMnemonic)
	if _, err := svc1.WalletImport(ctx, domain.LocalCLI(), domain.WalletImportRequest{Name: "vec"}, WalletImportInput{MnemonicStdin: true}); err != nil {
		t.Fatalf("WalletImport: %v", err)
	}
	_ = svc1.Close()

	// Second service over the SAME keystore dir, but a WRONG passphrase env: the
	// MessageSign unlock must fail closed.
	svc2 := openServiceAt(t, dir, map[string]string{
		"DAXIB_PASSPHRASE": "WRONG-pass-12345678",
	}, "")
	defer func() { _ = svc2.Close() }()
	_, err := svc2.MessageSign(ctx, domain.LocalCLI(),
		domain.MessageSignRequest{Ref: msgReceive0, Message: "m"},
		MessageSignInput{Message: []byte("m")})
	if err == nil {
		t.Fatal("MessageSign accepted a wrong passphrase")
	}
	if c := code(t, err); c != "keystore.bad_passphrase" {
		t.Fatalf("wrong-passphrase code=%s, want keystore.bad_passphrase", c)
	}
}

// TestServiceSignBoundNetworkMismatch pins the scope guard on `sign message`: a
// BOUND wallet refuses signing off its locked network with usage.network_mismatch
// (exit 2), NOT wallet.not_found (exit 10). The slash-ref form is the regression
// case — resolveSignRef derives via AddressAt, which on a bound wallet off its
// network has no active-coin_type chain and would surface wallet.not_found if the
// guard did not run first.
func TestServiceSignBoundNetworkMismatch(t *testing.T) {
	const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	dir := t.TempDir()

	openAt := func(net string) *Service {
		env := map[string]string{
			"DAXIB_KEYSTORE":           dir,
			"DAXIB_KDF_LIGHT":          "1",
			"DAXIB_PASSPHRASE":         "test-pass-12345678",
			"DAXIB_PASSPHRASE_CONFIRM": "test-pass-12345678",
		}
		svc, err := Open(context.Background(), Options{
			Keystore: dir, Network: net, KDFLight: true,
			Secret: SecretIO{
				Stdin:     bytesReader(mnemonic),
				LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok },
				IsTTY:     func() bool { return false },
				Prompt:    func(string) ([]byte, error) { return nil, errTestNoTTY },
			},
		})
		if err != nil {
			t.Fatalf("Open(%s): %v", net, err)
		}
		return svc
	}
	ctx := context.Background()

	// Import a BOUND mainnet wallet (coin_type 0).
	svcMain := openAt("mainnet")
	if _, err := svcMain.WalletImport(ctx, domain.LocalCLI(),
		domain.WalletImportRequest{Name: "locked", Network: domain.NetworkMainnet, Bind: true},
		WalletImportInput{MnemonicStdin: true}); err != nil {
		t.Fatalf("WalletImport bound mainnet: %v", err)
	}
	_ = svcMain.Close()

	// Reopen the SAME keystore on testnet (coin_type 1): the bound wallet has no
	// chain for the active coin_type, so the chain-touching slash-ref path would
	// hit wallet.not_found if the guard did not pre-empt it.
	svcTest := openAt("testnet")
	defer func() { _ = svcTest.Close() }()

	// Slash-ref form (the regression case).
	_, err := svcTest.MessageSign(ctx, domain.LocalCLI(),
		domain.MessageSignRequest{Ref: "locked/0/0", Message: "hi"},
		MessageSignInput{Message: []byte("hi")})
	if got := code(t, err); got != "usage.network_mismatch" {
		t.Fatalf("slash-ref sign on bound off-network: code = %q, want usage.network_mismatch", got)
	}

	// Explicit --wallet hint on a bare-address ref must also be guarded.
	_, err = svcTest.MessageSign(ctx, domain.LocalCLI(),
		domain.MessageSignRequest{Wallet: "locked", Ref: msgReceive0, Message: "hi"},
		MessageSignInput{Message: []byte("hi")})
	if got := code(t, err); got != "usage.network_mismatch" {
		t.Fatalf("hinted bare-address sign on bound off-network: code = %q, want usage.network_mismatch", got)
	}
}

// TestServiceSignAgnosticCrossNetwork asserts an AGNOSTIC wallet signs on any
// active network (no scope guard): the same wallet signs+verifies on mainnet and
// testnet, both exit 0.
func TestServiceSignAgnosticCrossNetwork(t *testing.T) {
	const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	dir := t.TempDir()

	openAt := func(net string) *Service {
		env := map[string]string{
			"DAXIB_KEYSTORE":           dir,
			"DAXIB_KDF_LIGHT":          "1",
			"DAXIB_PASSPHRASE":         "test-pass-12345678",
			"DAXIB_PASSPHRASE_CONFIRM": "test-pass-12345678",
		}
		svc, err := Open(context.Background(), Options{
			Keystore: dir, Network: net, KDFLight: true,
			Secret: SecretIO{
				Stdin:     bytesReader(mnemonic),
				LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok },
				IsTTY:     func() bool { return false },
				Prompt:    func(string) ([]byte, error) { return nil, errTestNoTTY },
			},
		})
		if err != nil {
			t.Fatalf("Open(%s): %v", net, err)
		}
		return svc
	}
	ctx := context.Background()

	svcMain := openAt("mainnet")
	if _, err := svcMain.WalletImport(ctx, domain.LocalCLI(),
		domain.WalletImportRequest{Name: "any"}, WalletImportInput{MnemonicStdin: true}); err != nil {
		t.Fatalf("WalletImport agnostic: %v", err)
	}
	mainSig, err := svcMain.MessageSign(ctx, domain.LocalCLI(),
		domain.MessageSignRequest{Ref: "any/0/0", Message: "hi"},
		MessageSignInput{Message: []byte("hi")})
	if err != nil {
		t.Fatalf("MessageSign mainnet (agnostic): %v", err)
	}
	if mainSig.Address != msgReceive0 {
		t.Fatalf("mainnet ref address = %q, want %q", mainSig.Address, msgReceive0)
	}
	_ = svcMain.Close()

	svcTest := openAt("testnet")
	defer func() { _ = svcTest.Close() }()
	testSig, err := svcTest.MessageSign(ctx, domain.LocalCLI(),
		domain.MessageSignRequest{Ref: "any/0/0", Message: "hi"},
		MessageSignInput{Message: []byte("hi")})
	if err != nil {
		t.Fatalf("MessageSign testnet (agnostic should not be guarded): %v", err)
	}
	if !strings.HasPrefix(testSig.Address, "tb1") {
		t.Fatalf("testnet ref address = %q, want tb1...", testSig.Address)
	}
}

// openServiceAt opens a light service over an EXISTING keystore dir with the given
// env + stdin (the shared-dir variant of newTestService for multi-open tests).
func openServiceAt(t *testing.T, dir string, env map[string]string, stdin string) *Service {
	t.Helper()
	env2 := map[string]string{"DAXIB_KEYSTORE": dir, "DAXIB_KDF_LIGHT": "1"}
	for k, v := range env {
		env2[k] = v
	}
	svc, err := Open(context.Background(), Options{
		Keystore: dir,
		Network:  "mainnet",
		KDFLight: true,
		Secret: SecretIO{
			Stdin:     bytesReader(stdin),
			LookupEnv: func(k string) (string, bool) { v, ok := env2[k]; return v, ok },
			IsTTY:     func() bool { return false },
			Prompt:    func(string) ([]byte, error) { return nil, errTestNoTTY },
		},
	})
	if err != nil {
		t.Fatalf("openServiceAt: %v", err)
	}
	return svc
}
