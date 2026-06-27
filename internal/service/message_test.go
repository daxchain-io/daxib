package service

import (
	"bytes"
	"context"
	"errors"
	"io"
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
	if _, err := svc.WalletImport(context.Background(), domain.WalletImportRequest{Name: "vec"}, WalletImportInput{MnemonicStdin: true}); err != nil {
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

	sig, err := svc.MessageSign(ctx,
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

	ver, err := svc.MessageVerify(ctx, domain.MessageVerifyRequest{
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

	sig, err := svc.MessageSign(ctx,
		domain.MessageSignRequest{Ref: "vec/0/0", Message: "via ref"},
		MessageSignInput{Message: []byte("via ref")})
	if err != nil {
		t.Fatalf("MessageSign by ref: %v", err)
	}
	if sig.Address != msgReceive0 {
		t.Fatalf("ref resolved to %q, want %q", sig.Address, msgReceive0)
	}
	ver, err := svc.MessageVerify(ctx, domain.MessageVerifyRequest{
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

	sig, err := svc.MessageSign(ctx,
		domain.MessageSignRequest{Ref: msgReceive0, Message: "original"},
		MessageSignInput{Message: []byte("original")})
	if err != nil {
		t.Fatalf("MessageSign: %v", err)
	}
	// Verify against a DIFFERENT message: well-formed signature, wrong message.
	ver, verr := svc.MessageVerify(ctx, domain.MessageVerifyRequest{
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

	_, err := svc.MessageVerify(ctx, domain.MessageVerifyRequest{
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

	_, err := svc.MessageSign(ctx,
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
	if _, err := svc1.WalletImport(ctx, domain.WalletImportRequest{Name: "vec"}, WalletImportInput{MnemonicStdin: true}); err != nil {
		t.Fatalf("WalletImport: %v", err)
	}
	_ = svc1.Close()

	// Second service over the SAME keystore dir, but a WRONG passphrase env: the
	// MessageSign unlock must fail closed.
	svc2 := openServiceAt(t, dir, map[string]string{
		"DAXIB_PASSPHRASE": "WRONG-pass-12345678",
	}, "")
	defer func() { _ = svc2.Close() }()
	_, err := svc2.MessageSign(ctx,
		domain.MessageSignRequest{Ref: msgReceive0, Message: "m"},
		MessageSignInput{Message: []byte("m")})
	if err == nil {
		t.Fatal("MessageSign accepted a wrong passphrase")
	}
	if c := code(t, err); c != "keystore.bad_passphrase" {
		t.Fatalf("wrong-passphrase code=%s, want keystore.bad_passphrase", c)
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
