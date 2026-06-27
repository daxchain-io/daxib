package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/daxchain-io/daxib/internal/domain"
)

// sign_cli_test.go drives the real `sign message` + `verify` commands through the
// Cobra funnel: sign a message for the canonical wallet's receive-0 address, then
// verify the produced base64 signature passphrase-free.

// TestSignVerifyCLIRoundtrip signs and verifies through the CLI, asserting the
// --json shapes and exit codes.
func TestSignVerifyCLIRoundtrip(t *testing.T) {
	isolateKeystore(t)
	importVec(t, "vec", "mainnet")

	out, stderr, code := execCLI(t,
		"sign", "message", canonReceive0,
		"--message", "hello daxib", "--network", "mainnet", "--json")
	if code != 0 {
		t.Fatalf("sign exit = %d, want 0:\n%s\n%s", code, out, stderr)
	}
	var signed domain.MessageSignResult
	if err := json.Unmarshal([]byte(out), &signed); err != nil {
		t.Fatalf("sign --json invalid: %v (%q)", err, out)
	}
	if signed.Address != canonReceive0 {
		t.Errorf("signed address = %q, want %q", signed.Address, canonReceive0)
	}
	if signed.Format != "bip322-simple" || signed.Signature == "" {
		t.Errorf("unexpected sign result: %+v", signed)
	}

	// Verify (passphrase-free; no keystore env needed for the crypto).
	vout, vstderr, vcode := execCLI(t,
		"verify", "--address", canonReceive0,
		"--message", "hello daxib", "--signature", signed.Signature,
		"--network", "mainnet", "--json")
	if vcode != 0 {
		t.Fatalf("verify exit = %d, want 0:\n%s\n%s", vcode, vout, vstderr)
	}
	var ver domain.MessageVerifyResult
	if err := json.Unmarshal([]byte(vout), &ver); err != nil {
		t.Fatalf("verify --json invalid: %v (%q)", err, vout)
	}
	if !ver.Valid {
		t.Fatal("verify of a freshly-signed message returned valid=false")
	}
}

// TestVerifyCLIInvalidIsExitZero proves a well-formed-but-wrong signature verifies
// false with exit 0 (an agent branches on the field, not the exit code).
func TestVerifyCLIInvalidIsExitZero(t *testing.T) {
	isolateKeystore(t)
	importVec(t, "vec", "mainnet")

	out, _, _ := execCLI(t,
		"sign", "message", canonReceive0, "--message", "original", "--network", "mainnet", "--json")
	var signed domain.MessageSignResult
	if err := json.Unmarshal([]byte(out), &signed); err != nil {
		t.Fatalf("sign --json invalid: %v", err)
	}

	// Verify against a DIFFERENT message: valid=false, exit 0.
	vout, _, vcode := execCLI(t,
		"verify", "--address", canonReceive0, "--message", "tampered",
		"--signature", signed.Signature, "--network", "mainnet", "--json")
	if vcode != 0 {
		t.Fatalf("verify of a mismatch exit = %d, want 0", vcode)
	}
	var ver domain.MessageVerifyResult
	if err := json.Unmarshal([]byte(vout), &ver); err != nil {
		t.Fatalf("verify --json invalid: %v", err)
	}
	if ver.Valid {
		t.Fatal("mismatched verify returned valid=true")
	}
}

// TestVerifyCLIBadSignature proves a non-base64 signature is a usage error (exit 2).
func TestVerifyCLIBadSignature(t *testing.T) {
	isolateKeystore(t)
	_, _, code := execCLI(t,
		"verify", "--address", canonReceive0, "--message", "m",
		"--signature", "!!!notbase64!!!", "--network", "mainnet", "--json")
	if code != int(domain.ExitUsage) {
		t.Fatalf("bad-signature exit = %d, want %d (usage)", code, domain.ExitUsage)
	}
}

// TestSignCLIMessageRequired proves no message source is a usage error (exit 2).
func TestSignCLIMessageRequired(t *testing.T) {
	isolateKeystore(t)
	importVec(t, "vec", "mainnet")
	_, stderr, code := execCLI(t, "sign", "message", canonReceive0, "--network", "mainnet", "--json")
	if code != int(domain.ExitUsage) {
		t.Fatalf("no-message exit = %d, want %d (usage)\n%s", code, domain.ExitUsage, stderr)
	}
	if !strings.Contains(stderr, "message_required") {
		t.Errorf("stderr should name message_required, got: %s", stderr)
	}
}

// TestSignCLIByRef signs via a <wallet>/<branch>/<index> ref.
func TestSignCLIByRef(t *testing.T) {
	isolateKeystore(t)
	importVec(t, "vec", "mainnet")
	out, stderr, code := execCLI(t,
		"sign", "message", "vec/0/0", "--message", "via ref", "--network", "mainnet", "--json")
	if code != 0 {
		t.Fatalf("sign-by-ref exit = %d, want 0:\n%s", code, stderr)
	}
	var signed domain.MessageSignResult
	if err := json.Unmarshal([]byte(out), &signed); err != nil {
		t.Fatalf("sign --json invalid: %v", err)
	}
	if signed.Address != canonReceive0 {
		t.Errorf("ref resolved to %q, want %q", signed.Address, canonReceive0)
	}
}
