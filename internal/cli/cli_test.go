package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// cli_test.go is the command-level smoke harness for the M2 wallet/address
// surface. execCLI drives the real Cobra tree (newRootCmd + mapError) with
// captured streams, so it exercises the actual error→exit mapping, --json shape,
// and ceremony. It mirrors daxie's internal/cli/cli_test.go execCLI funnel.

// execCLI runs the cli with explicit args and captured streams through the real
// Execute funnel (newRootCmd + mapError), returning stdout, stderr, and the exit
// code.
//
// Note: secrets (passphrase/mnemonic) reach the service via env vars and the
// --*-file channels, NOT cobra's input stream — the frontend wires os.Stdin
// directly into the service's SecretIO (see open.go), which a captured cobra
// SetIn cannot reach. Tests therefore use isolateKeystore (env passphrase) and
// --mnemonic-file (file channel) rather than stdin injection.
func execCLI(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var outBuf, errBuf bytes.Buffer
	rs := &rootState{}
	ctx := context.Background()
	root := newRootCmd(ctx, rs)
	root.SetArgs(args)
	root.SetOut(&outBuf)
	root.SetErr(&errBuf)
	err := root.ExecuteContext(ctx)
	code = mapError(&errBuf, rs.flags.Mode(), err)
	return outBuf.String(), errBuf.String(), code
}

// mnemonicFile writes the canonical mnemonic to a temp file and returns its path
// for --mnemonic-file.
func mnemonicFile(t *testing.T) string {
	t.Helper()
	return writeTempFile(t, "mnemonic", canonicalMnemonic+"\n")
}

// isolateKeystore points the keystore at a temp dir and wires a non-interactive
// keystore passphrase (env channel) + its first-init confirm, plus the light KDF
// so scrypt stays fast. Real env vars are set via t.Setenv so the production
// os.LookupEnv path in buildServiceOptions is exercised end to end.
func isolateKeystore(t *testing.T) string {
	t.Helper()
	ks := t.TempDir()
	t.Setenv("DAXIB_KEYSTORE", ks)
	t.Setenv("DAXIB_PASSPHRASE", "unit-test-passphrase-123")
	t.Setenv("DAXIB_PASSPHRASE_CONFIRM", "unit-test-passphrase-123")
	t.Setenv("DAXIB_KDF_LIGHT", "1")
	// Ensure no inherited network/wallet env leaks into the test.
	t.Setenv("DAXIB_NETWORK", "")
	t.Setenv("DAXIB_WALLET", "")
	return ks
}

// writeFile writes content to a temp file and returns the path (helper for
// --*-file flag tests).
func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}
