package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/daxchain-io/daxib/internal/cli/render"
	"github.com/daxchain-io/daxib/internal/domain"
)

// tx_test.go is the CLI SURFACE harness for the M4 tx/fee commands: flag→request
// validation, arg counts, exit mapping, the EVM-leak guard, and the
// renderTxOutcome stdout contract. The authoritative engine-verify send proof
// lives at the service layer (internal/service/send_test.go); these tests assert
// the frontend grammar without a backend.

func TestTxSendMissingTo(t *testing.T) {
	isolateKeystore(t)
	_, stderr, code := execCLI(t, "tx", "send", "--amount", "0.001", "--yes")
	if code != 2 {
		t.Fatalf("missing --to exit=%d, want 2:\n%s", code, stderr)
	}
}

func TestTxSendMissingAmount(t *testing.T) {
	isolateKeystore(t)
	_, stderr, code := execCLI(t, "tx", "send", "--to", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "--yes")
	if code != 2 {
		t.Fatalf("missing --amount exit=%d, want 2:\n%s", code, stderr)
	}
}

func TestTxSendBadTimeout(t *testing.T) {
	isolateKeystore(t)
	_, stderr, code := execCLI(t, "tx", "send",
		"--to", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
		"--amount", "0.001", "--wait", "--timeout", "not-a-duration", "--yes")
	if code != 2 {
		t.Fatalf("bad --timeout exit=%d, want 2:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "usage.bad_timeout") {
		t.Errorf("expected usage.bad_timeout code, got:\n%s", stderr)
	}
}

func TestTxSendBadAmount(t *testing.T) {
	isolateKeystore(t)
	for _, amt := range []string{"0", "-1", "abc", "21000001", "0.000000001", "200sat"} {
		_, stderr, code := execCLI(t, "tx", "send",
			"--to", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
			"--amount", amt, "--fee-rate", "10", "--yes")
		if code != 2 {
			t.Errorf("--amount %q exit=%d, want 2:\n%s", amt, code, stderr)
		}
	}
}

func TestTxSendBadAddress(t *testing.T) {
	isolateKeystore(t)
	// A testnet address on mainnet, and a garbage string.
	for _, to := range []string{"tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", "not-an-address"} {
		_, stderr, code := execCLI(t, "tx", "send",
			"--to", to, "--amount", "0.001", "--fee-rate", "10", "--yes")
		if code != 2 {
			t.Errorf("--to %q exit=%d, want 2:\n%s", to, code, stderr)
		}
		if !strings.Contains(stderr, "usage.bad_address") {
			t.Errorf("--to %q expected usage.bad_address:\n%s", to, stderr)
		}
	}
}

func TestExitCodeRegistry_TxCodes(t *testing.T) {
	cases := map[string]int{
		"tx.broadcast_rejected": 6,
		"usage.dust_output":     2,
		"tx.wait_timeout":       8,
		"usage.bad_amount":      2,
		"usage.bad_address":     2,
		"funds.insufficient":    5,
		"tx.input_spent":        9,
		"tx.fee_too_low":        6,
	}
	for code, want := range cases {
		if got := int(domain.ExitOf(code)); got != want {
			t.Errorf("ExitOf(%q)=%d, want %d", code, got, want)
		}
	}
}

func TestTxStatusArgCount(t *testing.T) {
	isolateKeystore(t)
	if _, _, code := execCLI(t, "tx", "status"); code != 2 {
		t.Errorf("tx status no-arg exit=%d, want 2", code)
	}
	if _, _, code := execCLI(t, "tx", "status", "a", "b"); code != 2 {
		t.Errorf("tx status two-arg exit=%d, want 2", code)
	}
}

func TestTxWaitArgCount(t *testing.T) {
	isolateKeystore(t)
	if _, _, code := execCLI(t, "tx", "wait"); code != 2 {
		t.Errorf("tx wait no-arg exit=%d, want 2", code)
	}
	if _, _, code := execCLI(t, "tx", "wait", "a", "b"); code != 2 {
		t.Errorf("tx wait two-arg exit=%d, want 2", code)
	}
}

func TestTxUnknownSubcommand(t *testing.T) {
	isolateKeystore(t)
	if _, _, code := execCLI(t, "tx", "speedup"); code != 2 {
		t.Errorf("unknown tx subcommand exit=%d, want 2", code)
	}
}

func TestTxSendUnknownFlag(t *testing.T) {
	isolateKeystore(t)
	if _, _, code := execCLI(t, "tx", "send", "--gas-price", "10"); code != 2 {
		t.Errorf("unknown flag exit=%d, want 2", code)
	}
}

func TestTxHelpListsSubcommands(t *testing.T) {
	stdout, _, code := execCLI(t, "tx", "--help")
	if code != 0 {
		t.Fatalf("tx --help exit=%d, want 0", code)
	}
	for _, sub := range []string{"send", "status", "wait", "list"} {
		if !strings.Contains(stdout, sub) {
			t.Errorf("tx --help missing subcommand %q:\n%s", sub, stdout)
		}
	}
	// M5/RBF commands must NOT appear in M4.
	for _, leak := range []string{"speedup", "cancel", "abandon"} {
		if strings.Contains(stdout, leak) {
			t.Errorf("tx --help leaks M5 command %q:\n%s", leak, stdout)
		}
	}
}

func TestTxSendHelpFlags(t *testing.T) {
	stdout, _, code := execCLI(t, "tx", "send", "--help")
	if code != 0 {
		t.Fatalf("tx send --help exit=%d, want 0", code)
	}
	for _, f := range []string{"--wallet", "--to", "--amount", "--fee-rate", "--speed", "--wait", "--confirmations", "--timeout", "--dry-run"} {
		if !strings.Contains(stdout, f) {
			t.Errorf("tx send --help missing flag %q:\n%s", f, stdout)
		}
	}
	// EVM-leak guard: no gas/nonce/max-fee flags.
	for _, leak := range []string{"--gas-", "--nonce", "--max-fee", "--max-priority"} {
		if strings.Contains(stdout, leak) {
			t.Errorf("tx send --help leaks EVM flag %q:\n%s", leak, stdout)
		}
	}
}

func TestFeeNoBackendConfigured(t *testing.T) {
	isolateKeystore(t)
	// Point config at an empty temp dir so no backend is configured for mainnet.
	t.Setenv("DAXIB_CONFIG", t.TempDir())
	t.Setenv("DAXIB_NETWORK", "mainnet")
	_, stderr, code := execCLI(t, "fee")
	if code != 10 {
		t.Fatalf("fee with no backend exit=%d, want 10 (backend.not_configured):\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "backend.not_configured") {
		t.Errorf("expected backend.not_configured, got:\n%s", stderr)
	}
}

func TestFeeHelp(t *testing.T) {
	stdout, _, code := execCLI(t, "fee", "--help")
	if code != 0 {
		t.Fatalf("fee --help exit=%d, want 0", code)
	}
	if !strings.Contains(stdout, "--speed") {
		t.Errorf("fee --help missing --speed:\n%s", stdout)
	}
}

// ── renderTxOutcome contract (the §5.3/§5.9 stdout discipline) ────────────────

func renderHarness(res domain.TxResult, err error) (stdout string, retErr error) {
	cmd := newRootCmd(context.Background(), &rootState{})
	var out bytes.Buffer
	cmd.SetOut(&out)
	retErr = renderTxOutcome(cmd, render.Mode{JSON: true}, res, err)
	return out.String(), retErr
}

func TestRenderTxOutcomeTimeoutEmitsStdoutThenError(t *testing.T) {
	res := domain.TxResult{Txid: "deadbeef", Status: domain.TxStateTimeout, Resume: "daxib tx wait deadbeef"}
	timeoutErr := domain.New(domain.CodeTxWaitTimeout, "timed out")
	stdout, err := renderHarness(res, timeoutErr)

	// Exactly one stdout object.
	dec := json.NewDecoder(strings.NewReader(stdout))
	var got domain.TxResult
	if derr := dec.Decode(&got); derr != nil {
		t.Fatalf("expected one JSON object on stdout, got %q (%v)", stdout, derr)
	}
	if dec.More() {
		t.Errorf("more than one stdout object: %q", stdout)
	}
	// The error funnels for the exit code (exit 8).
	de := domain.AsError(err)
	if de == nil || de.Exit != domain.ExitTimeoutPending {
		t.Errorf("err=%v, want tx.wait_timeout exit 8", err)
	}
}

func TestRenderTxOutcomeBareErrorNoStdout(t *testing.T) {
	stdout, err := renderHarness(domain.TxResult{}, domain.New(domain.CodeUsageBadAmount, "bad"))
	if stdout != "" {
		t.Errorf("a bare pre-broadcast error must write NOTHING to stdout, got %q", stdout)
	}
	if err == nil {
		t.Errorf("expected the error to be returned")
	}
}

func TestRenderTxOutcomeSuccessAndDryRun(t *testing.T) {
	// A populated result emits one object and returns nil.
	stdout, err := renderHarness(domain.TxResult{Txid: "abc", Status: domain.TxStateBroadcast}, nil)
	if err != nil || !strings.Contains(stdout, "abc") {
		t.Errorf("success: err=%v stdout=%q", err, stdout)
	}
	// A dry-run (empty txid, DryRun=true) also emits one object.
	stdout2, err2 := renderHarness(domain.TxResult{DryRun: true, Status: domain.TxStatePending}, nil)
	if err2 != nil {
		t.Errorf("dry-run err=%v", err2)
	}
	dec := json.NewDecoder(strings.NewReader(stdout2))
	var got domain.TxResult
	if derr := dec.Decode(&got); derr != nil || !got.DryRun {
		t.Errorf("dry-run did not emit a DryRun object: %q (%v)", stdout2, derr)
	}
}
