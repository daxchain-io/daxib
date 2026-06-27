package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/daxchain-io/daxib/internal/domain"
)

// tx_confirm_test.go pins AF-3: the money-moving confirmation prompt (tx
// send/speedup/cancel). confirmTxSend is factored so every branch is unit-testable
// without a real TTY.

var sampleConfirm = txConfirm{
	Action:    "Send",
	Recipient: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
	Amount:    "0.01",
	Fee:       "10 sat/vByte",
	Network:   "mainnet",
}

// TestConfirmTxSendYesSkips: --yes authorizes WITHOUT prompting (no stream read).
func TestConfirmTxSendYesSkips(t *testing.T) {
	var out strings.Builder
	proceed, err := confirmTxSend(&out, strings.NewReader(""), true /*isTTY*/, true /*yes*/, sampleConfirm)
	if err != nil {
		t.Fatalf("--yes should not error: %v", err)
	}
	if !proceed {
		t.Error("--yes must proceed=true")
	}
	if out.Len() != 0 {
		t.Errorf("--yes must not print a prompt; got %q", out.String())
	}
}

// TestConfirmTxSendNonTTYDefers: non-TTY without --yes does NOT prompt and does NOT
// error — it returns proceed=false so the service's usage.confirmation_required gate
// fires (the historical non-interactive contract is preserved).
func TestConfirmTxSendNonTTYDefers(t *testing.T) {
	var out strings.Builder
	proceed, err := confirmTxSend(&out, strings.NewReader(""), false /*isTTY*/, false /*yes*/, sampleConfirm)
	if err != nil {
		t.Fatalf("non-TTY without --yes must not error here (the service gate fires): %v", err)
	}
	if proceed {
		t.Error("non-TTY without --yes must proceed=false (defer to the service gate)")
	}
	if out.Len() != 0 {
		t.Errorf("non-TTY must not prompt; got %q", out.String())
	}
}

// TestConfirmTxSendTTYAccepts: an interactive 'y' proceeds, and the prompt shows the
// recipient/amount/fee/network the operator is authorizing.
func TestConfirmTxSendTTYAccepts(t *testing.T) {
	for _, ans := range []string{"y\n", "Y\n", "yes\n", "  YES \n"} {
		var out strings.Builder
		proceed, err := confirmTxSend(&out, strings.NewReader(ans), true /*isTTY*/, false /*yes*/, sampleConfirm)
		if err != nil {
			t.Fatalf("answer %q should proceed: %v", ans, err)
		}
		if !proceed {
			t.Errorf("answer %q must proceed=true", ans)
		}
		got := out.String()
		for _, want := range []string{sampleConfirm.Recipient, sampleConfirm.Amount, sampleConfirm.Fee, sampleConfirm.Network} {
			if !strings.Contains(got, want) {
				t.Errorf("prompt missing %q; got:\n%s", want, got)
			}
		}
	}
}

// TestConfirmAbandonPromptsAndAborts is the GAP-1 (no-TTY-confirm) regression: tx
// abandon — like send/speedup/cancel — must add a real interactive prompt rather than
// relying solely on the service's non-TTY gate. confirmAbandon routes through
// confirmTxSend with an irreversible-abandon summary; here we exercise that same
// confirmTxSend path with the abandon shape to lock the behavior: at a TTY without
// --yes, a decline aborts with usage.confirmation_required, and an accept proceeds.
func TestConfirmAbandonPromptsAndAborts(t *testing.T) {
	abandonConfirm := txConfirm{
		Action:    "abandon (irreversible: frees inputs of a never-broadcast signed tx)",
		Recipient: "tx deadbeef",
		Network:   "mainnet",
	}

	// Decline at a TTY ⇒ usage.confirmation_required (exit 2): no silent mutation.
	for _, ans := range []string{"\n", "n\n", "no\n"} {
		var out strings.Builder
		proceed, err := confirmTxSend(&out, strings.NewReader(ans), true /*isTTY*/, false /*yes*/, abandonConfirm)
		if proceed {
			t.Errorf("abandon answer %q must NOT proceed", ans)
		}
		var de *domain.Error
		if !errors.As(err, &de) || de.Code != "usage.confirmation_required" {
			t.Fatalf("abandon answer %q err = %v, want usage.confirmation_required", ans, err)
		}
		if !strings.Contains(out.String(), "abandon") {
			t.Errorf("abandon prompt must name the action; got:\n%s", out.String())
		}
	}

	// Accept at a TTY ⇒ proceed.
	var out strings.Builder
	proceed, err := confirmTxSend(&out, strings.NewReader("y\n"), true /*isTTY*/, false /*yes*/, abandonConfirm)
	if err != nil || !proceed {
		t.Fatalf("abandon 'y' must proceed: proceed=%v err=%v", proceed, err)
	}
}

// TestConfirmTxSendTTYAborts: anything but yes aborts with usage.confirmation_required
// (exit 2), so a fat-fingered Enter never moves funds.
func TestConfirmTxSendTTYAborts(t *testing.T) {
	for _, ans := range []string{"\n", "n\n", "no\n", "nope\n", "yeah\n"} {
		var out strings.Builder
		proceed, err := confirmTxSend(&out, strings.NewReader(ans), true /*isTTY*/, false /*yes*/, sampleConfirm)
		if proceed {
			t.Errorf("answer %q must NOT proceed", ans)
		}
		if err == nil {
			t.Fatalf("answer %q must abort with an error", ans)
		}
		var de *domain.Error
		if !errors.As(err, &de) || de.Code != "usage.confirmation_required" {
			t.Fatalf("answer %q err = %v, want usage.confirmation_required", ans, err)
		}
		if de.Exit != domain.ExitUsage {
			t.Errorf("abort exit = %d, want %d (USAGE)", de.Exit, domain.ExitUsage)
		}
	}
}
