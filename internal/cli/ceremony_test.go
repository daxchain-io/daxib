package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/daxchain-io/daxib/internal/domain"
)

// TestTwoDistinctPositions asserts the verification-position picker returns two
// distinct in-range indices for n>=2 and errors for n<2.
func TestTwoDistinctPositions(t *testing.T) {
	for _, n := range []int{2, 3, 12, 24} {
		for i := 0; i < 50; i++ {
			a, b, err := twoDistinctPositions(n)
			if err != nil {
				t.Fatalf("n=%d: %v", n, err)
			}
			if a == b {
				t.Fatalf("n=%d: positions not distinct: %d == %d", n, a, b)
			}
			if a < 0 || a >= n || b < 0 || b >= n {
				t.Fatalf("n=%d: position out of range: %d, %d", n, a, b)
			}
		}
	}
	for _, n := range []int{0, 1, -1} {
		if _, _, err := twoDistinctPositions(n); err == nil {
			t.Errorf("n=%d: expected an error", n)
		}
	}
}

// TestPreflightMnemonicDisplay asserts the channel gate: --yes or --json passes;
// without either (and no TTY under `go test`) it refuses with
// usage.confirmation_required.
func TestPreflightMnemonicDisplay(t *testing.T) {
	if err := preflightMnemonicDisplay(true, false); err != nil {
		t.Errorf("--yes should pass: %v", err)
	}
	if err := preflightMnemonicDisplay(false, true); err != nil {
		t.Errorf("--json should pass: %v", err)
	}
	// No --yes, no --json: under `go test` stdin is not a TTY, so this refuses.
	err := preflightMnemonicDisplay(false, false)
	if err == nil {
		t.Fatal("no-yes/no-json/no-TTY should refuse")
	}
	var de *domain.Error
	if !errors.As(err, &de) {
		t.Fatalf("error is not a *domain.Error: %T", err)
	}
	if de.Code != "usage.confirmation_required" {
		t.Errorf("code = %q, want usage.confirmation_required", de.Code)
	}
	if de.Exit != domain.ExitUsage {
		t.Errorf("exit = %d, want %d (USAGE)", de.Exit, domain.ExitUsage)
	}
}

// TestMnemonicCeremonyYesAndJSON asserts the ceremony short-circuits (echo in
// result) under both --yes and --json without running the interactive flow.
func TestMnemonicCeremonyYesAndJSON(t *testing.T) {
	for _, tc := range []struct {
		name           string
		yes, jsonMode  bool
		wantEchoResult bool
	}{
		{"yes", true, false, true},
		{"json", false, true, true},
		{"yes+json", true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			disp, err := mnemonicCeremony(nil, nil, tc.yes, tc.jsonMode, canonicalMnemonic, "")
			if err != nil {
				t.Fatalf("ceremony: %v", err)
			}
			if disp.echoInResult != tc.wantEchoResult {
				t.Errorf("echoInResult = %v, want %v", disp.echoInResult, tc.wantEchoResult)
			}
		})
	}
}

// uniformMnemonic is a 12-"word" string whose every position is the SAME token, so
// the interactive verify (which asks for two RANDOM positions) always expects the
// same answer regardless of which positions crypto/rand picks. mnemonicCeremony
// only splits on whitespace + compares — it does not BIP-39-validate — so this is a
// valid driver for the verify branch.
const uniformMnemonic = "alpha alpha alpha alpha alpha alpha alpha alpha alpha alpha alpha alpha"

// TestMnemonicCeremonyUsesInjectedStream is the KNOWN-3/TC-1 regression: the
// interactive ceremony reads its confirmation input from the INJECTED stream (not
// os.Stdin). A correct two-word re-entry returns echoInResult=false (the seed was
// shown + verified on the terminal, so the result redacts it), matching is
// case-insensitive + whitespace-trimmed, and a wrong word is a confirmation_required
// error.
func TestMnemonicCeremonyUsesInjectedStream(t *testing.T) {
	var out strings.Builder

	// (a) Correct re-entry (case-insensitive + surrounding whitespace) => verified,
	// redact from the result. The first line answers "Press Enter"; the next two
	// answer the two word prompts.
	in := strings.NewReader("\n  ALPHA \n\tAlpha\n")
	disp, err := mnemonicCeremony(&out, in, false, false, uniformMnemonic, "")
	if err != nil {
		t.Fatalf("correct ceremony: %v", err)
	}
	if disp.echoInResult {
		t.Errorf("echoInResult=true after a verified ceremony; want false (redact from result)")
	}
	if !strings.Contains(out.String(), "Mnemonic confirmed.") {
		t.Errorf("ceremony did not confirm:\n%s", out.String())
	}

	// (b) A wrong word fails with usage.confirmation_required naming the position.
	in2 := strings.NewReader("\nnotaword\nnotaword\n")
	_, err2 := mnemonicCeremony(&out, in2, false, false, uniformMnemonic, "")
	if err2 == nil {
		t.Fatal("wrong word should fail the ceremony")
	}
	var de *domain.Error
	if !errors.As(err2, &de) || de.Code != "usage.confirmation_required" {
		t.Fatalf("wrong-word err=%v, want usage.confirmation_required", err2)
	}
}
