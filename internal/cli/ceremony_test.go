package cli

import (
	"errors"
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
			disp, err := mnemonicCeremony(nil, tc.yes, tc.jsonMode, canonicalMnemonic, "")
			if err != nil {
				t.Fatalf("ceremony: %v", err)
			}
			if disp.echoInResult != tc.wantEchoResult {
				t.Errorf("echoInResult = %v, want %v", disp.echoInResult, tc.wantEchoResult)
			}
		})
	}
}
