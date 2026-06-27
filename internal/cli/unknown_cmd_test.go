package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/daxchain-io/daxib/internal/domain"
)

// unknown_cmd_test.go pins ECC-3: an UNKNOWN top-level command under --json must
// emit the {"error":{…}} JSON envelope on stderr (not the human "daxib: … (code)"
// line), regardless of whether --json precedes or follows the bogus command. Cobra
// returns the unknown-command error BEFORE it parses the persistent --json flag, so
// the funnel pre-scans argv (effectiveMode) to honor it.

// parseErrEnvelope decodes the stderr JSON error envelope, failing the test if the
// stderr is not the {"error":{…}} shape.
func parseErrEnvelope(t *testing.T, stderr string) domain.Error {
	t.Helper()
	var env struct {
		Error domain.Error `json:"error"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(stderr)), &env); err != nil {
		t.Fatalf("stderr is not the {\"error\":{…}} JSON envelope: %v\n  stderr: %q", err, stderr)
	}
	return env.Error
}

// TestUnknownCommandJSONEnvelope covers BOTH argv orderings: the --json flag after
// the bogus command, and before it. Each must produce a JSON envelope (exit USAGE).
func TestUnknownCommandJSONEnvelope(t *testing.T) {
	for _, args := range [][]string{
		{"bogus", "--json"},
		{"--json", "bogus"},
	} {
		out, stderr, code := execCLI(t, args...)
		if code != int(domain.ExitUsage) {
			t.Errorf("daxib %v exit = %d, want %d (USAGE)", args, code, domain.ExitUsage)
		}
		if out != "" {
			t.Errorf("daxib %v wrote to stdout (errors belong on stderr): %q", args, out)
		}
		// The defining ECC-3 assertion: stderr is JSON, NOT the human "daxib: …" line.
		if strings.HasPrefix(strings.TrimSpace(stderr), "daxib:") {
			t.Errorf("daxib %v emitted a HUMAN error line under --json; want the JSON envelope: %q", args, stderr)
		}
		e := parseErrEnvelope(t, stderr)
		if e.Exit != domain.ExitUsage {
			t.Errorf("daxib %v envelope exit = %d, want %d", args, e.Exit, domain.ExitUsage)
		}
		if !strings.HasPrefix(e.Code, "usage") {
			t.Errorf("daxib %v envelope code = %q, want a usage.* code", args, e.Code)
		}
	}
}

// TestUnknownCommandHumanLineWithoutJSON is the negative control: WITHOUT --json the
// unknown command still emits the human one-liner (the JSON pre-scan only ever turns
// json ON; it never forces JSON when the operator did not ask for it).
func TestUnknownCommandHumanLineWithoutJSON(t *testing.T) {
	_, stderr, code := execCLI(t, "bogus")
	if code != int(domain.ExitUsage) {
		t.Errorf("daxib bogus exit = %d, want %d", code, domain.ExitUsage)
	}
	if !strings.HasPrefix(strings.TrimSpace(stderr), "daxib:") {
		t.Errorf("daxib bogus (no --json) want the human error line, got: %q", stderr)
	}
}
