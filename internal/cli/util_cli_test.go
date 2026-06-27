package cli

import (
	"strings"
	"testing"
)

// util_cli_test.go is the command-level smoke for the utility/registry nouns added
// over the same core: completion, convert, contacts, and config. It drives the real
// Cobra tree through execCLI so the actual arg parsing, --json shape, and exit
// mapping are exercised.

// TestCompletionBashEmitsScript proves `daxib completion bash` emits a non-empty
// completion script (the command is registered + not hidden + generates from the
// live tree). It needs no keystore/service.
func TestCompletionBashEmitsScript(t *testing.T) {
	stdout, stderr, code := execCLI(t, "completion", "bash")
	if code != 0 {
		t.Fatalf("completion bash exit=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "# bash completion") && !strings.Contains(stdout, "complete ") {
		t.Fatalf("completion bash output does not look like a bash completion script:\n%s", firstLines(stdout, 5))
	}
	// The script references the real binary name, proving it is generated from the tree.
	if !strings.Contains(stdout, "daxib") {
		t.Errorf("completion script does not mention daxib")
	}

	// Every documented shell emits SOMETHING; an unknown shell is a usage error.
	for _, sh := range []string{"zsh", "fish", "powershell"} {
		out, _, c := execCLI(t, "completion", sh)
		if c != 0 || strings.TrimSpace(out) == "" {
			t.Errorf("completion %s: exit=%d empty=%v", sh, c, strings.TrimSpace(out) == "")
		}
	}
	if _, _, c := execCLI(t, "completion", "tcsh"); c != 2 {
		t.Errorf("completion tcsh exit=%d; want 2 (usage)", c)
	}
}

// TestConvertCLI proves `daxib convert` prints the bare scalar value (human) for a
// few representative conversions.
func TestConvertCLI(t *testing.T) {
	isolateKeystore(t) // convert opens the service; isolate state so no real files are touched

	cases := []struct {
		args []string
		want string
	}{
		{[]string{"convert", "0.001btc"}, "100000"},
		{[]string{"convert", "100000sat"}, "0.00100000"},
		{[]string{"convert", "0.5"}, "50000000"},
		{[]string{"convert", "1btc", "sat"}, "100000000"},
	}
	for _, tc := range cases {
		stdout, stderr, code := execCLI(t, tc.args...)
		if code != 0 {
			t.Fatalf("%v exit=%d stderr=%q", tc.args, code, stderr)
		}
		if strings.TrimSpace(stdout) != tc.want {
			t.Errorf("%v = %q; want %q", tc.args, strings.TrimSpace(stdout), tc.want)
		}
	}

	// A bad unit is a usage error (exit 2).
	if _, _, code := execCLI(t, "convert", "1btc", "gwei"); code != 2 {
		t.Errorf("convert 1btc gwei exit=%d; want 2", code)
	}
}

// firstLines returns the first n lines of s (for readable failure output).
func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
