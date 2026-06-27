package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/daxchain-io/daxib/internal/domain"
)

// mcp_test.go is the command-level suite for `daxib mcp` (docs/PLAN.md §6.7/§6.8):
// the `mcp tools` introspection (the compact table + footer; --json the tools/list
// payload; <name> a single tool's schema) and the `mcp serve --transport` switch
// (stdio accepted, http rejected). These build the server lazily (mcpserver.New
// touches no provider), so they run with no network and only the keystore env wired.

// TestMcpToolsHumanFooter pins §6.7: `mcp tools` prints the TOOL/KIND/DESCRIPTION
// table + the read/sign-count footer, and surfaces the §6.1 send + a read tool.
func TestMcpToolsHumanFooter(t *testing.T) {
	isolateKeystore(t)
	stdout, stderr, code := execCLI(t, "mcp", "tools")
	if code != 0 {
		t.Fatalf("mcp tools exit = %d, want 0; stderr=%s", code, stderr)
	}
	for _, want := range []string{"TOOL", "KIND", "DESCRIPTION", "send", "balance", "policy_show"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("mcp tools output missing %q:\n%s", want, stdout)
		}
	}
	// The footer states the contract (tools count, read/sign split, transport).
	if !strings.Contains(stdout, "Transport: stdio") || !strings.Contains(stdout, "tools (") {
		t.Errorf("mcp tools footer missing the §6.7 contract line:\n%s", stdout)
	}
	// The exclusion boundary must be visible in the surface: no mutation tool appears.
	for _, banned := range []string{"policy_set", "wallet_export", "backend_add", "wallet_create"} {
		if strings.Contains(stdout, banned) {
			t.Errorf("mcp tools surface lists an EXCLUDED tool %q (§6.1 boundary):\n%s", banned, stdout)
		}
	}
}

// TestMcpToolsJSONCount pins §6.7: `mcp tools --json` is the tools/list payload, and
// it carries exactly the §6.1 tool set, each with an inferred input + output schema.
func TestMcpToolsJSONCount(t *testing.T) {
	isolateKeystore(t)
	stdout, stderr, code := execCLI(t, "--json", "mcp", "tools")
	if code != 0 {
		t.Fatalf("mcp tools --json exit = %d, want 0; stderr=%s", code, stderr)
	}
	var payload struct {
		Tools []struct {
			Name         string          `json:"name"`
			Description  string          `json:"description"`
			InputSchema  json.RawMessage `json:"inputSchema"`
			OutputSchema json.RawMessage `json:"outputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("mcp tools --json is not valid JSON: %v\n%s", err, stdout)
	}
	// The §6.1 surface is 18 tools after GAP-2 added tx_speedup, tx_cancel,
	// sign_message, verify, and convert. The authoritative roster is
	// internal/mcpserver/tools.ToolNames (the cli may not import it across the arch
	// lattice); the golden test there pins the full set.
	if len(payload.Tools) != 18 {
		t.Fatalf("mcp tools --json has %d tools, want 18 (§6.1)", len(payload.Tools))
	}
	for _, tl := range payload.Tools {
		if tl.Name == "" || len(tl.InputSchema) == 0 || len(tl.OutputSchema) == 0 {
			t.Errorf("tool %q missing name/inputSchema/outputSchema in the tools/list payload", tl.Name)
		}
	}
}

// TestMcpToolsSingle pins §6.7: `mcp tools <name>` prints one tool's full schema; an
// unknown name is a clean ref.not_found (exit 10).
func TestMcpToolsSingle(t *testing.T) {
	isolateKeystore(t)
	stdout, stderr, code := execCLI(t, "mcp", "tools", "send")
	if code != 0 {
		t.Fatalf("mcp tools send exit = %d, want 0; stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "send") || !strings.Contains(stdout, "input schema") || !strings.Contains(stdout, "output schema") {
		t.Errorf("mcp tools send did not print the full single-tool schema:\n%s", stdout)
	}

	_, _, code = execCLI(t, "mcp", "tools", "no_such_tool")
	if code != int(domain.ExitNotFound) {
		t.Errorf("mcp tools <unknown> exit = %d, want %d (NOT_FOUND)", code, domain.ExitNotFound)
	}
}

// TestMcpServeRejectsHTTP pins §6.8: `mcp serve --transport http` is rejected in v1
// with a usage-class error (exit 2), and an unknown transport is likewise a usage
// error. The http pre-check runs BEFORE opening the service, so it is fast and
// side-effect-free (no keystore unlock) — and the rejection is the same domain.Error
// mcpserver.Serve would return.
func TestMcpServeRejectsHTTP(t *testing.T) {
	isolateKeystore(t)
	_, stderr, code := execCLI(t, "mcp", "serve", "--transport", "http")
	if code != int(domain.ExitUsage) {
		t.Fatalf("mcp serve --transport http exit = %d, want %d (USAGE); stderr=%s", code, domain.ExitUsage, stderr)
	}
	if !strings.Contains(stderr, "v1.1") {
		t.Errorf("http rejection should point forward to v1.1: %s", stderr)
	}

	_, _, code = execCLI(t, "mcp", "serve", "--transport", "websocket")
	if code != int(domain.ExitUsage) {
		t.Errorf("mcp serve --transport websocket exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

// TestMcpToolsDoesNotDialBackend pins §6.7's "never dials a backend": with NO backend
// configured at all, `mcp tools` still succeeds — introspection is purely type-driven
// over an in-memory pipe.
func TestMcpToolsDoesNotDialBackend(t *testing.T) {
	isolateKeystore(t)
	// Point config/state at empty temp dirs so no backend is configured.
	t.Setenv("DAXIB_CONFIG", t.TempDir())
	t.Setenv("DAXIB_STATE_DIR", t.TempDir())
	_, stderr, code := execCLI(t, "mcp", "tools")
	if code != 0 {
		t.Fatalf("mcp tools with no backend configured exit = %d, want 0 (must not dial); stderr=%s", code, stderr)
	}
}
