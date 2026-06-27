package mcpserver

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// server_test.go is the §6.1/§6.6/§6.8 unit suite for the transport-agnostic Server:
//   - New registers EXACTLY the §6.1 tools (count + name set), and the
//     deliberately-excluded set is genuinely ABSENT (the non-regressable security
//     boundary — a prompt-injected agent cannot raise its own limits, export a key,
//     or repoint the backend because no such tool exists, §6.1).
//   - the §6.6 error model maps the one domain.Error taxonomy onto the MCP tool-error
//     mechanism (toolError pass-through; dualSignal flags the tx.wait_timeout case
//     needing BOTH IsError and structured Out).
//   - the §6.8 transport switch accepts stdio only in v1; http is rejected with a
//     forward-pointing domain.Error, and an unknown transport is a usage error.

// wantTools is the EXACT tool surface from the §6.1 table (the frozen contract the
// golden + this test pin). Order-independent: compared as a set.
var wantTools = []string{
	"balance", "utxo_list", "wallet_list", "wallet_show", "address_list", "fee",
	"verify", "convert",
	"tx_status", "tx_wait", "tx_list",
	"policy_show", "policy_check",
	"send", "tx_speedup", "tx_cancel", "address_new", "sign_message",
}

// excludedTools is the recorded denylist of the §6.1 "Deliberately NOT tools" set.
// If ANY of these is ever registered, the security boundary regressed: policy
// mutation (raise own limits), wallet create/import/export (exfiltrate/plant a key),
// backend mutation (repoint the node), keystore passphrase change, network mutation.
// These MUST never be reachable over MCP in v1.
var excludedTools = []string{
	// policy mutations (admin-passphrase-gated; the agent never holds it)
	"policy_set", "policy_allow", "policy_deny", "policy_reset",
	"policy_change_admin_passphrase", "policy_pin", "policy_counters", "policy_verify",
	// wallet create/import/export — secret-emitting / key-exfiltration / key-planting
	"wallet_create", "wallet_import", "wallet_export",
	// backend mutations (repointing the node is an operator act)
	"backend_add", "backend_use", "backend_remove", "backend_test",
	// keystore admin
	"keystore_change_passphrase",
	// network mutations
	"network_add", "network_use", "network_remove",
	// self-referential / shell-only
	"mcp_serve", "mcp_tools", "version", "completion", "config",
}

// registeredToolNames lists every tool the server registers, via an in-memory client.
func registeredToolNames(t *testing.T) []string {
	t.Helper()
	ctx := context.Background()
	srv := New(nil) // schema/registration is type-driven; no service dialed

	clientT, serverT := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, serverT, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "server-test", Version: "0.0.0"}, nil)
	cs, err := client.Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	names := make([]string, 0, len(res.Tools))
	for _, tl := range res.Tools {
		names = append(names, tl.Name)
	}
	sort.Strings(names)
	return names
}

func TestNewRegistersExactlyTheToolSurface(t *testing.T) {
	got := registeredToolNames(t)
	if len(got) != len(wantTools) {
		t.Fatalf("registered %d tools, want EXACTLY %d (§6.1): %v", len(got), len(wantTools), got)
	}

	gotSet := make(map[string]bool, len(got))
	for _, n := range got {
		gotSet[n] = true
	}
	for _, want := range wantTools {
		if !gotSet[want] {
			t.Errorf("missing §6.1 tool %q (registered: %v)", want, got)
		}
	}
	// And nothing EXTRA beyond the canonical names (catches an unplanned addition).
	wantSet := make(map[string]bool, len(wantTools))
	for _, n := range wantTools {
		wantSet[n] = true
	}
	for _, n := range got {
		if !wantSet[n] {
			t.Errorf("UNEXPECTED tool %q registered; the surface is frozen at the §6.1 tools", n)
		}
	}
}

// TestExcludedToolsAreAbsent is the recorded, non-regressable security boundary
// (§6.1): no policy mutation, wallet create/import/export, backend/network mutation,
// or keystore passphrase change is reachable over MCP.
func TestExcludedToolsAreAbsent(t *testing.T) {
	got := registeredToolNames(t)
	gotSet := make(map[string]bool, len(got))
	for _, n := range got {
		gotSet[n] = true
	}
	for _, banned := range excludedTools {
		if gotSet[banned] {
			t.Errorf("SECURITY BOUNDARY VIOLATION: excluded tool %q is registered; the MCP surface must NOT expose it (§6.1 — a prompt-injected agent must not raise its own limits, export a key, or repoint the backend through the tool channel)", banned)
		}
	}
	// policy_show + policy_check (read-only) ARE on the surface — assert they stayed
	// reachable (the ONE narrow policy window an agent gets, read-only).
	for _, want := range []string{"policy_show", "policy_check"} {
		if !gotSet[want] {
			t.Errorf("%s (read-only) must be exposed (§6.1)", want)
		}
	}
}

// TestServeRejectsHTTP pins the §6.8 v1 transport contract: stdio is the only accepted
// transport; http is rejected with a forward-pointing usage.* domain.Error (so v1.1
// flips it on with a new file + enum value, not a refactor); an unknown transport is a
// usage error. (stdio is not exercised here — it would block on the real transport;
// the in-memory pipe + the cli serve smoke cover the serving path.)
func TestServeRejectsHTTP(t *testing.T) {
	srv := New(nil)

	err := Serve(context.Background(), srv, "http")
	if err == nil {
		t.Fatal("Serve(..., \"http\") returned nil; v1 must REJECT the http transport (§6.8)")
	}
	if code := domain.AsError(err).Code; !strings.HasPrefix(code, "usage.") {
		t.Errorf("http transport rejection code = %q, want a forward-pointing usage.* code", code)
	}
	if domain.AsError(err).Exit != domain.ExitUsage {
		t.Errorf("http transport rejection exit = %d, want %d (USAGE)", domain.AsError(err).Exit, domain.ExitUsage)
	}

	err = Serve(context.Background(), srv, "carrier-pigeon")
	if err == nil {
		t.Fatal("Serve(..., unknown) returned nil; an unknown transport must be a usage error")
	}
	if code := domain.AsError(err).Code; !strings.HasPrefix(code, "usage.") {
		t.Errorf("unknown transport rejection code = %q, want a usage.* code", code)
	}
}

// TestServeHTTPSeamRefuses pins the reserved v1.1 ServeHTTP seam (§6.8): the signature
// exists so the auth hook + HTTP handler have a home in v1.1, but the v1 body REFUSES
// (no net/http server is started). This guards that the seam is declared and inert,
// not accidentally wired.
func TestServeHTTPSeamRefuses(t *testing.T) {
	srv := New(nil)
	err := ServeHTTP(context.Background(), srv, HTTPOptions{Addr: "127.0.0.1:0"})
	if err == nil {
		t.Fatal("ServeHTTP returned nil in v1; the HTTP transport ships in v1.1 and must refuse now (§6.8)")
	}
	if code := domain.AsError(err).Code; !strings.HasPrefix(code, "usage.") {
		t.Errorf("ServeHTTP refusal code = %q, want a usage.* code", code)
	}
}

// TestToolErrorPassThrough pins §6.6: toolError passes a *domain.Error straight
// through (so domain.Error.Error() — the JSON envelope byte-identical to the CLI
// --json error — is what the SDK packs into the tool-error TextContent), and returns
// nil on success.
func TestToolErrorPassThrough(t *testing.T) {
	if got := toolError(nil); got != nil {
		t.Errorf("toolError(nil) = %v, want nil (success path)", got)
	}

	in := domain.New("policy.denied.tx_limit", "over the per-tx limit")
	got := toolError(in)
	if got == nil {
		t.Fatal("toolError(domain.Error) = nil, want the error passed through")
	}
	de := domain.AsError(got)
	if de.Code != "policy.denied.tx_limit" {
		t.Errorf("code = %q, want policy.denied.tx_limit (passed through unchanged)", de.Code)
	}
	if de.Exit != domain.ExitPolicyDenied {
		t.Errorf("exit = %d, want %d (the CLI exit for this code, preserved)", de.Exit, domain.ExitPolicyDenied)
	}
	// A raw (non-domain) error becomes a generic internal domain.Error.
	rawWrapped := domain.AsError(toolError(errors.New("boom")))
	if rawWrapped.Code != domain.CodeInternal {
		t.Errorf("raw error code = %q, want %q", rawWrapped.Code, domain.CodeInternal)
	}
}

// TestDualSignalCodes pins §6.6: only tx.wait_timeout — the outcome that needs BOTH
// IsError AND a structured *domain.TxResult (a still-pending tx at the deadline, with
// a resume command) — is dual-signal. A plain policy denial / ref.not_found is NOT
// dual-signal (it returns a plain tool-error), and nil is never dual-signal.
func TestDualSignalCodes(t *testing.T) {
	if !dualSignal(domain.New(domain.CodeTxWaitTimeout, "still pending at the deadline")) {
		t.Errorf("dualSignal(tx.wait_timeout) = false, want true (needs IsError + structured Out)")
	}
	for _, code := range []string{"policy.denied.tx_limit", "ref.not_found", "usage.invalid", "tx.broadcast_rejected"} {
		if dualSignal(domain.New(code, "x")) {
			t.Errorf("dualSignal(%q) = true, want false (a plain tool-error, not dual-signal)", code)
		}
	}
	if dualSignal(nil) {
		t.Error("dualSignal(nil) = true, want false")
	}
}
