package mcpserver

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// audit_test.go pins the §6 audit middleware: ONE structured line per inbound MCP
// request to stderr (method, tool name for a tools/call, outcome), never arguments
// or secrets — the operator's record of what an agent attempted over MCP.

func auditCapture(t *testing.T, base mcp.MethodHandler, method string, req mcp.Request) string {
	t.Helper()
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	if _, err := auditMiddleware(log)(base)(context.Background(), method, req); err != nil && domain.AsError(err) == nil {
		t.Fatalf("unexpected non-domain error: %v", err)
	}
	return buf.String()
}

// TestAuditMiddleware_ToolError logs the tool name and the in-band tool-error outcome.
func TestAuditMiddleware_ToolError(t *testing.T) {
	base := func(context.Context, string, mcp.Request) (mcp.Result, error) {
		return &mcp.CallToolResult{IsError: true}, nil
	}
	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "send"}}
	out := auditCapture(t, base, "tools/call", req)
	for _, want := range []string{"method=tools/call", "tool=send", "outcome=tool_error"} {
		if !strings.Contains(out, want) {
			t.Errorf("audit line %q missing %q", out, want)
		}
	}
}

// TestAuditMiddleware_Error logs the outcome and the domain error code (a policy
// denial in particular leaves a trail).
func TestAuditMiddleware_Error(t *testing.T) {
	base := func(context.Context, string, mcp.Request) (mcp.Result, error) {
		return nil, domain.New("policy.denied.day_limit", "over the rolling-24h limit")
	}
	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "send"}}
	out := auditCapture(t, base, "tools/call", req)
	for _, want := range []string{"tool=send", "outcome=error", "code=policy.denied.day_limit"} {
		if !strings.Contains(out, want) {
			t.Errorf("audit line %q missing %q", out, want)
		}
	}
}

// TestAuditMiddleware_OkNonTool logs ok and omits the tool field for a non-tool
// method (tools/list).
func TestAuditMiddleware_OkNonTool(t *testing.T) {
	base := func(context.Context, string, mcp.Request) (mcp.Result, error) {
		return &mcp.ListToolsResult{}, nil
	}
	out := auditCapture(t, base, "tools/list", &mcp.ListToolsRequest{})
	if !strings.Contains(out, "outcome=ok") || !strings.Contains(out, "method=tools/list") {
		t.Errorf("audit line %q missing ok/method", out)
	}
	if strings.Contains(out, "tool=") {
		t.Errorf("audit line %q should not carry a tool field for a non-tool method", out)
	}
}

// TestAuditMiddleware_OneLinePerCall asserts EXACTLY one audit line is emitted per
// inbound request (not zero, not two) — the operator's per-call record.
func TestAuditMiddleware_OneLinePerCall(t *testing.T) {
	base := func(context.Context, string, mcp.Request) (mcp.Result, error) {
		return &mcp.CallToolResult{}, nil
	}
	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "balance"}}
	out := auditCapture(t, base, "tools/call", req)
	if n := strings.Count(strings.TrimRight(out, "\n"), "\n") + 1; n != 1 {
		t.Errorf("audit emitted %d lines for one call, want exactly 1:\n%s", n, out)
	}
}
