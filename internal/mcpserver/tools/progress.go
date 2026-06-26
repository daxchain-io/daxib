package tools

import (
	"context"

	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// progress.go is the docs/PLAN.md §6.5 long-running-op wiring: it maps the core's
// single domain.EventSink onto MCP progress notifications, gated on the client's
// progress token. Long-running tools (tx_wait, and a wait-bearing send) BLOCK and
// stream — the handler holds the call open and emits one notification per
// intermediate domain.Event while the agent's CallTool future stays pending.
//
// It lives in package tools (the handlers call progressSink unqualified; mcpserver
// imports tools, so tools cannot import mcpserver — this is the cycle-free home).
//
// daxib's domain.Event is intentionally minimal — a Stage tag + a human Message,
// no typed payload — so the mapping is a single notification per event. The final
// result is always the tool's return value; progress is best-effort (a dropped
// notification never affects the outcome, which is fully captured in the return
// value).

// progressSink builds the domain.EventSink a write/stream handler hands to the
// service method. When the client sent no progress token it returns nil — the core
// tolerates a nil sink (emit is nil-safe) and the final result still carries the
// full picture, so omitting progress is never an error. Otherwise it returns a sink
// that forwards each domain.Event to the client over the call's session, keyed by
// the progress token.
func progressSink(ctx context.Context, req *mcp.CallToolRequest) domain.EventSink {
	if req == nil || req.Session == nil || req.Params == nil {
		return nil
	}
	token := req.Params.GetProgressToken()
	if token == nil {
		return nil // no progress token ⇒ no-op sink
	}
	return func(ev domain.Event) {
		// Best-effort: a notify failure (client drop, slow consumer) must not affect
		// the tool outcome, which is fully captured in the return value.
		_ = req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
			ProgressToken: token,
			Message:       ev.Stage + ": " + ev.Message, // the same vocabulary the CLI renders on stderr
		})
	}
}
