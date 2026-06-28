package tools

import (
	"context"

	"github.com/daxchain-io/daxib/internal/service"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// empty.go holds the two read-only policy verbs on the agent surface (docs/ARCHITECTURE.md
// §6.1): policy_show and policy_check. Every policy MUTATION is deliberately NOT a
// tool (admin-passphrase-gated, the agent never holds it) — these two READ the
// active policy so an agent can pre-flight a transfer.
//
// Two service shapes land here, recorded:
//
//   - PolicyShow's signature is (ctx) → (service.PolicyShowResult, error): it takes
//     NO request struct and NO Principal. The MCP input schema needs a concrete Go
//     type to infer from, so the tool's In is Empty (an empty object the SDK infers
//     as {"type":"object"}). The agent calls it with {} or no arguments.
//   - PolicyCheck takes service.PolicyCheckInput (a CLI-flag struct with NO json
//     tags). Inferring directly from it would surface Go-cased required fields, so
//     the tool binds PolicyCheckArgs — a thin tools-local input with snake_case
//     json + jsonschema tags — and field-copies it into PolicyCheckInput (pure
//     glue, no logic). The Out is service.PolicyCheckResult.
//
// Both Out types are SERVICE types, not domain types: mcpserver/tools legally
// imports service, so the inferred output schema for these two comes from service
// structs. The golden test pins them.

// Empty is the input type for policy_show, whose service method takes no request
// struct. The SDK infers it as an empty object schema; the agent supplies no
// arguments. It is a real exported type so the golden/parity tests can name it.
type Empty struct{}

// PolicyCheckArgs is the agent-facing input for policy_check. It carries snake_case
// json + jsonschema tags (PolicyCheckInput, a CLI-flag struct, has none), so the
// inferred schema matches the conventions of the other tools. It field-copies into
// service.PolicyCheckInput — the SAME struct the CLI `policy check` builds — with
// zero transformation.
type PolicyCheckArgs struct {
	To      string `json:"to" jsonschema:"recipient Bitcoin address for the active network"`
	Amount  string `json:"amount" jsonschema:"amount to check, a decimal BTC string or an integer-sat string"`
	FeeRate int64  `json:"fee_rate,omitempty" jsonschema:"assumed fee rate in sat/vByte (optional)"`
	FeeSat  int64  `json:"fee_sat,omitempty" jsonschema:"assumed absolute fee in sats (optional)"`
}

// addPolicyShow registers the read-only policy_show tool. PolicyShow takes (ctx)
// with no request, so the handler ignores the Empty input and returns the SAME
// service.PolicyShowResult the CLI `policy show --json` renders.
func addPolicyShow(srv *mcp.Server, name, desc string, fn func(context.Context) (service.PolicyShowResult, error)) {
	mcp.AddTool(srv, withSchemas[Empty, service.PolicyShowResult](readToolDef(name, desc)),
		func(ctx context.Context, _ *mcp.CallToolRequest, _ Empty) (*mcp.CallToolResult, *service.PolicyShowResult, error) {
			out, err := fn(ctx)
			if err != nil {
				return nil, nil, toolError(err)
			}
			return nil, &out, nil
		})
}

// addPolicyCheck registers the read-only policy_check (dry-run Evaluate) tool. It
// binds PolicyCheckArgs, copies it into service.PolicyCheckInput, and returns the
// SAME service.PolicyCheckResult the CLI builds. A denial is reported IN the result
// (allowed:false + the dotted code), exactly as the service method returns it — a
// dry-run reserves nothing, so there is no policy.denied error on this path.
func addPolicyCheck(srv *mcp.Server, name, desc string, fn func(context.Context, service.PolicyCheckInput) (service.PolicyCheckResult, error)) {
	mcp.AddTool(srv, withSchemas[PolicyCheckArgs, service.PolicyCheckResult](readToolDef(name, desc)),
		func(ctx context.Context, _ *mcp.CallToolRequest, in PolicyCheckArgs) (*mcp.CallToolResult, *service.PolicyCheckResult, error) {
			out, err := fn(ctx, service.PolicyCheckInput{
				To: in.To, Amount: in.Amount, FeeRate: in.FeeRate, FeeSat: in.FeeSat,
			})
			if err != nil {
				return nil, nil, toolError(err)
			}
			return nil, &out, nil
		})
}
