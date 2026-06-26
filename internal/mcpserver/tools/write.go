package tools

import (
	"context"

	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// write.go holds the funds-moving / mutation tools (docs/PLAN.md §6.1): send (the
// one money mover) and address_new (the receive affordance). The central guarantee
// (§6.4): send routes through the SAME svc.SendTx the CLI `tx send` runs — the only
// path that coin-selects → calls policy.Reserve (the chokepoint, INSIDE the service
// method, after the build and before the keystore signs) → signs → broadcasts. This
// package cannot import policy/keys, so it has no way to SKIP the check — guardrails
// bind MCP identically by construction. A prompt-injected agent cannot raise its own
// limits through the tool channel.
//
// The sendCeremony below is the ONE place a send request is touched before the call,
// and it touches ONLY frontend-ceremony fields:
//
//   - Yes = true. The interactive y/N is a TTY convenience that cannot exist over a
//     tool call; wiring it constant-true is the FULL extent of "MCP is
//     non-interactive," NOT a safety waiver (§6.4). It is the --yes confirmation
//     skip, never a policy waiver — Yes carries json:"-", so it is NEVER an
//     agent-visible schema field: the agent cannot, and need not, pass it. The
//     policy check consumes none of it (policy.Reserve runs regardless).
//   - Wait.Enabled = true. Over MCP, waiting for confirmation is the DEFAULT (agents
//     want the confirmed result + the settle-to-actuals, §6.4/§6.5). An agent that
//     supplies wait.confirmations / wait.timeout tunes the wait; those ride through
//     untouched. dry_run rides the schema field untouched (an agent that previews).
//
// The ceremony NEVER touches To/Amount/FeeRate/Speed/Wallet — those are the agent's
// inputs, passed verbatim.

// sendSink is the shape of the send service method: (ctx, SendRequest, EventSink) →
// (TxResult, error). daxib's send takes no Principal (the core is single-tenant in
// v1).
type sendSink func(context.Context, domain.SendRequest, domain.EventSink) (domain.TxResult, error)

// addSend registers the send tool — the §6.4 central guarantee. The handler is the
// SAME call the CLI runs: same request struct, same service method, so
// coin-select → policy.Reserve → sign → broadcast runs inside fn; this package
// cannot import policy/keys, so it cannot skip the check. sendCeremony stamps the
// §6.4 invariants onto the request just before the call — the ONLY place a send
// request is touched, and it touches only frontend-ceremony fields (Yes/Wait).
// A tx.wait_timeout returns BOTH IsError:true AND the structured TxResult (§6.6);
// any other failure (a policy denial, insufficient funds, a bad address) returns a
// plain tool error.
func addSend(srv *mcp.Server, name, desc string, fn sendSink) {
	mcp.AddTool(srv, withSchemas[domain.SendRequest, domain.TxResult](writeToolDef(name, desc)),
		func(ctx context.Context, req *mcp.CallToolRequest, in domain.SendRequest) (*mcp.CallToolResult, *domain.TxResult, error) {
			sendCeremony(&in) // §6.4 ceremony: Yes/Wait; never a policy field
			out, err := fn(ctx, in, progressSink(ctx, req))
			if dualSignal(err) {
				return dualResult(err), &out, nil // BOTH IsError + structured Out
			}
			if err != nil {
				return nil, nil, toolError(err)
			}
			return nil, &out, nil
		})
}

// sendCeremony wires the §6.4 invariants onto a SendRequest. Over MCP the
// confirmation is implicit (Yes) and waiting for finality is the default
// (Wait.Enabled). dry_run, fee_rate, speed, and an explicit wait tuning all ride
// the schema fields untouched.
func sendCeremony(in *domain.SendRequest) {
	in.Yes = true
	in.Wait.Enabled = true
}

// addressNewFn is the receive-affordance service method: (ctx, AddressNewRequest) →
// (AddressNewResult, error). It DERIVES (and records) the next address from the
// stored xpub — no passphrase, no signing — so it is NOT in the signing set; it uses
// the write annotations only because it MUTATES the wallet's watermark (it advances
// the next-index). There is no ceremony and no dual-signal.
type addressNewFn func(context.Context, domain.AddressNewRequest) (domain.AddressNewResult, error)

// addAddressNew registers the address_new tool — the agent's sanctioned path to a
// fresh invoice address (mirroring how daxie exposes receive's new-address but NOT
// raw account derivation, §6.1). It binds the SAME domain.AddressNewRequest the CLI
// `address new` binds and returns domain.AddressNewResult.
func addAddressNew(srv *mcp.Server, name, desc string, fn addressNewFn) {
	mcp.AddTool(srv, withSchemas[domain.AddressNewRequest, domain.AddressNewResult](writeToolDef(name, desc)),
		func(ctx context.Context, _ *mcp.CallToolRequest, in domain.AddressNewRequest) (*mcp.CallToolResult, *domain.AddressNewResult, error) {
			out, err := fn(ctx, in)
			if err != nil {
				return nil, nil, toolError(err)
			}
			return nil, &out, nil
		})
}
