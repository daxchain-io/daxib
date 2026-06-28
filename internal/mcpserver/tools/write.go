package tools

import (
	"context"

	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/service"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// write.go holds the funds-moving / mutation tools (docs/ARCHITECTURE.md §6.1): send (the
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
//   - Yes = true. The interactive y/N confirmation prompt (AF-3, the CLI's TTY
//     gate for tx send/speedup/cancel) cannot exist over a tool call; wiring it
//     constant-true is the FULL extent of "MCP is non-interactive," NOT a safety
//     waiver (§6.4). It is the --yes confirmation skip, never a policy waiver — Yes
//     carries json:"-", so it is NEVER an agent-visible schema field: the agent
//     cannot, and need not, pass it. The policy check consumes none of it
//     (policy.Reserve runs regardless).
//   - Wait.Enabled = true. Over MCP, waiting for confirmation is the DEFAULT (agents
//     want the confirmed result + the settle-to-actuals, §6.4/§6.5). An agent that
//     supplies wait.confirmations / wait.timeout tunes the wait; those ride through
//     untouched. dry_run rides the schema field untouched (an agent that previews).
//
// The ceremony NEVER touches To/Amount/FeeRate/Speed/Wallet — those are the agent's
// inputs, passed verbatim.

// sendSink is the shape of the send service method: (ctx, Principal,
// SendRequest, EventSink) → (TxResult, error). The MCP frontend passes
// domain.LocalMCP() so an agent-initiated send is journaled Source:"mcp"
// (issue #11).
type sendSink func(context.Context, domain.Principal, domain.SendRequest, domain.EventSink) (domain.TxResult, error)

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
			out, err := fn(ctx, domain.LocalMCP(), in, progressSink(ctx, req))
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
type addressNewFn func(context.Context, domain.Principal, domain.AddressNewRequest) (domain.AddressNewResult, error)

// addAddressNew registers the address_new tool — the agent's sanctioned path to a
// fresh invoice address (mirroring how daxie exposes receive's new-address but NOT
// raw account derivation, §6.1). It binds the SAME domain.AddressNewRequest the CLI
// `address new` binds and returns domain.AddressNewResult.
func addAddressNew(srv *mcp.Server, name, desc string, fn addressNewFn) {
	mcp.AddTool(srv, withSchemas[domain.AddressNewRequest, domain.AddressNewResult](writeToolDef(name, desc)),
		func(ctx context.Context, _ *mcp.CallToolRequest, in domain.AddressNewRequest) (*mcp.CallToolResult, *domain.AddressNewResult, error) {
			out, err := fn(ctx, domain.LocalMCP(), in)
			if err != nil {
				return nil, nil, toolError(err)
			}
			return nil, &out, nil
		})
}

// speedupFn / cancelFn are the RBF-replacement service shapes (GAP-2): same shape as
// send — (ctx, In, EventSink) → (TxResult, error) — because a speedup/cancel is a
// fresh coin-select → policy.Reserve → sign → broadcast inside the service method.
type speedupFn func(context.Context, domain.Principal, domain.SpeedupRequest, domain.EventSink) (domain.TxResult, error)
type cancelFn func(context.Context, domain.Principal, domain.CancelRequest, domain.EventSink) (domain.TxResult, error)

// addSpeedup registers the tx_speedup tool (GAP-2). It rides the SAME guardrails as
// send: the service method coin-selects the replacement and runs policy.Reserve
// before the keystore signs — this package cannot import policy/keys, so it cannot
// skip the check. The §6.4 ceremony (Yes constant-true, Wait default-on) applies for
// the same reasons it does to send; a tx.wait_timeout dual-signals (IsError + Out).
func addSpeedup(srv *mcp.Server, name, desc string, fn speedupFn) {
	mcp.AddTool(srv, withSchemas[domain.SpeedupRequest, domain.TxResult](writeToolDef(name, desc)),
		func(ctx context.Context, req *mcp.CallToolRequest, in domain.SpeedupRequest) (*mcp.CallToolResult, *domain.TxResult, error) {
			in.Yes = true
			in.Wait.Enabled = true
			out, err := fn(ctx, domain.LocalMCP(), in, progressSink(ctx, req))
			if dualSignal(err) {
				return dualResult(err), &out, nil
			}
			if err != nil {
				return nil, nil, toolError(err)
			}
			return nil, &out, nil
		})
}

// addCancel registers the tx_cancel tool (GAP-2). Same guardrails + ceremony as
// addSpeedup (the replacement is policy-checked before signing).
func addCancel(srv *mcp.Server, name, desc string, fn cancelFn) {
	mcp.AddTool(srv, withSchemas[domain.CancelRequest, domain.TxResult](writeToolDef(name, desc)),
		func(ctx context.Context, req *mcp.CallToolRequest, in domain.CancelRequest) (*mcp.CallToolResult, *domain.TxResult, error) {
			in.Yes = true
			in.Wait.Enabled = true
			out, err := fn(ctx, domain.LocalMCP(), in, progressSink(ctx, req))
			if dualSignal(err) {
				return dualResult(err), &out, nil
			}
			if err != nil {
				return nil, nil, toolError(err)
			}
			return nil, &out, nil
		})
}

// signMessageFn is the BIP-322 sign shape (GAP-2): (ctx, MessageSignRequest,
// MessageSignInput) → (MessageSignResult, error). The MessageSignInput carries the
// frontend's message + passphrase channels; over MCP the message rides the request's
// `message` field (no float, no secret) and the keystore passphrase resolves from the
// out-of-band env channel (PassphraseStdin/File left zero), EXACTLY like send. It is
// keystore-gated, not policy-gated: it unlocks a key but moves no funds.
type signMessageFn func(context.Context, domain.Principal, domain.MessageSignRequest, service.MessageSignInput) (domain.MessageSignResult, error)

// addSignMessage registers the sign_message tool (GAP-2). The handler binds the SAME
// domain.MessageSignRequest the CLI `sign message` binds and constructs the
// MessageSignInput from the request's message (the passphrase comes from the env
// channel server-side, never a tool argument). Yes is json:"-" and irrelevant (sign
// has no confirmation gate); we leave the input's passphrase channels zero so the
// service falls through to the env channel.
func addSignMessage(srv *mcp.Server, name, desc string, fn signMessageFn) {
	mcp.AddTool(srv, withSchemas[domain.MessageSignRequest, domain.MessageSignResult](signToolDef(name, desc)),
		func(ctx context.Context, _ *mcp.CallToolRequest, in domain.MessageSignRequest) (*mcp.CallToolResult, *domain.MessageSignResult, error) {
			out, err := fn(ctx, domain.LocalMCP(), in, service.MessageSignInput{Message: []byte(in.Message)})
			if err != nil {
				return nil, nil, toolError(err)
			}
			return nil, &out, nil
		})
}

// psbtSignFn is the PSBT-sign shape: (ctx, PSBTSignRequest, PSBTSignInput) →
// (PSBTResult, error). Like send it unlocks a key AND authorizes a spend (it runs
// eng.Reserve INSIDE the service method before any byte is signed), so it is the
// PSBT analog of send: this package cannot import policy/keys, so it cannot skip the
// check. The keystore passphrase resolves from the out-of-band env channel (the
// input's passphrase channels left zero), EXACTLY like sign_message; Yes is
// constant-true (the §6.4 confirmation ceremony cannot exist over a tool call — NOT
// a policy waiver).
type psbtSignFn func(context.Context, domain.Principal, domain.PSBTSignRequest, service.PSBTSignInput) (domain.PSBTResult, error)

func addPSBTSign(srv *mcp.Server, name, desc string, fn psbtSignFn) {
	mcp.AddTool(srv, withSchemas[domain.PSBTSignRequest, domain.PSBTResult](signToolDef(name, desc)),
		func(ctx context.Context, _ *mcp.CallToolRequest, in domain.PSBTSignRequest) (*mcp.CallToolResult, *domain.PSBTResult, error) {
			in.Yes = true // §6.4 ceremony: the TTY confirmation cannot exist over a tool call
			out, err := fn(ctx, domain.LocalMCP(), in, service.PSBTSignInput{})
			if err != nil {
				return nil, nil, toolError(err)
			}
			return nil, &out, nil
		})
}

// psbtBroadcastFn is the PSBT-broadcast shape: (ctx, PSBTBroadcastRequest,
// EventSink) → (TxResult, error). It moves bytes onto the wire (the policy charge
// already happened at sign; this commits the cross-linked reservation). The §6.4
// ceremony applies (Yes constant-true, Wait default-on); a tx.wait_timeout
// dual-signals (IsError + Out).
type psbtBroadcastFn func(context.Context, domain.Principal, domain.PSBTBroadcastRequest, domain.EventSink) (domain.TxResult, error)

func addPSBTBroadcast(srv *mcp.Server, name, desc string, fn psbtBroadcastFn) {
	mcp.AddTool(srv, withSchemas[domain.PSBTBroadcastRequest, domain.TxResult](writeToolDef(name, desc)),
		func(ctx context.Context, req *mcp.CallToolRequest, in domain.PSBTBroadcastRequest) (*mcp.CallToolResult, *domain.TxResult, error) {
			in.Yes = true
			in.Wait.Enabled = true
			out, err := fn(ctx, domain.LocalMCP(), in, progressSink(ctx, req))
			if dualSignal(err) {
				return dualResult(err), &out, nil
			}
			if err != nil {
				return nil, nil, toolError(err)
			}
			return nil, &out, nil
		})
}
