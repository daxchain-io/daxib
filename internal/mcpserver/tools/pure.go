package tools

import (
	"context"

	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// pure.go holds the read-only handler wrappers (docs/PLAN.md §6.2; no signing, no
// policy reservation). They bind args → the SAME domain request → the SAME service
// method → result. They contain NO business logic; the only difference between them
// is the SHAPE of the service method (most reads are (ctx, In)→(Out, error); tx_wait
// takes an EventSink and returns a TxResult that can dual-signal a timeout), so there
// is one wrapper per shape and register.go picks the right one. The Out is returned
// as a pointer so the SDK's typed-nil handling marshals a real object.

// readPlainFn is a read/metadata service method with NO EventSink and NO Principal:
// (ctx, In) → (Out, error). Balance/UTXOList/WalletList/WalletShow/AddressList/Fee/
// ListTxs all match.
type readPlainFn[In, Out any] func(context.Context, In) (Out, error)

func addReadPlain[In, Out any](srv *mcp.Server, name, desc string, fn readPlainFn[In, Out]) {
	mcp.AddTool(srv, withSchemas[In, Out](readToolDef(name, desc)),
		func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, *Out, error) {
			out, err := fn(ctx, in)
			if err != nil {
				return nil, nil, toolError(err)
			}
			return nil, &out, nil
		})
}

// txStatusFn is the tx_status shape: (ctx, In) → (TxResult, error). tx_status folds
// the journal record + one backend re-check (it NEVER broadcasts). It is read-class
// — no EventSink, no dual-signal (a status read of a known/unknown txid is either a
// TxResult or a plain ref.not_found error).
type txStatusFn[In any] func(context.Context, In) (domain.TxResult, error)

func addTxStatus[In any](srv *mcp.Server, name, desc string, fn txStatusFn[In]) {
	mcp.AddTool(srv, withSchemas[In, domain.TxResult](readToolDef(name, desc)),
		func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, *domain.TxResult, error) {
			out, err := fn(ctx, in)
			if err != nil {
				return nil, nil, toolError(err)
			}
			return nil, &out, nil
		})
}

// txWaitFn is the tx_wait shape: (ctx, In, EventSink) → (TxResult, error). tx_wait
// runs the wait machine on a known txid — it streams progress but SIGNS NOTHING
// (it may rebroadcast stored bytes, the lost-broadcast window, but never produces a
// new signature). At the deadline it surfaces tx.wait_timeout, which is dual-signal:
// the agent reads BOTH the error code AND the TxResult (status + a resume command).
type txWaitFn[In any] func(context.Context, In, domain.EventSink) (domain.TxResult, error)

func addTxWait[In any](srv *mcp.Server, name, desc string, fn txWaitFn[In]) {
	mcp.AddTool(srv, withSchemas[In, domain.TxResult](readToolDef(name, desc)),
		func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, *domain.TxResult, error) {
			out, err := fn(ctx, in, progressSink(ctx, req))
			if dualSignal(err) {
				return dualResult(err), &out, nil // BOTH IsError + structured Out (§6.6)
			}
			if err != nil {
				return nil, nil, toolError(err)
			}
			return nil, &out, nil
		})
}
