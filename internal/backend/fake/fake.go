// Package fake is the one hand-written backend.Client fake — the load-bearing
// test seam for service-pipeline tests (the Bitcoin sibling of daxie's
// chain/fake). Tests inject it instead of touching the network; it programs
// per-method results (or function hooks) and records every call for assertions.
// No mock framework.
//
// Its behaviour is kept honest against the real adapters by the shared
// confirmation/aggregation assertions the httptest suites run, so the fake cannot
// drift from real semantics.
package fake

import (
	"context"
	"sync"

	"github.com/daxchain-io/daxib/internal/backend"
	"github.com/daxchain-io/daxib/internal/domain"
)

// Call is one recorded method invocation.
type Call struct {
	Method string
	Args   []any
}

// Client is a programmable backend.Client fake. Zero values are sensible; prefer
// New() for an initialized recorder. All fields are read under a mutex so the
// fake is safe to drive from concurrent goroutines.
type Client struct {
	mu sync.Mutex

	// Programmable state for the wired M3 paths.
	Tip         int64
	UTXOsByAddr map[string][]domain.UTXO // address -> its UTXOs
	Fees        domain.FeeEstimates

	// Function hooks for the methods later milestones drive.
	UTXOsFn     func(ctx context.Context, addrs []string) ([]domain.UTXO, error)
	BroadcastFn func(ctx context.Context, raw []byte) (string, error)
	TxStatusFn  func(ctx context.Context, txid string) (domain.TxStatus, error)

	// Calls records every invocation in order.
	Calls []Call

	// Err, when non-nil, is returned by EVERY method (a backend-unreachable
	// simulation). It takes precedence over programmed results and hooks.
	Err error
}

// compile-time guarantee the fake satisfies the real interface.
var _ backend.Client = (*Client)(nil)

// New returns a fake with an initialized UTXO map and recorder.
func New() *Client {
	return &Client{UTXOsByAddr: map[string][]domain.UTXO{}}
}

func (c *Client) record(method string, args ...any) {
	c.Calls = append(c.Calls, Call{Method: method, Args: args})
}

// CallsFor returns the recorded calls to a method, in order.
func (c *Client) CallsFor(method string) []Call {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []Call
	for _, call := range c.Calls {
		if call.Method == method {
			out = append(out, call)
		}
	}
	return out
}

func (c *Client) TipHeight(ctx context.Context) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.record("TipHeight")
	if c.Err != nil {
		return 0, c.Err
	}
	return c.Tip, nil
}

func (c *Client) UTXOs(ctx context.Context, addrs []string) ([]domain.UTXO, error) {
	c.mu.Lock()
	fn := c.UTXOsFn
	err := c.Err
	c.record("UTXOs", addrs)
	byAddr := c.UTXOsByAddr
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if fn != nil {
		return fn(ctx, addrs)
	}
	var out []domain.UTXO
	for _, a := range addrs {
		out = append(out, byAddr[a]...)
	}
	return out, nil
}

func (c *Client) FeeEstimates(ctx context.Context) (domain.FeeEstimates, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.record("FeeEstimates")
	if c.Err != nil {
		return domain.FeeEstimates{}, c.Err
	}
	return c.Fees, nil
}

func (c *Client) Broadcast(ctx context.Context, raw []byte) (string, error) {
	c.mu.Lock()
	fn := c.BroadcastFn
	err := c.Err
	c.record("Broadcast", raw)
	c.mu.Unlock()
	if err != nil {
		return "", err
	}
	if fn != nil {
		return fn(ctx, raw)
	}
	return "", nil
}

func (c *Client) TxStatus(ctx context.Context, txid string) (domain.TxStatus, error) {
	c.mu.Lock()
	fn := c.TxStatusFn
	err := c.Err
	c.record("TxStatus", txid)
	c.mu.Unlock()
	if err != nil {
		return domain.TxStatus{}, err
	}
	if fn != nil {
		return fn(ctx, txid)
	}
	return domain.TxStatus{Txid: txid}, nil
}

func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.record("Close")
}
