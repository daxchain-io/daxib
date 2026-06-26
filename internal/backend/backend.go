// Package backend is daxib's chain-read provider seam (docs/PLAN.md §6): the
// single load-bearing test seam between the service core and a Bitcoin backend.
// It is the Bitcoin sibling of daxie's internal/chain — same structure, swapped
// chain: a backend.Client interface, a fully-resolved backend.Options that Dial
// consumes, and TWO real implementations behind it — a Bitcoin Core JSON-RPC
// adapter (stateless: scantxoutset / getblockcount / estimatesmartfee /
// sendrawtransaction) and an Esplora REST adapter (mempool.space-style). A
// hand-written fake (backend/fake) lets service-pipeline tests run with no node.
//
// backend is a provider leaf. It imports domain (the error taxonomy + the UTXO/
// fee/tx value types) and stdlib net/http only — NEVER service, a frontend, or
// the config store. The Endpoint→Options assembly (secret-reference resolution,
// default-per-network selection) lives in service, the composition root that
// legally imports both backend and config. Resolved secrets exist only
// transiently inside an Options value at dial time; they are never persisted
// (the §7.5 contract).
//
// Only TipHeight + UTXOs are wired into M3 features (backend test + balance +
// utxo list); FeeEstimates / Broadcast / TxStatus are implemented in FULL on both
// adapters (real calls, not stubs that lie) for the forward tx milestone and are
// covered by the lighter adapter tests.
package backend

import (
	"context"
	"time"

	"github.com/daxchain-io/daxib/internal/domain"
)

// Client is the chain-read boundary — THE universal test seam (docs/PLAN.md §6).
// Every method is a thin, real adapter call (Core JSON-RPC or Esplora REST); the
// same contract is satisfied by backend/fake. The pair is kept honest by the
// adapter httptest suites + the fake, which assert the identical confirmation /
// aggregation semantics so they cannot drift.
type Client interface {
	// TipHeight returns the backend's current best block height (getblockcount /
	// GET /blocks/tip/height). It backs the confirmation math, the `backend test`
	// probe, and is run inside Dial as the reachability check.
	TipHeight(ctx context.Context) (int64, error)

	// UTXOs returns every confirmed-or-mempool unspent output paying to any of
	// addrs (Core: one scantxoutset over a desc set; Esplora: GET
	// /address/:addr/utxo per address). Height is the confirming block (0 =
	// unconfirmed) and Confirmations is computed from the tip. This is the core of
	// `balance` and `utxo list`.
	UTXOs(ctx context.Context, addrs []string) ([]domain.UTXO, error)

	// FeeEstimates returns the sat/vByte fee table by confirmation target
	// (estimatesmartfee / GET /fee-estimates). Plumbed by a later tx milestone.
	FeeEstimates(ctx context.Context) (domain.FeeEstimates, error)

	// Broadcast submits a raw, fully-signed transaction (sendrawtransaction /
	// POST /tx) and returns its txid. Implemented now for the later tx milestone.
	Broadcast(ctx context.Context, rawTx []byte) (txid string, err error)

	// TxStatus returns a transaction's confirmation state
	// (getrawtransaction|gettxout / GET /tx/:txid). Implemented now for later.
	TxStatus(ctx context.Context, txid string) (domain.TxStatus, error)

	// Close releases the underlying HTTP client/connection. Safe to call once.
	Close()
}

// DefaultTimeout is the per-dial / per-request timeout applied when
// Options.Timeout is zero.
const DefaultTimeout = 30 * time.Second

// Options is the FULLY RESOLVED backend endpoint that Dial consumes. service
// assembles it from a stored config.Endpoint at dial time:
//
//   - URL has its ${env:}/${file:} references ALREADY resolved (the resolved
//     value lives only for the lifetime of this struct and is never persisted,
//     §7.5);
//   - RPCUser / RPCPassword are ref-resolved Core auth (or a CookieFile path the
//     adapter reads itself);
//   - DisplayURL is the MASKED, log-safe URL service supplies for error messages
//     and data envelopes.
//
// config NEVER builds this value (config→backend is not a sanctioned edge, §7.5).
type Options struct {
	// Type selects the adapter (core | esplora).
	Type domain.BackendType

	// URL is the resolved endpoint URL (no ${…} references remain). For Core it is
	// the JSON-RPC HTTP endpoint; for Esplora the REST base URL. The resolved URL
	// may carry a secret (an embedded credential) and is therefore NEVER put into
	// a user/log-facing string — messages use DisplayURL.
	URL string

	// DisplayURL is the MASKED form of the endpoint URL, safe to log and embed in
	// errors/data envelopes. When empty, Dial derives a masked form from URL so a
	// resolved secret is never leaked even on a probe path.
	DisplayURL string

	// Network is the declared network name, carried for error messages and data
	// envelopes (it does not affect dialing in M3).
	Network domain.Network

	// Core auth (resolved). One of RPCUser+RPCPassword OR CookieFile.
	RPCUser     string
	RPCPassword string
	CookieFile  string // path to a bitcoind .cookie file (read at request time)

	// Timeout bounds the dial and each request. Zero = DefaultTimeout.
	Timeout time.Duration
}

// timeout returns the effective per-dial/request timeout.
func (o Options) timeout() time.Duration {
	if o.Timeout <= 0 {
		return DefaultTimeout
	}
	return o.Timeout
}

// displayURL returns the masked, log-safe endpoint URL. It prefers the
// service-supplied DisplayURL (the masked RAW ref); when empty it derives a
// masked form from the RESOLVED URL so a leaked credential is never surfaced.
func (o Options) displayURL() string {
	if o.DisplayURL != "" {
		return o.DisplayURL
	}
	return maskResolvedURL(o.URL)
}
