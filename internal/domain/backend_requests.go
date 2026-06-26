package domain

// backend_requests.go is the wire contract for the M3 backend + balance + utxo
// surface: the request/result structs the cli/mcp frontends pass to (and receive
// from) the service. They mirror daxie's rpc/network request shapes, swapping the
// Ethereum endpoint for a Bitcoin backend (Core RPC / Esplora) and the
// account-balance number for the UTXO-derived confirmed/unconfirmed split. No
// struct here holds a float; sats are int64 and BTC is rendered as a decimal
// STRING (never a float64) so a balance round-trips exactly.

// BackendType is the backend implementation kind: a Bitcoin Core JSON-RPC node or
// an Esplora REST server.
type BackendType string

const (
	// BackendCore is a Bitcoin Core JSON-RPC backend (stateless; scantxoutset).
	BackendCore BackendType = "core"
	// BackendEsplora is an Esplora REST backend (mempool.space-style).
	BackendEsplora BackendType = "esplora"
)

// ParseBackendType validates a backend type name.
func ParseBackendType(s string) (BackendType, error) {
	switch s {
	case string(BackendCore):
		return BackendCore, nil
	case string(BackendEsplora):
		return BackendEsplora, nil
	default:
		return "", Newf(CodeUsage+".backend_type",
			"unknown backend type %q: want one of core, esplora", s)
	}
}

// ── backend add ──────────────────────────────────────────────────────────────

// BackendAddRequest is the wire input for `backend add <name>`. The auth secret
// values arrive as RAW ${env:}/${file:} references (or, discouraged, literals) and
// are stored verbatim — they are resolved transiently in the service at dial time,
// never persisted resolved (the §7.5 secret-ref contract).
type BackendAddRequest struct {
	Name    string      `json:"name"`
	Network Network     `json:"network"`
	Type    BackendType `json:"type"`
	URL     string      `json:"url"`
	// Core auth (one of rpcuser+rpcpassword OR a cookie file). Stored as raw refs.
	RPCUser     string `json:"rpcuser,omitempty"`
	RPCPassword string `json:"rpcpassword,omitempty"` // ${env:}/${file:} ref
	RPCCookie   string `json:"rpccookie,omitempty"`   // path to a .cookie file (may be a ${file:} indirection target)
}

// BackendAddResult is the wire output for `backend add`.
type BackendAddResult struct {
	Name    string      `json:"name"`
	Network Network     `json:"network"`
	Type    BackendType `json:"type"`
	URL     string      `json:"url"` // MASKED
}

// ── backend list ───────────────────────────────────────────────────────────

// BackendListRequest is the wire input for `backend list` (optional network
// filter).
type BackendListRequest struct {
	Network Network `json:"network,omitempty"`
}

// BackendSummary is one row of `backend list`. URL is MASKED. Default marks the
// network's default backend.
type BackendSummary struct {
	Name    string      `json:"name"`
	Network Network     `json:"network"`
	Type    BackendType `json:"type"`
	URL     string      `json:"url"` // MASKED
	Default bool        `json:"default,omitempty"`
}

// BackendListResult is the wire output for `backend list`.
type BackendListResult struct {
	Backends []BackendSummary `json:"backends"`
}

// ── backend use ────────────────────────────────────────────────────────────

// BackendUseRequest is the wire input for `backend use <name>`.
type BackendUseRequest struct {
	Name string `json:"name"`
}

// BackendUseResult is the wire output for `backend use`.
type BackendUseResult struct {
	Name    string  `json:"name"`
	Network Network `json:"network"`
}

// ── backend remove ─────────────────────────────────────────────────────────

// BackendRemoveRequest is the wire input for `backend remove <name>`.
type BackendRemoveRequest struct {
	Name string `json:"name"`
}

// BackendRemoveResult is the wire output for `backend remove`.
type BackendRemoveResult struct {
	Name       string  `json:"name"`
	ClearedFor Network `json:"cleared_for,omitempty"` // network whose default was cleared
}

// ── backend test ───────────────────────────────────────────────────────────

// BackendTestRequest is the wire input for `backend test [<name>]`. An empty Name
// tests the active network's default backend.
type BackendTestRequest struct {
	Name string `json:"name,omitempty"`
}

// BackendTestResult is the wire output for `backend test`: a successful dial +
// TipHeight call, with the observed tip height and the round-trip latency in
// milliseconds.
type BackendTestResult struct {
	Name      string      `json:"name"`
	Network   Network     `json:"network"`
	Type      BackendType `json:"type"`
	URL       string      `json:"url"` // MASKED
	TipHeight int64       `json:"tip_height"`
	LatencyMS int64       `json:"latency_ms"`
}

// ── balance ────────────────────────────────────────────────────────────────

// BalanceRequest is the wire input for `balance`. Wallet defaults through the
// usual --wallet > DAXIB_WALLET > default-wallet precedence. UTXOs toggles the
// per-UTXO enumeration in the result.
type BalanceRequest struct {
	Wallet string `json:"wallet,omitempty"`
	UTXOs  bool   `json:"utxos,omitempty"`
}

// BalanceResult is the wire output for `balance`. Amounts are satoshis (int64)
// plus an exact BTC decimal STRING (never a float). Confirmed/Unconfirmed split
// the spendable set; Total is their sum. When the request set UTXOs, the
// individual coins are enumerated.
type BalanceResult struct {
	Wallet         string    `json:"wallet"`
	Network        Network   `json:"network"`
	Backend        string    `json:"backend"`
	ConfirmedSat   int64     `json:"confirmed_sat"`
	UnconfirmedSat int64     `json:"unconfirmed_sat"`
	TotalSat       int64     `json:"total_sat"`
	ConfirmedBTC   string    `json:"confirmed_btc"`
	UnconfirmedBTC string    `json:"unconfirmed_btc"`
	TotalBTC       string    `json:"total_btc"`
	UTXOCount      int       `json:"utxo_count"`
	TipHeight      int64     `json:"tip_height"`
	UTXOs          []UTXORow `json:"utxos,omitempty"`
}

// UTXORow is one enumerated UTXO in a balance/utxo-list result.
type UTXORow struct {
	Outpoint      string `json:"outpoint"` // "txid:vout"
	Address       string `json:"address"`
	ValueSat      int64  `json:"value_sat"`
	ValueBTC      string `json:"value_btc"`
	Confirmations int64  `json:"confirmations"`
}

// ── utxo list ──────────────────────────────────────────────────────────────

// UTXOListRequest is the wire input for `utxo list`.
type UTXOListRequest struct {
	Wallet string `json:"wallet,omitempty"`
}

// UTXOListResult is the wire output for `utxo list`: the per-UTXO breakdown.
type UTXOListResult struct {
	Wallet    string    `json:"wallet"`
	Network   Network   `json:"network"`
	Backend   string    `json:"backend"`
	TipHeight int64     `json:"tip_height"`
	UTXOs     []UTXORow `json:"utxos"`
	TotalSat  int64     `json:"total_sat"`
	TotalBTC  string    `json:"total_btc"`
}
