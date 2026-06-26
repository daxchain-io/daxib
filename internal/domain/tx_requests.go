package domain

import (
	"encoding/json"
	"time"
)

// tx_requests.go is the wire contract for the M4 transaction-send surface: the
// request/result structs the cli/mcp frontends pass to (and receive from) the
// service for `tx send`, `tx status`, `tx list`, `tx wait`, and `fee`. They
// mirror daxie's tx request shapes, Bitcoin-flavored: NO float field — every
// amount is int64 satoshis plus an exact BTC decimal STRING; the fee rate is an
// integer sat/vByte. The lifecycle status is TxState (string enum) — distinct
// from the chain-read value type TxStatus in chain.go (a tx's confirmation state
// reported by the backend), which keeps its name.

// TxState is the journaled send-lifecycle status surfaced in a TxResult/TxRow. It
// is the frontend-facing projection of the journal's record status (§5.1):
// signed → broadcast → confirmed/failed, plus pending (mempool-seen, 0-conf) and
// timeout (a --wait deadline; NOT a failure — resumable).
type TxState string

const (
	// TxStateSigned: journaled BEFORE broadcast; the raw bytes are persisted for an
	// idempotent rebroadcast (the lost-broadcast window).
	TxStateSigned TxState = "signed"
	// TxStateBroadcast: the backend accepted the tx (or it was already known); the
	// chain has (or will have) it.
	TxStateBroadcast TxState = "broadcast"
	// TxStatePending: the tx is in the mempool, 0 confirmations (a --wait poll
	// observed it but the confirmation target is not yet met).
	TxStatePending TxState = "pending"
	// TxStateConfirmed: confirmed at >= the requested confirmations (terminal).
	TxStateConfirmed TxState = "confirmed"
	// TxStateFailed: a permanent broadcast reject (terminal).
	TxStateFailed TxState = "failed"
	// TxStateTimeout: a --wait deadline hit with the tx still pending — NOT a
	// failure; the caller can resume with `daxib tx wait <txid>`.
	TxStateTimeout TxState = "timeout"
)

// Duration is a wire-friendly time.Duration that marshals to a Go duration STRING
// (e.g. "10m0s") so a --json result round-trips a human-readable timeout rather
// than an opaque nanosecond integer. It mirrors daxie's domain Duration.
type Duration struct {
	D time.Duration
}

// MarshalJSON renders the duration as its String() form (or "" when zero).
func (d Duration) MarshalJSON() ([]byte, error) {
	if d.D == 0 {
		return json.Marshal("")
	}
	return json.Marshal(d.D.String())
}

// UnmarshalJSON parses a duration string back (best-effort; an empty/zero string
// is the zero duration). It accepts either a string ("10m") or a number of
// nanoseconds for forward tolerance.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		if s == "" {
			d.D = 0
			return nil
		}
		parsed, perr := time.ParseDuration(s)
		if perr != nil {
			return perr
		}
		d.D = parsed
		return nil
	}
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	d.D = time.Duration(n)
	return nil
}

// WaitOpts bundles the --wait/--confirmations/--timeout options threaded into a
// send (and the standalone `tx wait`). Confirmations is a pointer so "flag unset"
// is distinguishable from an explicit 0 (the service then applies its default
// confirmation target).
type WaitOpts struct {
	Enabled       bool     `json:"enabled,omitempty"`
	Confirmations *int64   `json:"confirmations,omitempty"`
	Timeout       Duration `json:"timeout,omitempty"`
}

// SendRequest is the wire input for `tx send`. Amount is the raw `--amount`
// string (parsed by ParseAmountToSats in the service so the bad-amount error is
// label-aware). FeeRate is the raw `--fee-rate` string ("" → estimate by Speed).
// Yes is the frontend confirmation flag (never serialized).
type SendRequest struct {
	Wallet  string   `json:"wallet,omitempty"`
	To      string   `json:"to"`
	Amount  string   `json:"amount"`
	FeeRate string   `json:"fee_rate,omitempty"`
	Speed   string   `json:"speed,omitempty"`
	DryRun  bool     `json:"dry_run,omitempty"`
	Yes     bool     `json:"-"`
	Wait    WaitOpts `json:"wait,omitempty"`
}

// SpeedupRequest is the wire input for `tx speedup <txid>` (RBF/BIP-125): build a
// replacement of an unconfirmed, RBF-signaling, wallet-originated send spending the
// SAME inputs with a HIGHER fee, paying the SAME recipient. FeeRate is the raw
// `--fee-rate` string ("" → a sensible bump above the original / the backend fast
// estimate). Yes is the frontend confirmation flag (never serialized).
type SpeedupRequest struct {
	Wallet  string   `json:"wallet,omitempty"`
	Txid    string   `json:"txid"`
	FeeRate string   `json:"fee_rate,omitempty"`
	Wait    WaitOpts `json:"wait,omitempty"`
	Yes     bool     `json:"-"`
}

// CancelRequest is the wire input for `tx cancel <txid>` (RBF/BIP-125): build a
// replacement that redirects ALL funds to a fresh wallet-owned change address
// (voiding the original payment) with a higher fee. Same shape as SpeedupRequest.
type CancelRequest struct {
	Wallet  string   `json:"wallet,omitempty"`
	Txid    string   `json:"txid"`
	FeeRate string   `json:"fee_rate,omitempty"`
	Wait    WaitOpts `json:"wait,omitempty"`
	Yes     bool     `json:"-"`
}

// TxInputRef is one selected input in a TxResult (outpoint + the address it pays
// from + its value).
type TxInputRef struct {
	Outpoint string `json:"outpoint"` // "txid:vout"
	Address  string `json:"address"`
	ValueSat int64  `json:"value_sat"`
}

// TxOutputRef is one output in a TxResult. Change marks the wallet-owned change
// output.
type TxOutputRef struct {
	Address  string `json:"address"`
	ValueSat int64  `json:"value_sat"`
	Change   bool   `json:"change,omitempty"`
}

// TxResult is the wire output for `tx send` / `tx status` / `tx wait`. Amounts
// are satoshis (int64) plus an exact BTC decimal STRING. Status is the lifecycle
// TxState. RawTxHex is the fully-signed transaction (hex, no 0x prefix); it is
// emitted under --json for an agent that wants to re-broadcast or inspect.
type TxResult struct {
	Txid          string        `json:"txid,omitempty"`
	Network       Network       `json:"network"`
	Wallet        string        `json:"wallet,omitempty"`
	To            string        `json:"to"`
	AmountSat     int64         `json:"amount_sat"`
	AmountBTC     string        `json:"amount_btc"`
	FeeSat        int64         `json:"fee_sat"`
	FeeBTC        string        `json:"fee_btc"`
	FeeRate       int64         `json:"fee_rate"` // sat/vByte
	Vsize         int64         `json:"vsize"`
	ChangeSat     int64         `json:"change_sat,omitempty"`
	ChangeBTC     string        `json:"change_btc,omitempty"`
	ChangeAddress string        `json:"change_address,omitempty"`
	Inputs        []TxInputRef  `json:"inputs,omitempty"`
	Outputs       []TxOutputRef `json:"outputs,omitempty"`
	Status        TxState       `json:"status"`
	Confirmations int64         `json:"confirmations,omitempty"`
	BlockHeight   int64         `json:"block_height,omitempty"`
	JournalID     string        `json:"journal_id,omitempty"`
	RawTxHex      string        `json:"raw_tx_hex,omitempty"`
	Resume        string        `json:"resume,omitempty"`
	DryRun        bool          `json:"dry_run,omitempty"`
	// Replacement is true when this result is an RBF replacement (`tx speedup`/`tx
	// cancel`); ReplacesTxid is the original tx's txid the replacement supersedes.
	Replacement  bool   `json:"replacement,omitempty"`
	ReplacesTxid string `json:"replaces_txid,omitempty"`
}

// TxStatusRequest is the wire input for `tx status <txid>`.
type TxStatusRequest struct {
	Txid string `json:"txid"`
}

// WaitRequest is the wire input for `tx wait <txid>`.
type WaitRequest struct {
	Txid          string   `json:"txid"`
	Confirmations *int64   `json:"confirmations,omitempty"`
	Timeout       Duration `json:"timeout,omitempty"`
}

// TxListRequest is the wire input for `tx list` (optional wallet filter, optional
// limit; 0 = no limit).
type TxListRequest struct {
	Wallet string `json:"wallet,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}

// TxRow is one row of `tx list` (newest-first).
type TxRow struct {
	JournalID     string  `json:"journal_id"`
	Txid          string  `json:"txid,omitempty"`
	Status        TxState `json:"status"`
	To            string  `json:"to"`
	AmountSat     int64   `json:"amount_sat"`
	AmountBTC     string  `json:"amount_btc"`
	FeeSat        int64   `json:"fee_sat"`
	Vsize         int64   `json:"vsize"`
	Confirmations int64   `json:"confirmations,omitempty"`
	TS            string  `json:"ts"`
}

// TxListResult is the wire output for `tx list`.
type TxListResult struct {
	Network Network `json:"network"`
	Wallet  string  `json:"wallet,omitempty"`
	Txs     []TxRow `json:"txs"`
}

// FeeRequest is the wire input for the `fee` noun (mark the selected --speed
// recommendation).
type FeeRequest struct {
	Speed string `json:"speed,omitempty"`
}

// FeeQuotesResult is the wire output for `fee`: the backend's sat/vByte estimates
// by speed tier + the per-target table, with the floor-applied recommendation the
// --speed selects. SelectedRate is the headline sat/vByte a script reads.
type FeeQuotesResult struct {
	Network      Network       `json:"network"`
	Backend      string        `json:"backend"`
	Slow         int64         `json:"slow"`
	Normal       int64         `json:"normal"`
	Fast         int64         `json:"fast"`
	ByTarget     map[int]int64 `json:"by_target,omitempty"`
	FloorSatVB   int64         `json:"floor_sat_vb"`
	Selected     string        `json:"selected"`
	SelectedRate int64         `json:"selected_rate"`
}
