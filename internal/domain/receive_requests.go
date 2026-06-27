package domain

// receive_requests.go is the wire contract for `daxib receive` — the inbound
// counterpart that completes the agent-to-agent payment loop (the Bitcoin sibling
// of daxie's receive engine, reframed for the UTXO model). The command resolves or
// derives a receive address, emits it UP FRONT, then BLOCKS polling the backend
// until an inbound payment to that address is seen and reaches the confirmation
// target. Triple-duty (CLI flags, MCP schema, in-process call); every amount is an
// integer count of satoshis (the no-float rule), BTC only ever a decimal string.

// ReceiveRequest is the inbound-detection request. An empty Amount is the
// any-inbound path (any confirmed inbound satisfies it); a non-empty Amount waits
// for the cumulative confirmed inbound to reach it. --new derives a FRESH receive
// index (a keystore meta.json write — requires a writable keystore); otherwise the
// wallet's next-unused receive address is PEEKED (no watermark burn) and listened
// on. Timeout ZERO ⇒ UNBOUNDED invoice wait (set one for agents).
type ReceiveRequest struct {
	// Wallet is the wallet to derive/peek the receive address from ("" = the
	// default wallet, --wallet > DAXIB_WALLET > meta default).
	Wallet string `json:"wallet,omitempty" jsonschema:"wallet to receive on; defaults to the active wallet"`
	// New derives a FRESH receive address via keys.DeriveNext (a keystore meta.json
	// write — requires a writable keystore). Without it the next-unused receive
	// address is PEEKED (no watermark advance) so a no-op listen burns no index.
	New bool `json:"new,omitempty" jsonschema:"derive a fresh receive address (requires a writable keystore)"`
	// Amount is the target: human BTC ("0.001") or "<n>sat". "" ⇒ any-inbound.
	Amount string `json:"amount,omitempty" jsonschema:"target amount, e.g. 0.001 (BTC) or 150000sat; omit for any-inbound"`
	// Confirmations overrides the confirmation target. nil ⇒ DefaultReceiveConfirmations.
	Confirmations *uint64 `json:"confirmations,omitempty" jsonschema:"confirmation target; omit for the default (1)"`
	// Timeout bounds the wait. ZERO ⇒ UNBOUNDED invoice wait.
	Timeout Duration `json:"timeout,omitempty" jsonschema:"Go duration, e.g. 30m; ZERO/omit = UNBOUNDED wait (set one for agents)"`
	// PollInterval overrides the backend poll cadence. ZERO ⇒ DefaultReceivePoll.
	PollInterval Duration `json:"poll_interval,omitempty" jsonschema:"poll cadence, e.g. 5s; omit for the default"`
}

// DefaultReceiveConfirmations is the confirmation target when the request leaves
// it unset. One confirmation is the daxib default (a single block is enough for
// most agent flows; an operator raises it via --confirmations).
const DefaultReceiveConfirmations uint64 = 1

// ReceiveTarget is the resolved completion target echoed on the listening event.
// AmountSat is 0 for the any-inbound mode; Timeout is *string so an unbounded wait
// renders as JSON null and a bounded wait as the duration string.
type ReceiveTarget struct {
	AmountSat     int64   `json:"amount_sat"`
	AmountBTC     string  `json:"amount_btc"`
	Confirmations uint64  `json:"confirmations"`
	Timeout       *string `json:"timeout"` // null ⇒ unbounded
}

// DetectedPayment is one inbound UTXO paying the receive address, carried in the
// result and the detected/confirmed events. ValueSat is the output amount;
// Confirmations is its depth at the time of the event.
type DetectedPayment struct {
	Txid          string `json:"txid"`
	Vout          uint32 `json:"vout"`
	ValueSat      int64  `json:"value_sat"`
	ValueBTC      string `json:"value_btc"`
	Confirmations int64  `json:"confirmations"`
}

// ReceiveResult is the terminal result for the in-process / MCP caller. The same
// outcome is also carried in the final complete/timeout event so a CLI agent reads
// it from the stream without inspecting $?. Status is "complete" (Exit 0) or
// "timeout" (Exit 8).
type ReceiveResult struct {
	Address      string            `json:"address"`
	Wallet       string            `json:"wallet"`
	Network      Network           `json:"network"`
	Target       ReceiveTarget     `json:"target"`
	Status       string            `json:"status"` // "complete" | "timeout"
	ConfirmedSat int64             `json:"confirmed_sat"`
	ConfirmedBTC string            `json:"confirmed_btc"`
	RemainingSat int64             `json:"remaining_sat"`
	Payments     []DetectedPayment `json:"payments"`
	Exit         int               `json:"exit"` // 0 complete | 8 timeout
}

// ── the receive event stream (its own sink, distinct from the send/wait Event) ──

// ReceiveEventKind is the discriminant on a ReceiveEvent. The listening event is
// emitted UP FRONT (carrying the address); detected/confirming/confirmed track one
// payment's progress; complete (exit 0) and timeout (exit 8) are the only TERMINAL
// kinds.
type ReceiveEventKind string

const (
	RecvListening ReceiveEventKind = "listening"
	RecvDetected  ReceiveEventKind = "detected"  // an inbound payment seen (possibly still unconfirmed)
	RecvConfirmed ReceiveEventKind = "confirmed" // a payment reached the confirmation target
	RecvComplete  ReceiveEventKind = "complete"  // terminal: the target is satisfied (exit 0)
	RecvTimeout   ReceiveEventKind = "timeout"   // terminal: the deadline hit pending (exit 8)
)

// ReceiveEvent is one record on the receive stream. The renderer marshals it to a
// stable NDJSON line under --json (the receive stream is the one sanctioned
// exception to single-object-on-stdout) or a short human line otherwise. Unset
// numeric fields render as their zero (a decimal string for amounts).
type ReceiveEvent struct {
	Kind    ReceiveEventKind `json:"event"`
	Address string           `json:"address,omitempty"`
	Network string           `json:"network,omitempty"`
	Target  *ReceiveTarget   `json:"target,omitempty"`
	Txid    string           `json:"txid,omitempty"`
	// Vout, ValueSat and Confirmations are ALWAYS present (no omitempty): the receive
	// NDJSON stream is a documented contract, so a zero must not silently drop a key
	// (RECV-2). They mirror the already-stable confirmed_* fields.
	Vout          uint32 `json:"vout"`
	ValueSat      int64  `json:"value_sat"`
	ValueBTC      string `json:"value_btc"`
	Confirmations int64  `json:"confirmations"`
	ConfirmedSat  int64  `json:"confirmed_sat"`
	ConfirmedBTC  string `json:"confirmed_btc"`
	RemainingSat  int64  `json:"remaining_sat"`
	Exit          *int   `json:"exit,omitempty"` // set on the terminal complete/timeout events
}

// ReceiveEventSink is the streaming callback the receive use case emits to. A nil
// sink is a no-op (the service guards every emit), so a non-streaming caller (the
// MCP affordance path, later) can pass nil and read only the terminal result.
type ReceiveEventSink func(ReceiveEvent)
