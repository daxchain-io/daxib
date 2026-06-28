// Package journal is daxib's crash-safe local transaction journal: an append-only
// JSONL record of Daxib-originated sends (one record = one line = one write(2)),
// ONE FILE PER NETWORK, guarded by cross-platform flock (via internal/fsx). IDs
// are ULIDs (in-package, see id.go). The journal is the source of truth for an
// in-flight send's signed bytes and the outpoints it consumed.
//
// It is a faithful port of daxie's internal/journal MINUS nonce.go / NonceManager
// and all policy/reservation coupling: the Bitcoin UTXO model has no nonce
// counter, so the identity-of-spend is the txid and double-spend is prevented by
// (a) the wallet send-lock serializing selection and (b) the journal recording
// which UTXO outpoints an in-flight tx consumed.
//
// The two statuses `signed` (journaled BEFORE broadcast, no recorded broadcast)
// and `broadcast` (after broadcast succeeded) are the §5.1 reconciliation
// discriminator: "no broadcast recorded ⇒ release/rebroadcast the same bytes;
// broadcast recorded ⇒ never re-build, only re-poll". This is the entire
// crash-safety proof.
//
// Dependency surface (enforced by arch_test + the depguard lattice): journal
// imports internal/domain (the Error taxonomy) and internal/fsx (atomic writes,
// flock, perms) ONLY. It NEVER imports service, backend, keys, config, or a
// frontend.
package journal

// Status is the record lifecycle. `signed` = journaled BEFORE broadcast (no
// recorded broadcast); `broadcast` = after broadcast succeeded — the §5.1
// reconciliation discriminator. The terminal set {confirmed, failed, replaced} is
// what Unresolved() filters OUT.
type Status string

const (
	// StatusSigned: journaled BEFORE broadcast; RawTx persisted; NO recorded
	// broadcast → recovery rebroadcasts the SAME bytes (idempotent).
	StatusSigned Status = "signed"
	// StatusBroadcast: sendrawtransaction accepted (or already-known) → the chain
	// has (or will have) it; txid recorded.
	StatusBroadcast Status = "broadcast"
	// StatusConfirmed: TxStatus.Confirmed at >= the target confirmations (terminal).
	StatusConfirmed Status = "confirmed"
	// StatusFailed: a permanent broadcast reject (terminal); UTXOs released for
	// re-selection.
	StatusFailed Status = "failed"
	// StatusReplaced is the reserved spelling for a future M5+ RBF bump. It is
	// DECLARED so the on-disk schema is stable, but never WRITTEN in M4.
	StatusReplaced Status = "replaced"
)

// terminalStatuses are the statuses a record never leaves: it is resolved and is
// only kept as `tx list` history. Unresolved() returns everything NOT in this set.
var terminalStatuses = map[Status]bool{
	StatusConfirmed: true,
	StatusFailed:    true,
	StatusReplaced:  true,
}

// IsTerminal reports whether s is a resolved status (Unresolved excludes these;
// compaction keeps terminal records — the journal IS `tx list` history).
func (s Status) IsTerminal() bool { return terminalStatuses[s] }

// JInput is one consumed UTXO recorded on the journal line: the outpoint it spent
// (so a concurrent send can avoid re-selecting it while the tx is unresolved),
// plus its value and address for `tx status`/`tx list` rendering.
type JInput struct {
	Txid     string `json:"txid"`
	Vout     uint32 `json:"vout"`
	ValueSat int64  `json:"value_sat"`
	Address  string `json:"address"`
}

// JOutput is one output of the journaled tx. Change marks the wallet-owned change
// output (empty Address + no Change when the change was folded into the fee).
type JOutput struct {
	Address  string `json:"address"`
	ValueSat int64  `json:"value_sat"`
	Change   bool   `json:"change,omitempty"`
}

// Record is one journal line (VERBATIM field names; one record = one line = one
// write(2)). Reads fold latest-wins-per-id; Seq is assigned under the flock at
// append time. RawTx carries the full signed wire bytes (hex, no 0x prefix)
// written at status=signed BEFORE broadcast, so recovery rebroadcasts the SAME
// bytes (idempotent).
type Record struct {
	V             int       `json:"v"`  // schema version, 1
	ID            string    `json:"id"` // ULID
	Seq           uint64    `json:"seq"`
	TS            string    `json:"ts"`      // RFC3339Nano (UTC) from the injected clock
	Network       string    `json:"network"` // mainnet/testnet/signet/regtest
	Wallet        string    `json:"wallet"`  // wallet name — for `tx list --wallet` + the send-lock key
	Status        Status    `json:"status"`
	Source        string    `json:"source"`          // "cli" | "mcp"
	Txid          string    `json:"txid"`            // set at broadcast (also computable from RawTx)
	RawTx         string    `json:"raw_tx"`          // hex of the fully-signed wire.MsgTx (no 0x prefix)
	FeeRate       int64     `json:"fee_rate"`        // sat/vByte
	FeeSat        int64     `json:"fee_sat"`         // absolute fee
	Vsize         int64     `json:"vsize"`           // predicted/actual vsize
	Inputs        []JInput  `json:"inputs"`          // the consumed UTXOs (the double-spend-avoidance record)
	Outputs       []JOutput `json:"outputs"`         // the tx outputs
	RecipientAddr string    `json:"recipient_addr"`  // the payee address
	RecipientSat  int64     `json:"recipient_sat"`   // the payee amount
	ChangeAddr    string    `json:"change_addr"`     // wallet-owned change address (empty when no change)
	Confirmations int64     `json:"confirmations"`   // 0 until polled
	BlockHeight   int64     `json:"block_height"`    // 0 until confirmed
	Error         *string   `json:"error,omitempty"` // the reject reason on a failed record
	// ReservationID cross-links the policy spend reservation (M5) so service can
	// reconcile orphaned reservations against this record at Open (a record that
	// reached `broadcast` ⇒ commit the reservation; still `signed`/absent ⇒ release).
	// Omitted (and zero on M4 records) when no policy is active.
	ReservationID string `json:"reservation_id,omitempty"`
	// ReplacesID / ReplacedByID are the RBF (BIP-125) linkage. On a `tx speedup`/`tx
	// cancel` replacement record, ReplacesID is the ORIGINAL record's id; on the
	// original (now StatusReplaced) record, ReplacedByID is the replacement's id. Both
	// are omitempty so a non-RBF record's wire shape is unchanged (recordVersion stays
	// 1, schema-stable), and a shallow clone/fold copies the strings safely.
	ReplacesID   string `json:"replaces_id,omitempty"`
	ReplacedByID string `json:"replaced_by_id,omitempty"`
	// PSBTBase64 carries the partial (signed-but-not-broadcast) PSBT for a record
	// written by `psbt sign`. A `psbt sign` does NOT produce broadcastable raw bytes
	// (RawTx stays empty — the PSBT may still need a co-signer), so the durable
	// artifact is the base64 PSBT here, cross-linked to the spend reservation via
	// ReservationID. Omitted (and zero) on every send/RBF record (schema-stable;
	// recordVersion stays 1). `psbt broadcast` recovers the reservation by the
	// unsigned-tx txid and commits it on accept.
	PSBTBase64 string `json:"psbt_base64,omitempty"`
}

// recordVersion is the current schema version stamped into Record.V on append.
const recordVersion = 1

// clone returns a copy of r safe to mutate without aliasing the caller's record.
// Slice/pointer fields are copied by value of the header/pointer; SetState
// REPLACES them (it never mutates a shared backing array), so a shallow copy is
// sufficient for the latest-wins fold.
func (r *Record) clone() *Record {
	if r == nil {
		return nil
	}
	cp := *r
	return &cp
}
