package domain

// psbt_requests.go holds the plain request/result value types for the `psbt`
// noun (BIP-174). Like every domain type they carry NO internal import and NO
// *psbt.Packet — only base64/hex strings, integer sats, and bools — so the wire
// contract is transport-agnostic (CLI flags and the MCP schema bind the SAME
// structs). The `In` request types whose tools are MCP-exposed (PSBTSignRequest,
// PSBTDecodeRequest, PSBTBroadcastRequest) drive the inferred JSON schema, so
// their fields carry snake_case json + jsonschema tags.
//
// A PSBT is NOT a secret (it holds no private material), so the base64 PSBT may
// travel as a flag value / request field (unlike a passphrase). The keystore
// passphrase for `psbt sign` rides the standard out-of-band env/stdin/file
// channel, never a request field.

// PSBTCreateRequest builds an UNSIGNED, fully-populated v2/RBF PSBT spending the
// wallet's confirmed UTXOs to To/Amount. It authorizes nothing (an unsigned tx
// moves no funds) — policy is enforced at `psbt sign`. It is NOT MCP-exposed.
type PSBTCreateRequest struct {
	Wallet  string `json:"wallet,omitempty"`
	To      string `json:"to"`
	Amount  string `json:"amount"`
	FeeRate string `json:"fee_rate,omitempty"`
	Speed   string `json:"speed,omitempty"`
}

// PSBTSignRequest is the policy chokepoint request: decode the PSBT, detect
// wallet-owned inputs by script match, derive the net wallet outflow, run the
// policy reservation BEFORE signing a byte, then attach one PartialSig per owned
// input. The PSBT field is the base64 envelope. Yes/passphrase ride the frontend
// channels (Yes is json:"-" — a ceremony field, never agent-visible).
type PSBTSignRequest struct {
	PSBT   string `json:"psbt" jsonschema:"the base64-encoded PSBT (BIP-174) to sign"`
	Wallet string `json:"wallet,omitempty" jsonschema:"wallet whose owned inputs to sign (optional; default wallet)"`
	Yes    bool   `json:"-"`
}

// PSBTCombineRequest merges N PSBTs that share an identical unsigned tx, unioning
// per-input PartialSigs/Bip32Derivation/WitnessUtxo. It is pure (no keystore/
// policy/backend) and NOT MCP-exposed.
type PSBTCombineRequest struct {
	PSBTs []string `json:"psbts"`
}

// PSBTFinalizeRequest finalizes a PSBT (assembles FinalScriptWitness from the
// PartialSigs). Pure; NOT MCP-exposed.
type PSBTFinalizeRequest struct {
	PSBT string `json:"psbt"`
}

// PSBTExtractRequest extracts the network-serializable raw tx HEX from a complete
// PSBT. Pure; NOT MCP-exposed.
type PSBTExtractRequest struct {
	PSBT string `json:"psbt"`
}

// PSBTBroadcastRequest finalizes-if-needed, extracts, and broadcasts a PSBT
// through the SAME send tail (journal + reservation commit on accept). It is the
// only PSBT verb that dials the backend + writes the journal. --yes gated. It is
// MCP-exposed in the funds-moving group.
type PSBTBroadcastRequest struct {
	PSBT   string   `json:"psbt" jsonschema:"the base64-encoded PSBT to finalize+extract+broadcast"`
	Wallet string   `json:"wallet,omitempty" jsonschema:"wallet that owns the PSBT (optional; default wallet)"`
	Yes    bool     `json:"-"`
	Wait   WaitOpts `json:"-"`
}

// PSBTDecodeRequest is read-only human/JSON inspection of a PSBT. No keystore/
// backend/policy. MCP-exposed (read class).
type PSBTDecodeRequest struct {
	PSBT   string `json:"psbt" jsonschema:"the base64-encoded PSBT to decode and inspect"`
	Wallet string `json:"wallet,omitempty" jsonschema:"wallet to annotate which inputs/outputs are mine (optional; default wallet)"`
}

// PSBTInputView is one input row of a decoded PSBT: its outpoint, the prevout
// address (when derivable from the WitnessUtxo script), value in sats, whether it
// is wallet-owned (Mine), and whether daxib has attached a signature (Signed).
type PSBTInputView struct {
	Outpoint string `json:"outpoint"`
	Address  string `json:"address,omitempty"`
	ValueSat int64  `json:"value_sat"`
	Mine     bool   `json:"mine"`
	Signed   bool   `json:"signed"`
}

// PSBTOutputView is one output row of a decoded PSBT: its address, value, whether
// it is wallet-owned (Mine), and whether it is the wallet-owned change output.
type PSBTOutputView struct {
	Address  string `json:"address,omitempty"`
	ValueSat int64  `json:"value_sat"`
	Mine     bool   `json:"mine"`
	Change   bool   `json:"change,omitempty"`
}

// PSBTResult is the envelope the create/sign/combine/finalize/extract/decode
// verbs return (broadcast returns the byte-identical TxResult instead). PSBT is
// the (possibly updated) base64 PSBT ("" for extract, which returns RawTxHex). It
// also carries the inspection view so a single render covers every verb.
type PSBTResult struct {
	PSBT       string           `json:"psbt,omitempty"`
	RawTxHex   string           `json:"raw_tx,omitempty"`
	Txid       string           `json:"txid,omitempty"`
	Network    Network          `json:"network,omitempty"`
	FeeSat     int64            `json:"fee_sat,omitempty"`
	FeeBTC     string           `json:"fee_btc,omitempty"`
	FeeRate    int64            `json:"fee_rate_sat_vb,omitempty"`
	Vsize      int64            `json:"vsize,omitempty"`
	Complete   bool             `json:"complete"`
	SignedByUs int              `json:"signed_by_us"`
	Inputs     []PSBTInputView  `json:"inputs,omitempty"`
	Outputs    []PSBTOutputView `json:"outputs,omitempty"`
	Warnings   []string         `json:"warnings,omitempty"`
}
