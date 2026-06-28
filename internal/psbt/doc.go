// Package psbt is daxib's thin serialization/mechanics layer over BIP-174
// Partially-Signed Bitcoin Transactions (github.com/btcsuite/btcd/btcutil/psbt).
//
// It is a PURE provider leaf: it imports the btcd primitives (the btcutil/psbt
// codec, wire, txscript, btcutil) and internal/domain (the Error taxonomy) ONLY.
// It NEVER imports the core (service), a frontend (cli/mcpserver), or another
// daxib provider (keys/backend/policy/coinselect). It holds NO keys and makes NO
// policy decision — the service drives ownership detection, the policy
// reservation, and the keystore signer; this leaf only encodes/decodes the
// envelope, attaches a caller-supplied PartialSig, unions PSBTs, finalizes,
// extracts, and summarizes. Keeping the leaf key- and policy-agnostic is what lets
// the lattice (TestImportMatrix / depguard) prove `psbt sign` cannot bypass the
// policy chokepoint: the only path to a signature is through the service's
// eng.Reserve, never this package.
//
// It must also stay offline-safe (no btcd/blockchain or btcd/mempool, which drag
// the chainstate/validation tree in and threaten the CGO0+windows build).
//
// The surface:
//
//	Decode      base64 -> *Packet (NewFromRawBytes)
//	Encode      *Packet -> base64 (Packet.B64Encode)
//	BuildFromUnsigned   an unsigned wire.MsgTx + per-input WitnessUtxo/Bip32
//	                    + change Bip32 -> a fully-populated unsigned *Packet
//	AttachPartialSig    lift (sig, pubkey) from a signed witness into a PInput's
//	                    PartialSigs (wrapping the Updater) — no signing crypto here
//	Combine     hand-written union of N PSBTs sharing one unsigned tx (txid guard;
//	            btcutil/psbt ships no Combine method)
//	Finalize    MaybeFinalizeAll
//	Extract     a complete *Packet -> raw network tx HEX (Extract + Serialize)
//	Summarize   decode-to-view (inputs/outputs/values/fee) for inspection
//
// References: BIP-174 (github.com/bitcoin/bips/blob/master/bip-0174.mediawiki).
package psbt
