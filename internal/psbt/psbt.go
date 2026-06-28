package psbt

import (
	"bytes"
	"encoding/hex"
	"strings"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"github.com/daxchain-io/daxib/internal/domain"
)

// InputBip32 is the per-input BIP-32 derivation hint a daxib-created PSBT carries
// (so an external/hardware signer knows which key signs the input): the compressed
// pubkey, the master-key fingerprint, and the full BIP-84 path as child indices.
type InputBip32 struct {
	PubKey      []byte   // compressed pubkey (33 bytes)
	Fingerprint uint32   // master key fingerprint
	Path        []uint32 // BIP-84 path as child indices (hardened bits set)
}

// InputMeta is the per-input metadata BuildFromUnsigned attaches: the prevout
// (script + value, required for the witness sighash) and the BIP-32 hint.
type InputMeta struct {
	PrevScript []byte
	PrevValue  int64
	Bip32      InputBip32
}

// OutputBip32 marks a wallet-owned output (the change/self output) with its
// derivation hint so a verifier sees the change returns to the wallet. Index is
// the output's index in the unsigned tx.
type OutputBip32 struct {
	Index int
	Bip32 InputBip32
}

// Decode parses a base64 PSBT envelope into a *psbt.Packet. A malformed envelope
// is usage.bad_psbt (exit 2).
func Decode(b64 string) (*psbt.Packet, error) {
	p, err := psbt.NewFromRawBytes(strings.NewReader(strings.TrimSpace(b64)), true)
	if err != nil {
		return nil, domain.Wrap(domain.CodeBadPSBT, "decoding the PSBT", err)
	}
	return p, nil
}

// Encode serializes a *psbt.Packet back to a base64 PSBT envelope.
func Encode(p *psbt.Packet) (string, error) {
	s, err := p.B64Encode()
	if err != nil {
		return "", domain.Wrap(domain.CodeStateCorrupt, "encoding the PSBT", err)
	}
	return s, nil
}

// BuildFromUnsigned wraps an unsigned wire.MsgTx as a fully-populated unsigned
// PSBT: per input it attaches the WitnessUtxo (prevout script+value, required by
// the witness sighash and consumed by a later signer/policy) and the BIP-32
// derivation hint; for each wallet-owned output it attaches the output BIP-32 hint
// (so a verifier sees the change is wallet-owned). The tx MUST be unsigned (no
// witnesses/sigscripts); inputMeta is indexed by tx input position.
func BuildFromUnsigned(tx *wire.MsgTx, inputMeta []InputMeta, ownedOutputs []OutputBip32) (*psbt.Packet, error) {
	if len(inputMeta) != len(tx.TxIn) {
		return nil, domain.Newf(domain.CodeStateCorrupt,
			"psbt build: %d input metadata for %d tx inputs", len(inputMeta), len(tx.TxIn))
	}
	p, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		return nil, domain.Wrap(domain.CodeStateCorrupt, "building PSBT from unsigned tx", err)
	}
	u, err := psbt.NewUpdater(p)
	if err != nil {
		return nil, domain.Wrap(domain.CodeStateCorrupt, "opening PSBT updater", err)
	}
	for i, m := range inputMeta {
		if err := u.AddInWitnessUtxo(wire.NewTxOut(m.PrevValue, m.PrevScript), i); err != nil {
			return nil, domain.Wrap(domain.CodeStateCorrupt, "attaching input witness utxo", err)
		}
		if len(m.Bip32.PubKey) > 0 {
			if err := u.AddInBip32Derivation(m.Bip32.Fingerprint, m.Bip32.Path, m.Bip32.PubKey, i); err != nil {
				return nil, domain.Wrap(domain.CodeStateCorrupt, "attaching input bip32 derivation", err)
			}
		}
	}
	for _, o := range ownedOutputs {
		if o.Index < 0 || o.Index >= len(p.Outputs) {
			return nil, domain.Newf(domain.CodeStateCorrupt, "psbt build: owned output index %d out of range", o.Index)
		}
		if len(o.Bip32.PubKey) == 0 {
			continue
		}
		if err := u.AddOutBip32Derivation(o.Bip32.Fingerprint, o.Bip32.Path, o.Bip32.PubKey, o.Index); err != nil {
			return nil, domain.Wrap(domain.CodeStateCorrupt, "attaching output bip32 derivation", err)
		}
	}
	return p, nil
}

// AttachPartialSig lifts a (sig, pubkey) pair — the two elements of a P2WPKH
// witness produced by the keystore signer — into input idx's PartialSigs, via the
// Updater (which validates and de-dupes). The signing crypto happened in the keys
// provider; this is pure mechanics, no key material. sig is the DER signature with
// the trailing sighash byte (witness[0]); pubKey is the compressed pubkey
// (witness[1]). A SignInvalid outcome is a state.corrupt (the witness daxib just
// produced did not validate — a derivation/value mismatch).
func AttachPartialSig(p *psbt.Packet, idx int, sig, pubKey []byte) error {
	if idx < 0 || idx >= len(p.Inputs) {
		return domain.Newf(domain.CodeStateCorrupt, "psbt attach: input index %d out of range", idx)
	}
	u, err := psbt.NewUpdater(p)
	if err != nil {
		return domain.Wrap(domain.CodeStateCorrupt, "opening PSBT updater", err)
	}
	// Single-sig P2WPKH: no redeem/witness script. Updater.Sign de-dupes on pubkey,
	// validates the sig against the WitnessUtxo, and appends the PartialSig.
	outcome, serr := u.Sign(idx, sig, pubKey, nil, nil)
	if serr != nil {
		return domain.Wrap(domain.CodeStateCorrupt, "attaching partial signature", serr)
	}
	if outcome == psbt.SignInvalid {
		return domain.Newf(domain.CodeStateCorrupt, "psbt attach: signature for input %d did not validate", idx)
	}
	return nil
}

// Finalize attempts to finalize every input (assembling FinalScriptWitness from
// the PartialSigs). For single-sig P2WPKH this needs exactly daxib's one
// PartialSig per owned input. It is best-effort per BIP-174 (an input lacking
// enough sigs stays unfinalized); IsComplete reports whether all inputs finalized.
// An incomplete PSBT is NOT an error here (a co-signer may still add sigs).
func Finalize(p *psbt.Packet) error {
	if err := psbt.MaybeFinalizeAll(p); err != nil {
		// MaybeFinalizeAll errors only on a structurally-broken input, not on a merely
		// under-signed one. Surface it as incomplete so the caller maps it cleanly.
		return domain.Wrap(domain.CodePSBTIncomplete, "finalizing the PSBT", err)
	}
	return nil
}

// Extract serializes a COMPLETE (finalized) PSBT to its raw network tx HEX. A PSBT
// that is not complete is psbt.incomplete (exit 2) — extraction requires every
// input finalized.
func Extract(p *psbt.Packet) (string, error) {
	if !p.IsComplete() {
		return "", domain.New(domain.CodePSBTIncomplete,
			"the PSBT is not complete: every input must be finalized before extract (run `psbt finalize`, or supply the missing co-signer signatures)")
	}
	tx, err := psbt.Extract(p)
	if err != nil {
		return "", domain.Wrap(domain.CodePSBTIncomplete, "extracting the network tx from the PSBT", err)
	}
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return "", domain.Wrap(domain.CodeStateCorrupt, "serializing the extracted tx", err)
	}
	return hex.EncodeToString(buf.Bytes()), nil
}

// ExtractTx is Extract returning the *wire.MsgTx (the service's broadcast path
// needs the raw bytes + txid, not just hex). Same completeness precondition.
func ExtractTx(p *psbt.Packet) (*wire.MsgTx, error) {
	if !p.IsComplete() {
		return nil, domain.New(domain.CodePSBTIncomplete,
			"the PSBT is not complete: every input must be finalized before extract")
	}
	tx, err := psbt.Extract(p)
	if err != nil {
		return nil, domain.Wrap(domain.CodePSBTIncomplete, "extracting the network tx from the PSBT", err)
	}
	return tx, nil
}

// View is the decoded, per-input/-output summary of a PSBT for inspection. Owned
// is decided by the CALLER (it matches against the wallet's scripts); Summarize
// fills the script-derived fields (outpoint/address/value/signed) and leaves
// Mine/Change for the service to annotate.
type View struct {
	Inputs  []InputView
	Outputs []OutputView
	FeeSat  int64
	HasFee  bool // false when an input WitnessUtxo is missing (fee uncomputable)
}

// InputView is one decoded input. Script is the prevout scriptPubKey (hex), used
// by the caller for ownership matching.
type InputView struct {
	Outpoint string
	Script   []byte // prevout scriptPubKey (nil when no WitnessUtxo)
	Address  string // derived from Script for the active network ("" if non-standard)
	ValueSat int64
	Signed   bool // daxib (or anyone) has attached a PartialSig or a FinalScriptWitness
}

// OutputView is one decoded output.
type OutputView struct {
	Script   []byte
	Address  string
	ValueSat int64
}

// Summarize decodes a PSBT into a per-input/-output View for the active network's
// params (used to render addresses). It reads the prevout script/value from each
// input's WitnessUtxo (preferred) or NonWitnessUtxo, computes the fee when every
// input value is known, and flags an input as signed when it carries a PartialSig
// or a FinalScriptWitness. It makes no ownership decision (the service annotates
// Mine/Change by matching Script against the wallet's derived scripts).
func Summarize(p *psbt.Packet, params *chaincfg.Params) View {
	v := View{
		Inputs:  make([]InputView, len(p.Inputs)),
		Outputs: make([]OutputView, len(p.Outputs)),
		HasFee:  true,
	}
	var inSum, outSum int64
	for i := range p.Inputs {
		pi := &p.Inputs[i]
		op := p.UnsignedTx.TxIn[i].PreviousOutPoint
		iv := InputView{Outpoint: op.String()}
		script, value, ok := prevout(pi)
		if ok {
			iv.Script = script
			iv.ValueSat = value
			iv.Address = addressForScript(script, params)
			inSum += value
		} else {
			v.HasFee = false // an unknown input value makes the fee uncomputable
		}
		iv.Signed = len(pi.PartialSigs) > 0 || len(pi.FinalScriptWitness) > 0
		v.Inputs[i] = iv
	}
	for i, txout := range p.UnsignedTx.TxOut {
		ov := OutputView{
			Script:   txout.PkScript,
			ValueSat: txout.Value,
			Address:  addressForScript(txout.PkScript, params),
		}
		outSum += txout.Value
		v.Outputs[i] = ov
	}
	if v.HasFee {
		v.FeeSat = inSum - outSum
	}
	return v
}

// prevout returns an input's prevout (script, value) from its WitnessUtxo. daxib is
// P2WPKH-only, so a witness spend REQUIRES the WitnessUtxo (the BIP-143 amount is
// uncomputable without it); an input lacking one returns ok=false and is treated as
// not-ours / unvaluable by the caller.
func prevout(pi *psbt.PInput) (script []byte, value int64, ok bool) {
	if pi.WitnessUtxo != nil {
		return pi.WitnessUtxo.PkScript, pi.WitnessUtxo.Value, true
	}
	return nil, 0, false
}

// AllPrevouts returns the prevout (script+value) for EVERY input that carries a
// WitnessUtxo, keyed by the input's spent outpoint. The service seeds the BIP-143
// sighash fetcher with this map so a FOREIGN co-signer input (which daxib does not
// sign but which NewTxSigHashes still iterates) does not nil-panic. An input
// lacking a WitnessUtxo is simply absent from the map.
func AllPrevouts(p *psbt.Packet) map[wire.OutPoint]*wire.TxOut {
	out := make(map[wire.OutPoint]*wire.TxOut, len(p.Inputs))
	for i := range p.Inputs {
		script, value, ok := prevout(&p.Inputs[i])
		if !ok {
			continue
		}
		op := p.UnsignedTx.TxIn[i].PreviousOutPoint
		out[op] = wire.NewTxOut(value, script)
	}
	return out
}

// PrevScriptValue returns an input's prevout script + value (WitnessUtxo only;
// daxib P2WPKH-only signing needs the witness amount), plus ok=false when there is
// no WitnessUtxo (a witness spend cannot compute the BIP-143 amount without it).
func PrevScriptValue(p *psbt.Packet, idx int) (script []byte, value int64, ok bool) {
	if idx < 0 || idx >= len(p.Inputs) {
		return nil, 0, false
	}
	return prevout(&p.Inputs[idx])
}

// addressForScript decodes a scriptPubKey to its address string for the network,
// returning "" for a non-standard/multi script (so a render shows the value only).
func addressForScript(script []byte, params *chaincfg.Params) string {
	if len(script) == 0 || params == nil {
		return ""
	}
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(script, params)
	if err != nil || len(addrs) != 1 {
		return ""
	}
	return addrs[0].EncodeAddress()
}

// IsComplete reports whether every input of the PSBT is finalized.
func IsComplete(p *psbt.Packet) bool { return p.IsComplete() }

// scriptHex renders a scriptPubKey as lowercase hex (the ownership-map key the
// service builds against).
func scriptHex(script []byte) string { return hex.EncodeToString(script) }

// AddressFromScript is the exported address decoder for the service's renderers.
func AddressFromScript(script []byte, params *chaincfg.Params) string {
	return addressForScript(script, params)
}

// P2WPKHScript builds the P2WPKH scriptPubKey for a compressed pubkey hash (used
// by the leaf's round-trip test). It is exported only for test convenience.
func P2WPKHScript(pubKeyHash []byte, params *chaincfg.Params) ([]byte, error) {
	addr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, params)
	if err != nil {
		return nil, err
	}
	return txscript.PayToAddrScript(addr)
}

// ScriptHexKey is the exported ownership-map key helper (lowercase hex of a
// scriptPubKey) so the service keys its byScript map identically to the leaf.
func ScriptHexKey(script []byte) string { return scriptHex(script) }
