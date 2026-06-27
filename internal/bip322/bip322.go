// Package bip322 implements BIP-322 "simple" message signing/verification for
// native-SegWit P2WPKH (BIP-84) addresses — daxib's only address type (§3.5).
//
// It is a pure provider leaf: it imports the btcd primitives (txscript, wire,
// chainhash, btcutil) and domain (for the network→params map), but never the core
// or a frontend. The signing key is supplied by the caller (the keys provider
// materializes it under the keystore passphrase); this package never touches the
// keystore, so Verify is passphrase-free.
//
// BIP-322 "simple" works over two virtual transactions:
//
//	to_spend: a 1-in/1-out tx whose input commits to the tagged message hash and
//	          whose single output's scriptPubKey IS the signing address's script.
//	to_sign : a 1-in/1-out tx spending to_spend:0, with an OP_RETURN output. The
//	          witness of to_sign's input, serialized as a Bitcoin witness stack, IS
//	          the signature. Verification reconstructs both txs from (address,
//	          message) and runs the script engine on to_sign's input with the
//	          decoded witness — a passing engine means the signature is valid.
//
// References: BIP-322 (github.com/bitcoin/bips/blob/master/bip-0322.mediawiki).
package bip322

import (
	"bytes"
	"errors"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"github.com/daxchain-io/daxib/internal/domain"
)

// Format is the canonical format string daxib stamps on a BIP-322 simple result.
const Format = "bip322-simple"

// messageTag is the BIP-322 tagged-hash tag for a signed message.
var messageTag = []byte("BIP0322-signed")

// ErrUnsupportedAddress is returned when the address is not a P2WPKH (the only
// type daxib signs/verifies in v1). It maps to usage.bad_address at the service.
var ErrUnsupportedAddress = errors.New("bip322: only P2WPKH (bech32 v0, 20-byte) addresses are supported")

// MessageHash is the BIP-322 tagged hash of the message: tagged_hash(
// "BIP0322-signed", message). It is the 32-byte value the to_spend input commits
// to.
func MessageHash(message []byte) []byte {
	h := chainhash.TaggedHash(messageTag, message)
	return h[:]
}

// scriptForAddress decodes a bech32 address for the network and returns its
// scriptPubKey, requiring a P2WPKH (witness-v0, 20-byte program). Any other type
// (legacy, P2SH, Taproot) is ErrUnsupportedAddress.
func scriptForAddress(address string, params *chaincfg.Params) (btcutil.Address, []byte, error) {
	addr, err := btcutil.DecodeAddress(address, params)
	if err != nil {
		return nil, nil, err
	}
	if !addr.IsForNet(params) {
		return nil, nil, ErrUnsupportedAddress
	}
	wpkh, ok := addr.(*btcutil.AddressWitnessPubKeyHash)
	if !ok {
		return nil, nil, ErrUnsupportedAddress
	}
	script, err := txscript.PayToAddrScript(wpkh)
	if err != nil {
		return nil, nil, err
	}
	return wpkh, script, nil
}

// buildToSpend constructs the BIP-322 to_spend virtual tx for (scriptPubKey,
// messageHash). It is deterministic: version 0, locktime 0; one input spending the
// "null" outpoint (all-zero hash, index 0xFFFFFFFF) with sequence 0 and scriptSig
// "OP_0 PUSH32 <messageHash>"; one zero-value output paying scriptPubKey.
func buildToSpend(scriptPubKey, messageHash []byte) (*wire.MsgTx, error) {
	scriptSig, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_0).
		AddData(messageHash).
		Script()
	if err != nil {
		return nil, err
	}
	tx := wire.NewMsgTx(0)
	tx.LockTime = 0
	var nullHash chainhash.Hash // all zeros
	in := wire.NewTxIn(wire.NewOutPoint(&nullHash, 0xFFFFFFFF), scriptSig, nil)
	in.Sequence = 0
	tx.AddTxIn(in)
	tx.AddTxOut(wire.NewTxOut(0, scriptPubKey))
	return tx, nil
}

// buildToSign constructs the BIP-322 to_sign virtual tx spending to_spend:0:
// version 0, locktime 0; one input with sequence 0 and an empty scriptSig (the
// witness is filled by signing/verification); one zero-value OP_RETURN output.
func buildToSign(toSpend *wire.MsgTx) *wire.MsgTx {
	toSpendHash := toSpend.TxHash()
	tx := wire.NewMsgTx(0)
	tx.LockTime = 0
	in := wire.NewTxIn(wire.NewOutPoint(&toSpendHash, 0), nil, nil)
	in.Sequence = 0
	tx.AddTxIn(in)
	opReturn, _ := txscript.NewScriptBuilder().AddOp(txscript.OP_RETURN).Script()
	tx.AddTxOut(wire.NewTxOut(0, opReturn))
	return tx
}

// Sign produces the BIP-322 "simple" signature (the base64-able witness bytes) for
// message under privKey, for the given P2WPKH address. The caller owns privKey and
// is responsible for zeroing it. The returned bytes are the serialized witness
// stack ([signature, pubkey] for P2WPKH), which the frontend base64-encodes.
func Sign(address string, message []byte, privKey *btcec.PrivateKey, network domain.Network) ([]byte, error) {
	params := chainParams(network)
	_, scriptPubKey, err := scriptForAddress(address, params)
	if err != nil {
		return nil, err
	}

	toSpend, err := buildToSpend(scriptPubKey, MessageHash(message))
	if err != nil {
		return nil, err
	}
	toSign := buildToSign(toSpend)

	// BIP-143 witness signature over to_sign:0 spending the to_spend output (value
	// 0, scriptPubKey = the P2WPKH script). compressed=true (BIP-84).
	prevOut := wire.NewTxOut(0, scriptPubKey)
	fetcher := txscript.NewCannedPrevOutputFetcher(prevOut.PkScript, prevOut.Value)
	sigHashes := txscript.NewTxSigHashes(toSign, fetcher)
	witness, err := txscript.WitnessSignature(
		toSign, sigHashes, 0, 0, scriptPubKey,
		txscript.SigHashAll, privKey, true,
	)
	if err != nil {
		return nil, err
	}
	toSign.TxIn[0].Witness = witness
	return SerializeWitness(witness), nil
}

// Verify reconstructs the BIP-322 virtual txs from (address, message), decodes the
// witness from sig (the serialized witness stack), attaches it to to_sign:0, and
// runs the script engine. It returns (true, nil) on a valid signature and
// (false, nil) on a well-formed-but-invalid one — an invalid signature is NOT an
// error. A non-nil error means the inputs were malformed (bad address or an
// undecodable witness), which the service maps to a usage failure.
func Verify(address string, message, sig []byte, network domain.Network) (bool, error) {
	params := chainParams(network)
	_, scriptPubKey, err := scriptForAddress(address, params)
	if err != nil {
		return false, err
	}

	witness, err := DeserializeWitness(sig)
	if err != nil {
		return false, err
	}

	toSpend, err := buildToSpend(scriptPubKey, MessageHash(message))
	if err != nil {
		return false, err
	}
	toSign := buildToSign(toSpend)
	toSign.TxIn[0].Witness = witness

	prevOut := wire.NewTxOut(0, scriptPubKey)
	fetcher := txscript.NewCannedPrevOutputFetcher(prevOut.PkScript, prevOut.Value)
	sigHashes := txscript.NewTxSigHashes(toSign, fetcher)
	engine, err := txscript.NewEngine(
		scriptPubKey, toSign, 0, txscript.StandardVerifyFlags, nil, sigHashes, 0, fetcher,
	)
	if err != nil {
		// A construction failure here is a malformed witness (e.g. a witness that is
		// not even shaped like a script witness), not a daxib bug — treat it as an
		// invalid signature rather than an error.
		return false, nil
	}
	if execErr := engine.Execute(); execErr != nil {
		return false, nil // a real signature mismatch / tamper — invalid, not an error
	}
	return true, nil
}

// SerializeWitness encodes a witness stack as the canonical Bitcoin witness:
// varint(num_items) followed by each item as varint(len)||bytes. This is the exact
// byte string BIP-322 "simple" defines as the signature.
func SerializeWitness(witness wire.TxWitness) []byte {
	var buf bytes.Buffer
	_ = wire.WriteVarInt(&buf, 0, uint64(len(witness)))
	for _, item := range witness {
		_ = wire.WriteVarBytes(&buf, 0, item)
	}
	return buf.Bytes()
}

// DeserializeWitness inverts SerializeWitness. A trailing-garbage or
// length-overrun input is an error (a malformed signature). The 0x1000000 cap on
// each element bounds a hostile length field cheaply.
func DeserializeWitness(b []byte) (wire.TxWitness, error) {
	r := bytes.NewReader(b)
	count, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return nil, err
	}
	if count == 0 || count > 100 {
		return nil, errors.New("bip322: witness item count out of range")
	}
	witness := make(wire.TxWitness, 0, count)
	for i := uint64(0); i < count; i++ {
		item, err := wire.ReadVarBytes(r, 0, 1<<24, "witness item")
		if err != nil {
			return nil, err
		}
		witness = append(witness, item)
	}
	if r.Len() != 0 {
		return nil, errors.New("bip322: trailing bytes after witness")
	}
	return witness, nil
}

// chainParams maps a daxib network to its btcd chaincfg.Params (the same mapping
// the keys provider uses; duplicated here to keep bip322 a leaf that does not
// import keys).
func chainParams(n domain.Network) *chaincfg.Params {
	switch n {
	case domain.NetworkMainnet:
		return &chaincfg.MainNetParams
	case domain.NetworkTestnet:
		return &chaincfg.TestNet3Params
	case domain.NetworkTestnet4:
		return &chaincfg.TestNet4Params
	case domain.NetworkSignet:
		return &chaincfg.SigNetParams
	case domain.NetworkRegtest:
		return &chaincfg.RegressionNetParams
	default:
		return &chaincfg.MainNetParams
	}
}
