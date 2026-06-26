package coinselect_test

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	bip39 "github.com/tyler-smith/go-bip39"
)

// sign_helper_test.go provides the in-process P2WPKH key-derivation + signing +
// engine-verification machinery shared by the vsize and select tests. It derives
// private keys directly from the canonical BIP-84 vector wallet (mnemonic
// "abandon…about", mainnet) via btcd hdkeychain — NO daxib keys-package or
// service dependency, so the coinselect tests stay leaf-pure.

const canonicalMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// rbfSequence is the RBF-signaling nSequence the send pipeline uses on every
// input; the vsize math is independent of the sequence value but we use it here so
// the signed test tx matches production bytes.
const rbfSequence = 0xfffffffd

// vectorAccountKey derives the BIP-84 account-level extended private key
// (m/84'/0'/0') from the canonical mnemonic on mainnet.
func vectorAccountKey(t *testing.T) *hdkeychain.ExtendedKey {
	t.Helper()
	seed := bip39.NewSeed(canonicalMnemonic, "")
	master, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("NewMaster: %v", err)
	}
	purpose, err := master.Derive(hdkeychain.HardenedKeyStart + 84)
	if err != nil {
		t.Fatalf("derive purpose: %v", err)
	}
	coin, err := purpose.Derive(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		t.Fatalf("derive coin: %v", err)
	}
	acct, err := coin.Derive(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		t.Fatalf("derive account: %v", err)
	}
	return acct
}

// vectorLeafKey derives the leaf private key + its P2WPKH pkScript at
// account/branch/index.
func vectorLeafKey(t *testing.T, acct *hdkeychain.ExtendedKey, branch, index uint32) (*btcec.PrivateKey, []byte) {
	t.Helper()
	b, err := acct.Derive(branch)
	if err != nil {
		t.Fatalf("derive branch %d: %v", branch, err)
	}
	leaf, err := b.Derive(index)
	if err != nil {
		t.Fatalf("derive index %d: %v", index, err)
	}
	priv, err := leaf.ECPrivKey()
	if err != nil {
		t.Fatalf("ECPrivKey: %v", err)
	}
	pub, err := leaf.ECPubKey()
	if err != nil {
		t.Fatalf("ECPubKey: %v", err)
	}
	wprog := btcutil.Hash160(pub.SerializeCompressed())
	addr, err := btcutil.NewAddressWitnessPubKeyHash(wprog, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("NewAddressWitnessPubKeyHash: %v", err)
	}
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatalf("PayToAddrScript: %v", err)
	}
	return priv, pkScript
}

// signedTx is a built+signed transaction plus the prevout metadata needed to
// engine-verify each input.
type signedTx struct {
	tx         *wire.MsgTx
	prevScript [][]byte
	prevAmount []int64
}

// buildSignedP2WPKHTx builds a tx with numInputs P2WPKH inputs (each funded by a
// distinct receive-branch leaf of the vector wallet, value inAmount) and
// numOutputs P2WPKH outputs, signs every input with BIP-143 segwit (low-S,
// SigHashAll), and returns it with the prevout scripts/amounts.
func buildSignedP2WPKHTx(t *testing.T, numInputs, numOutputs int, inAmount, outAmount int64) signedTx {
	t.Helper()
	acct := vectorAccountKey(t)

	tx := wire.NewMsgTx(2)
	prevScripts := make([][]byte, numInputs)
	prevAmounts := make([]int64, numInputs)
	privs := make([]*btcec.PrivateKey, numInputs)

	for i := 0; i < numInputs; i++ {
		priv, pkScript := vectorLeafKey(t, acct, 0, uint32(i))
		privs[i] = priv
		prevScripts[i] = pkScript
		prevAmounts[i] = inAmount
		// A distinct fake funding outpoint per input (a real prior tx hash here is
		// irrelevant to vsize/signing — only the script+amount matter for sighash).
		var hashBytes [32]byte
		hashBytes[0] = byte(i + 1)
		h, err := chainhash.NewHash(hashBytes[:])
		if err != nil {
			t.Fatalf("NewHash: %v", err)
		}
		op := wire.NewOutPoint(h, uint32(i))
		in := wire.NewTxIn(op, nil, nil)
		in.Sequence = rbfSequence
		tx.AddTxIn(in)
	}

	// Outputs: pay to change-branch leaves (still P2WPKH, the only type that
	// matters for vsize).
	for j := 0; j < numOutputs; j++ {
		_, pkScript := vectorLeafKey(t, acct, 1, uint32(j))
		tx.AddTxOut(wire.NewTxOut(outAmount, pkScript))
	}

	// Sign each input (BIP-143). The subscript for a P2WPKH input is the P2PKH
	// template over the same pubkey hash (btcd builds this from the witness program).
	prevOuts := make(map[wire.OutPoint]*wire.TxOut, numInputs)
	for i := range tx.TxIn {
		prevOuts[tx.TxIn[i].PreviousOutPoint] = wire.NewTxOut(prevAmounts[i], prevScripts[i])
	}
	fetcher := txscript.NewMultiPrevOutFetcher(prevOuts)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)
	for i := range tx.TxIn {
		subscript := p2wpkhSubscript(t, prevScripts[i])
		witness, err := txscript.WitnessSignature(
			tx, sigHashes, i, prevAmounts[i], subscript,
			txscript.SigHashAll, privs[i], true,
		)
		if err != nil {
			t.Fatalf("WitnessSignature input %d: %v", i, err)
		}
		tx.TxIn[i].Witness = witness
	}

	return signedTx{tx: tx, prevScript: prevScripts, prevAmount: prevAmounts}
}

// p2wpkhSubscript converts a P2WPKH scriptPubKey (OP_0 <20-byte hash>) into the
// BIP-143 sighash subscript — the canonical P2PKH script over the same 20-byte
// pubkey hash (OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG).
func p2wpkhSubscript(t *testing.T, pkScript []byte) []byte {
	t.Helper()
	// pkScript = [OP_0(0x00)][0x14][20-byte hash]; extract the hash.
	if len(pkScript) != 22 || pkScript[0] != 0x00 || pkScript[1] != 0x14 {
		t.Fatalf("not a P2WPKH script: %x", pkScript)
	}
	hash := pkScript[2:]
	script, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_DUP).
		AddOp(txscript.OP_HASH160).
		AddData(hash).
		AddOp(txscript.OP_EQUALVERIFY).
		AddOp(txscript.OP_CHECKSIG).
		Script()
	if err != nil {
		t.Fatalf("build subscript: %v", err)
	}
	return script
}

// engineVerify runs txscript.NewEngine on every input with StandardVerifyFlags and
// asserts each validates — the proof the signatures are real and spendable.
func engineVerify(t *testing.T, s signedTx) {
	t.Helper()
	prevOuts := make(map[wire.OutPoint]*wire.TxOut, len(s.tx.TxIn))
	for i := range s.tx.TxIn {
		prevOuts[s.tx.TxIn[i].PreviousOutPoint] = wire.NewTxOut(s.prevAmount[i], s.prevScript[i])
	}
	fetcher := txscript.NewMultiPrevOutFetcher(prevOuts)
	sigHashes := txscript.NewTxSigHashes(s.tx, fetcher)
	for i := range s.tx.TxIn {
		eng, err := txscript.NewEngine(
			s.prevScript[i], s.tx, i, txscript.StandardVerifyFlags,
			nil, sigHashes, s.prevAmount[i], fetcher,
		)
		if err != nil {
			t.Fatalf("NewEngine input %d: %v", i, err)
		}
		if err := eng.Execute(); err != nil {
			t.Fatalf("engine.Execute input %d FAILED (signature invalid/unspendable): %v", i, err)
		}
	}
}

// serializedVSize returns the actual signed-tx vsize as the network computes it:
// ceil(weight/4), with weight from blockchain.GetTransactionWeight.
func serializedVSize(tx *wire.MsgTx) int64 {
	weight := txWeight(tx)
	return (weight + 3) / 4 // ceil(weight/4)
}

// rawBytes serializes the tx (with witnesses) to wire bytes.
func rawBytes(t *testing.T, tx *wire.MsgTx) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return buf.Bytes()
}
