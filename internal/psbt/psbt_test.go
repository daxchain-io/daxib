package psbt_test

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	btcpsbt "github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/psbt"
)

// testKey returns a deterministic privkey + its compressed pubkey + P2WPKH script
// + address for regtest.
func testKey(t *testing.T, seedByte byte) (*btcec.PrivateKey, []byte, []byte, btcutil.Address) {
	t.Helper()
	var raw [32]byte
	for i := range raw {
		raw[i] = seedByte + byte(i)
	}
	priv, pub := btcec.PrivKeyFromBytes(raw[:])
	h160 := btcutil.Hash160(pub.SerializeCompressed())
	addr, err := btcutil.NewAddressWitnessPubKeyHash(h160, &chaincfg.RegressionNetParams)
	if err != nil {
		t.Fatalf("address: %v", err)
	}
	script, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatalf("script: %v", err)
	}
	return priv, pub.SerializeCompressed(), script, addr
}

// buildUnsignedTx makes a 1-in/2-out (recipient + change) unsigned tx spending one
// input that pays prevScript.
func buildUnsignedTx(t *testing.T, prevScript, recipScript, changeScript []byte) *wire.MsgTx {
	t.Helper()
	h, _ := chainhash.NewHashFromStr("aa00000000000000000000000000000000000000000000000000000000000000")
	tx := wire.NewMsgTx(2)
	in := wire.NewTxIn(wire.NewOutPoint(h, 0), nil, nil)
	in.Sequence = 0xfffffffd
	tx.AddTxIn(in)
	tx.AddTxOut(wire.NewTxOut(60_000, recipScript))
	tx.AddTxOut(wire.NewTxOut(39_000, changeScript))
	return tx
}

func TestBuildEncodeDecodeRoundTrip(t *testing.T) {
	priv, pub, ownScript, _ := testKey(t, 1)
	_ = priv
	_, _, recipScript, _ := testKey(t, 50)

	tx := buildUnsignedTx(t, ownScript, recipScript, ownScript)
	meta := []psbt.InputMeta{{
		PrevScript: ownScript, PrevValue: 100_000,
		Bip32: psbt.InputBip32{PubKey: pub, Fingerprint: 0x12345678, Path: []uint32{84, 1, 0, 0, 0}},
	}}
	pkt, err := psbt.BuildFromUnsigned(tx, meta, []psbt.OutputBip32{{Index: 1, Bip32: psbt.InputBip32{PubKey: pub, Fingerprint: 0x12345678, Path: []uint32{84, 1, 0, 1, 0}}}})
	if err != nil {
		t.Fatalf("BuildFromUnsigned: %v", err)
	}
	b64, err := psbt.Encode(pkt)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := psbt.Decode(b64)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.UnsignedTx.TxHash() != tx.TxHash() {
		t.Fatalf("round-trip txid mismatch")
	}
	if got.Inputs[0].WitnessUtxo == nil || got.Inputs[0].WitnessUtxo.Value != 100_000 {
		t.Fatalf("WitnessUtxo not preserved")
	}
	if len(got.Inputs[0].Bip32Derivation) != 1 {
		t.Fatalf("input bip32 not preserved")
	}
	if len(got.Outputs[1].Bip32Derivation) != 1 {
		t.Fatalf("change output bip32 not preserved")
	}
}

func TestDecodeBadPSBT(t *testing.T) {
	_, err := psbt.Decode("not-a-psbt")
	if err == nil {
		t.Fatal("expected an error decoding garbage")
	}
	if code := domain.AsError(err).Code; code != domain.CodeBadPSBT {
		t.Fatalf("code = %q, want %q", code, domain.CodeBadPSBT)
	}
}

func TestAttachFinalizeExtract(t *testing.T) {
	priv, pub, ownScript, _ := testKey(t, 7)
	_, _, recipScript, _ := testKey(t, 70)
	tx := buildUnsignedTx(t, ownScript, recipScript, ownScript)
	meta := []psbt.InputMeta{{PrevScript: ownScript, PrevValue: 100_000,
		Bip32: psbt.InputBip32{PubKey: pub, Fingerprint: 1, Path: []uint32{84, 1, 0, 0, 0}}}}
	pkt, err := psbt.BuildFromUnsigned(tx, meta, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	// Produce a real P2WPKH witness signature for input 0.
	prevOut := wire.NewTxOut(100_000, ownScript)
	fetcher := txscript.NewCannedPrevOutputFetcher(ownScript, 100_000)
	_ = prevOut
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)
	witness, err := txscript.WitnessSignature(tx, sigHashes, 0, 100_000, ownScript, txscript.SigHashAll, priv, true)
	if err != nil {
		t.Fatalf("WitnessSignature: %v", err)
	}
	if len(witness) != 2 {
		t.Fatalf("witness shape: %d", len(witness))
	}

	// Before signing: not complete.
	if psbt.IsComplete(pkt) {
		t.Fatal("an unsigned PSBT must not be complete")
	}
	// Extract before complete is an error.
	if _, eerr := psbt.Extract(pkt); eerr == nil {
		t.Fatal("extract of an incomplete PSBT must error")
	} else if domain.AsError(eerr).Code != domain.CodePSBTIncomplete {
		t.Fatalf("incomplete extract code = %q", domain.AsError(eerr).Code)
	}

	if err := psbt.AttachPartialSig(pkt, 0, witness[0], witness[1]); err != nil {
		t.Fatalf("AttachPartialSig: %v", err)
	}
	if len(pkt.Inputs[0].PartialSigs) != 1 {
		t.Fatalf("expected 1 partial sig, got %d", len(pkt.Inputs[0].PartialSigs))
	}
	if err := psbt.Finalize(pkt); err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if !psbt.IsComplete(pkt) {
		t.Fatal("a finalized single-sig PSBT must be complete")
	}
	rawHex, err := psbt.Extract(pkt)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if rawHex == "" {
		t.Fatal("empty raw tx hex")
	}
}

func TestCombineUnionsAndRejectsMismatch(t *testing.T) {
	priv1, pub1, own1, _ := testKey(t, 3)
	priv2, pub2, own2, _ := testKey(t, 9)
	_, _, recip, _ := testKey(t, 90)

	// A 2-in tx: input 0 owned by key1, input 1 owned by key2 (a co-signing scenario).
	h, _ := chainhash.NewHashFromStr("bb00000000000000000000000000000000000000000000000000000000000000")
	tx := wire.NewMsgTx(2)
	in0 := wire.NewTxIn(wire.NewOutPoint(h, 0), nil, nil)
	in1 := wire.NewTxIn(wire.NewOutPoint(h, 1), nil, nil)
	tx.AddTxIn(in0)
	tx.AddTxIn(in1)
	tx.AddTxOut(wire.NewTxOut(150_000, recip))

	mkPart := func() *btcpsbt.Packet {
		meta := []psbt.InputMeta{
			{PrevScript: own1, PrevValue: 100_000, Bip32: psbt.InputBip32{PubKey: pub1, Fingerprint: 1, Path: []uint32{84, 1, 0, 0, 0}}},
			{PrevScript: own2, PrevValue: 100_000, Bip32: psbt.InputBip32{PubKey: pub2, Fingerprint: 2, Path: []uint32{84, 1, 0, 0, 1}}},
		}
		p, err := psbt.BuildFromUnsigned(tx.Copy(), meta, nil)
		if err != nil {
			t.Fatalf("build part: %v", err)
		}
		return p
	}

	signInput := func(p *btcpsbt.Packet, idx int, priv *btcec.PrivateKey, script []byte) {
		fetch := txscript.NewMultiPrevOutFetcher(map[wire.OutPoint]*wire.TxOut{
			tx.TxIn[0].PreviousOutPoint: wire.NewTxOut(100_000, own1),
			tx.TxIn[1].PreviousOutPoint: wire.NewTxOut(100_000, own2),
		})
		sh := txscript.NewTxSigHashes(p.UnsignedTx, fetch)
		w, err := txscript.WitnessSignature(p.UnsignedTx, sh, idx, 100_000, script, txscript.SigHashAll, priv, true)
		if err != nil {
			t.Fatalf("sign input %d: %v", idx, err)
		}
		if err := psbt.AttachPartialSig(p, idx, w[0], w[1]); err != nil {
			t.Fatalf("attach input %d: %v", idx, err)
		}
	}

	partA := mkPart()
	signInput(partA, 0, priv1, own1)
	partB := mkPart()
	signInput(partB, 1, priv2, own2)

	merged, err := psbt.Combine([]*btcpsbt.Packet{partA, partB})
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	if len(merged.Inputs[0].PartialSigs) != 1 || len(merged.Inputs[1].PartialSigs) != 1 {
		t.Fatalf("combine did not union both partial sigs: in0=%d in1=%d",
			len(merged.Inputs[0].PartialSigs), len(merged.Inputs[1].PartialSigs))
	}
	// A combine of both signed inputs should finalize completely.
	if err := psbt.Finalize(merged); err != nil {
		t.Fatalf("finalize merged: %v", err)
	}
	if !psbt.IsComplete(merged) {
		t.Fatal("merged 2-of-2 PSBT must be complete after combine+finalize")
	}

	// Mismatch: a part with a DIFFERENT unsigned tx must be rejected.
	otherTx := tx.Copy()
	otherTx.TxOut[0].Value = 140_000 // changes the txid
	otherMeta := []psbt.InputMeta{
		{PrevScript: own1, PrevValue: 100_000, Bip32: psbt.InputBip32{PubKey: pub1, Fingerprint: 1, Path: []uint32{84, 1, 0, 0, 0}}},
		{PrevScript: own2, PrevValue: 100_000, Bip32: psbt.InputBip32{PubKey: pub2, Fingerprint: 2, Path: []uint32{84, 1, 0, 0, 1}}},
	}
	otherPart, err := psbt.BuildFromUnsigned(otherTx, otherMeta, nil)
	if err != nil {
		t.Fatalf("build other: %v", err)
	}
	_, merr := psbt.Combine([]*btcpsbt.Packet{partA, otherPart})
	if merr == nil {
		t.Fatal("combine of differing unsigned txs must be rejected")
	}
	if code := domain.AsError(merr).Code; code != domain.CodePSBTCombineMismatch {
		t.Fatalf("combine mismatch code = %q, want %q", code, domain.CodePSBTCombineMismatch)
	}
}

func TestSummarize(t *testing.T) {
	_, pub, ownScript, ownAddr := testKey(t, 11)
	_, _, recipScript, recipAddr := testKey(t, 110)
	tx := buildUnsignedTx(t, ownScript, recipScript, ownScript)
	meta := []psbt.InputMeta{{PrevScript: ownScript, PrevValue: 100_000,
		Bip32: psbt.InputBip32{PubKey: pub, Fingerprint: 1, Path: []uint32{84, 1, 0, 0, 0}}}}
	pkt, err := psbt.BuildFromUnsigned(tx, meta, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	v := psbt.Summarize(pkt, &chaincfg.RegressionNetParams)
	if !v.HasFee {
		t.Fatal("fee should be computable (WitnessUtxo present)")
	}
	if v.FeeSat != 100_000-60_000-39_000 {
		t.Fatalf("fee = %d, want %d", v.FeeSat, 1_000)
	}
	if v.Inputs[0].ValueSat != 100_000 {
		t.Fatalf("input value = %d", v.Inputs[0].ValueSat)
	}
	if v.Outputs[0].Address != recipAddr.EncodeAddress() {
		t.Fatalf("recipient address = %q, want %q", v.Outputs[0].Address, recipAddr.EncodeAddress())
	}
	// The change output pays our own script.
	if v.Outputs[1].Address != ownAddr.EncodeAddress() {
		t.Fatalf("change address = %q, want %q", v.Outputs[1].Address, ownAddr.EncodeAddress())
	}
}
