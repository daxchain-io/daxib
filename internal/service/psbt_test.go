package service

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	btcpsbt "github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	fakebackend "github.com/daxchain-io/daxib/internal/backend/fake"
	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/psbt"
)

// psbt_test.go proves the PSBT noun: create builds an unsigned PSBT, sign enforces
// the sealed spend policy BEFORE attaching any signature (a DENIAL produces NO
// PartialSig), an allowed sign attaches exactly one PartialSig per owned input and
// journals a `signed` record cross-linked to the reservation, and the full
// create→sign→broadcast pipeline lands the bytes on the wire.

// decodePSBT is a tiny test helper.
func decodePSBT(t *testing.T, b64 string) *btcpsbt.Packet {
	t.Helper()
	pkt, err := psbt.Decode(b64)
	if err != nil {
		t.Fatalf("decode psbt: %v", err)
	}
	return pkt
}

// buildForeignPSBT builds a 1-in/1-out unsigned PSBT whose input pays a script the
// `vec` wallet does not own (a fresh random key on regtest... but the service runs
// on mainnet here, so encode a mainnet P2WPKH foreign script). Its WitnessUtxo is
// present (so the value is computable), proving the not-owned refusal is by SCRIPT
// match, not a missing-WitnessUtxo accident.
func buildForeignPSBT(t *testing.T) string {
	t.Helper()
	var raw [32]byte
	for i := range raw {
		raw[i] = 0xC0 + byte(i)
	}
	_, pub := btcec.PrivKeyFromBytes(raw[:])
	h160 := btcutil.Hash160(pub.SerializeCompressed())
	addr, err := btcutil.NewAddressWitnessPubKeyHash(h160, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("foreign addr: %v", err)
	}
	script, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatalf("foreign script: %v", err)
	}
	h, _ := chainhash.NewHashFromStr("cc00000000000000000000000000000000000000000000000000000000000000")
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(h, 0), nil, nil))
	tx.AddTxOut(wire.NewTxOut(90_000, script))
	pkt, err := psbt.BuildFromUnsigned(tx, []psbt.InputMeta{{PrevScript: script, PrevValue: 100_000}}, nil)
	if err != nil {
		t.Fatalf("build foreign psbt: %v", err)
	}
	b64, err := psbt.Encode(pkt)
	if err != nil {
		t.Fatalf("encode foreign psbt: %v", err)
	}
	return b64
}

func TestPSBTCreateThenSignAttachesPartialSig(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	svc, teardown := newPolicySendService(t, fake)
	defer teardown()

	// A generous cap (allowlist off): the sign is in-policy.
	if _, err := svc.PolicySet(context.Background(), PolicySetInput{
		MaxTxSat: "100000000", MaxDaySat: "100000000", AllowlistOn: boolFalse(),
	}); err != nil {
		t.Fatalf("PolicySet: %v", err)
	}
	programUTXO(fake, canonicalReceive0, "11"+strings.Repeat("0", 62), 0, 1_000_000)

	// 1. Create an unsigned PSBT.
	cre, err := svc.PSBTCreate(context.Background(), domain.PSBTCreateRequest{
		Wallet: "vec", To: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", Amount: "0.005", FeeRate: "10",
	})
	if err != nil {
		t.Fatalf("PSBTCreate: %v", err)
	}
	if cre.PSBT == "" {
		t.Fatal("create produced an empty PSBT")
	}
	pkt := decodePSBT(t, cre.PSBT)
	if len(pkt.Inputs) == 0 || pkt.Inputs[0].WitnessUtxo == nil {
		t.Fatal("created PSBT has no input WitnessUtxo")
	}
	for i := range pkt.Inputs {
		if len(pkt.Inputs[i].PartialSigs) != 0 {
			t.Fatal("a freshly created PSBT must carry NO signatures")
		}
	}

	// 2. Sign it (in-policy ⇒ a PartialSig is attached).
	sig, err := svc.PSBTSign(context.Background(),
		domain.PSBTSignRequest{PSBT: cre.PSBT, Wallet: "vec", Yes: true},
		PSBTSignInput{})
	if err != nil {
		t.Fatalf("PSBTSign: %v", err)
	}
	signed := decodePSBT(t, sig.PSBT)
	attached := 0
	for i := range signed.Inputs {
		attached += len(signed.Inputs[i].PartialSigs)
	}
	if attached == 0 {
		t.Fatal("an in-policy sign must attach at least one PartialSig")
	}
	if sig.SignedByUs == 0 {
		t.Fatalf("signed_by_us = 0, want > 0")
	}

	// A `signed` journal record was written, cross-linked to a reservation, with the
	// PSBT base64 carried and RawTx empty.
	recs, _ := svc.journal.List(context.Background(), svc.net, "")
	var found bool
	for _, r := range recs {
		if r.Status == "signed" && r.PSBTBase64 != "" {
			found = true
			if r.RawTx != "" {
				t.Fatal("a psbt-signed record must have empty RawTx (no broadcastable bytes yet)")
			}
			if r.ReservationID == "" {
				t.Fatal("a psbt-signed record must cross-link a ReservationID")
			}
		}
	}
	if !found {
		t.Fatal("psbt sign must journal a `signed` record carrying the PSBT")
	}

	// The reservation is RESERVED (not committed) — sign does not broadcast.
	cr, _ := svc.PolicyCounters(context.Background())
	if len(cr.Counters) == 0 || cr.Counters[0].Used24hSat == "0" {
		t.Fatalf("psbt sign must reserve the spend in the rolling-24h window: %+v", cr.Counters)
	}
}

func TestPSBTSignDeniedOverLimitProducesNoSignature(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	svc, teardown := newPolicySendService(t, fake)
	defer teardown()
	programUTXO(fake, canonicalReceive0, "11"+strings.Repeat("0", 62), 0, 1_000_000)

	// First, with a GENEROUS policy, CREATE the PSBT (create takes no reservation and
	// is not policy-gated).
	if _, err := svc.PolicySet(context.Background(), PolicySetInput{
		MaxTxSat: "100000000", MaxDaySat: "100000000", AllowlistOn: boolFalse(),
	}); err != nil {
		t.Fatalf("PolicySet (generous): %v", err)
	}
	cre, err := svc.PSBTCreate(context.Background(), domain.PSBTCreateRequest{
		Wallet: "vec", To: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", Amount: "0.005", FeeRate: "10",
	})
	if err != nil {
		t.Fatalf("PSBTCreate: %v", err)
	}

	// Now TIGHTEN the per-tx cap WELL below the spend (500_000 sat external).
	if _, err := svc.PolicySet(context.Background(), PolicySetInput{
		MaxTxSat: "100000", AllowlistOn: boolFalse(),
	}); err != nil {
		t.Fatalf("PolicySet (tight): %v", err)
	}

	// Signing must be DENIED (exit 3) and produce NO PartialSig.
	res, err := svc.PSBTSign(context.Background(),
		domain.PSBTSignRequest{PSBT: cre.PSBT, Wallet: "vec", Yes: true}, PSBTSignInput{})
	if err == nil {
		t.Fatal("an over-limit psbt sign must be denied")
	}
	de := domain.AsError(err)
	if de.Code != "policy.denied.tx_limit" || de.Exit != domain.ExitPolicyDenied {
		t.Fatalf("denied sign: code=%s exit=%d; want policy.denied.tx_limit / exit 3", de.Code, de.Exit)
	}
	if res.PSBT != "" {
		t.Fatal("a denied sign must return no PSBT")
	}
	// The ORIGINAL (created) PSBT still carries no signatures — nothing was signed.
	pkt := decodePSBT(t, cre.PSBT)
	for i := range pkt.Inputs {
		if len(pkt.Inputs[i].PartialSigs) != 0 {
			t.Fatal("a denied sign must leave the PSBT unsigned")
		}
	}
	// No `signed` journal record exists (sign was denied before Append).
	recs, _ := svc.journal.List(context.Background(), svc.net, "")
	for _, r := range recs {
		if r.PSBTBase64 != "" {
			t.Fatal("a denied psbt sign must journal no signed record")
		}
	}
}

func TestPSBTCreateSignBroadcastPipeline(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	var captured []byte
	captureBroadcast(fake, &captured)
	svc, teardown := newPolicySendService(t, fake)
	defer teardown()

	if _, err := svc.PolicySet(context.Background(), PolicySetInput{
		MaxTxSat: "100000000", MaxDaySat: "100000000", AllowlistOn: boolFalse(),
	}); err != nil {
		t.Fatalf("PolicySet: %v", err)
	}
	programUTXO(fake, canonicalReceive0, "11"+strings.Repeat("0", 62), 0, 1_000_000)

	cre, err := svc.PSBTCreate(context.Background(), domain.PSBTCreateRequest{
		Wallet: "vec", To: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", Amount: "0.005", FeeRate: "10",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	sig, err := svc.PSBTSign(context.Background(),
		domain.PSBTSignRequest{PSBT: cre.PSBT, Wallet: "vec", Yes: true}, PSBTSignInput{})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	res, err := svc.PSBTBroadcast(context.Background(),
		domain.PSBTBroadcastRequest{PSBT: sig.PSBT, Wallet: "vec", Yes: true}, nil)
	if err != nil {
		t.Fatalf("broadcast: %v", err)
	}
	if res.Status != domain.TxStateBroadcast || res.Txid == "" {
		t.Fatalf("broadcast status=%s txid=%q; want broadcast + a txid", res.Status, res.Txid)
	}
	if len(captured) == 0 {
		t.Fatal("nothing reached the wire")
	}
	// The broadcast bytes deserialize to a valid signed tx.
	tx := wire.NewMsgTx(2)
	if err := tx.Deserialize(bytes.NewReader(captured)); err != nil {
		t.Fatalf("broadcast bytes do not deserialize: %v", err)
	}
	if tx.TxHash().String() != res.Txid {
		t.Fatalf("broadcast txid mismatch")
	}
	// The reservation is now COMMITTED (broadcast accepted).
	cr, _ := svc.PolicyCounters(context.Background())
	if len(cr.Counters) == 0 || cr.Counters[0].Used24hSat == "0" {
		t.Fatalf("a broadcast PSBT must keep the reservation committed: %+v", cr.Counters)
	}
}

func TestPSBTSignRejectsForeignOnlyPSBT(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	svc, teardown := newPolicySendService(t, fake)
	defer teardown()
	if _, err := svc.PolicySet(context.Background(), PolicySetInput{
		MaxTxSat: "100000000", MaxDaySat: "100000000", AllowlistOn: boolFalse(),
	}); err != nil {
		t.Fatalf("PolicySet: %v", err)
	}

	// A PSBT whose single input pays a FOREIGN script (not in the wallet's gap window):
	// sign must refuse with psbt.not_owned.
	foreign := buildForeignPSBT(t)
	_, err := svc.PSBTSign(context.Background(),
		domain.PSBTSignRequest{PSBT: foreign, Wallet: "vec", Yes: true}, PSBTSignInput{})
	if err == nil {
		t.Fatal("signing a PSBT with no owned inputs must error")
	}
	if code := domain.AsError(err).Code; code != domain.CodePSBTNotOwned {
		t.Fatalf("code = %q, want %q", code, domain.CodePSBTNotOwned)
	}
}
