package service

import (
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

// psbt_defects_test.go is the regression suite for the confirmed PSBT defects: the
// allowlist/denylist destination-gate bypass via a non-standard (address-less)
// recipient output, the nil-pointer panic on a partially-owned (co-signer) PSBT,
// the multisig over-charge of a co-signer's contributed value, the unverified
// fee-rate cap, and the Combine in-place mutation.

// ownedScript returns the wallet's receive[0] P2WPKH scriptPubKey (canonicalReceive0)
// so a test can build a PSBT spending a wallet-OWNED input.
func ownedScript(t *testing.T) []byte {
	t.Helper()
	addr, err := btcutil.DecodeAddress(canonicalReceive0, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("decode owned addr: %v", err)
	}
	sc, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatalf("owned script: %v", err)
	}
	return sc
}

// nonStandardScript is a witness-v2 output script (OP_2 <32 bytes>): relay-standard
// for forward-compat but ExtractPkScriptAddrs renders no single address, so
// AddressFromScript returns "" — the leg the allowlist gate used to skip.
func nonStandardScript(t *testing.T) []byte {
	t.Helper()
	b := txscript.NewScriptBuilder()
	b.AddOp(txscript.OP_2)
	var data [32]byte
	for i := range data {
		data[i] = byte(0xA0 + i)
	}
	b.AddData(data[:])
	sc, err := b.Script()
	if err != nil {
		t.Fatalf("non-standard script: %v", err)
	}
	if psbt.AddressFromScript(sc, &chaincfg.MainNetParams) != "" {
		t.Fatal("precondition: non-standard script must render to NO address")
	}
	return sc
}

// foreignP2WPKHScript builds a standard P2WPKH script for a deterministic key the
// `vec` wallet does NOT own (a co-signer leg).
func foreignP2WPKHScript(t *testing.T, seed byte) []byte {
	t.Helper()
	var raw [32]byte
	for i := range raw {
		raw[i] = seed + byte(i)
	}
	_, pub := btcec.PrivKeyFromBytes(raw[:])
	h160 := btcutil.Hash160(pub.SerializeCompressed())
	addr, err := btcutil.NewAddressWitnessPubKeyHash(h160, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("foreign addr: %v", err)
	}
	sc, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatalf("foreign script: %v", err)
	}
	return sc
}

// psbtInput is one input spec for buildOwnedPSBT.
type psbtInput struct {
	script   []byte
	value    int64
	hashByte byte
}

// psbtOutput is one output spec for buildOwnedPSBT.
type psbtOutput struct {
	script []byte
	value  int64
}

// buildOwnedPSBT builds an unsigned PSBT with the given inputs/outputs, attaching a
// WitnessUtxo to every input (so values are computable and the foreign-input sighash
// fetcher can be seeded).
func buildOwnedPSBT(t *testing.T, ins []psbtInput, outs []psbtOutput) string {
	t.Helper()
	tx := wire.NewMsgTx(2)
	metas := make([]psbt.InputMeta, len(ins))
	for i, in := range ins {
		hb := in.hashByte
		if hb == 0 {
			hb = byte(0x11 + i)
		}
		var hbytes [32]byte
		for j := range hbytes {
			hbytes[j] = hb
		}
		h, err := chainhash.NewHash(hbytes[:])
		if err != nil {
			t.Fatalf("input hash: %v", err)
		}
		tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(h, uint32(i)), nil, nil))
		metas[i] = psbt.InputMeta{PrevScript: in.script, PrevValue: in.value}
	}
	for _, o := range outs {
		tx.AddTxOut(wire.NewTxOut(o.value, o.script))
	}
	pkt, err := psbt.BuildFromUnsigned(tx, metas, nil)
	if err != nil {
		t.Fatalf("build psbt: %v", err)
	}
	b64, err := psbt.Encode(pkt)
	if err != nil {
		t.Fatalf("encode psbt: %v", err)
	}
	return b64
}

// programOwnedUTXO programs the fake backend so the wallet's owned input outpoint is
// re-verifiable against the live UTXO set at the given value.
func programOwnedUTXO(fake *fakebackend.Client, value int64) (txidHex string) {
	txidHex = strings.Repeat("11", 32)
	programUTXO(fake, canonicalReceive0, txidHex, 0, value)
	return txidHex
}

// TestPSBTSign_AllowlistBypassNonStandardOutputDenied is the regression for the
// allowlist destination-gate bypass: with the allowlist ON and a legit allowlisted
// external[0], a SECOND non-standard (address-less) external sink must NOT slip
// through ungated. The whole sign must be DENIED and NO PartialSig produced.
func TestPSBTSign_AllowlistBypassNonStandardOutputDenied(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	svc, teardown := newPolicySendService(t, fake)
	defer teardown()

	programOwnedUTXO(fake, 1_000_000)

	// Generous caps, allowlist ON, only the legit recipient pinned.
	on := true
	if _, err := svc.PolicySet(context.Background(), domain.LocalCLI(), PolicySetInput{
		MaxTxSat: "100000000", MaxDaySat: "100000000", AllowlistOn: &on,
	}); err != nil {
		t.Fatalf("PolicySet: %v", err)
	}
	const legit = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
	if _, err := svc.PolicyAllow(context.Background(), domain.LocalCLI(), PolicyPinInput{Address: legit}); err != nil {
		t.Fatalf("PolicyAllow: %v", err)
	}

	legitAddr, _ := btcutil.DecodeAddress(legit, &chaincfg.MainNetParams)
	legitScript, _ := txscript.PayToAddrScript(legitAddr)

	// out0 = allowlisted legit (anchors external[0]); out1 = non-standard sink.
	b64 := buildOwnedPSBT(t,
		[]psbtInput{{script: ownedScript(t), value: 1_000_000}},
		[]psbtOutput{
			{script: legitScript, value: 10_000},
			{script: nonStandardScript(t), value: 980_000},
		})

	res, err := svc.PSBTSign(context.Background(), domain.LocalCLI(),
		domain.PSBTSignRequest{PSBT: b64, Wallet: "vec", Yes: true}, PSBTSignInput{})
	if err == nil {
		t.Fatal("BYPASS: a non-standard non-allowlisted sink rode along ungated — sign must be DENIED")
	}
	if code := domain.AsError(err).Code; code != "policy.denied.not_allowlisted" {
		t.Fatalf("denied code = %q, want policy.denied.not_allowlisted", code)
	}
	if res.PSBT != "" {
		t.Fatal("a denied sign must return no PSBT")
	}
}

// TestPSBTSign_AllowlistAllowsLegitOnly is the positive control: with the allowlist
// ON and the sole external recipient allowlisted (no non-standard sink), the sign
// succeeds. Proves the deny in the bypass test is caused by the non-standard leg, not
// by gating every sign under an allowlist.
func TestPSBTSign_AllowlistAllowsLegitOnly(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	svc, teardown := newPolicySendService(t, fake)
	defer teardown()
	programOwnedUTXO(fake, 1_000_000)

	on := true
	if _, err := svc.PolicySet(context.Background(), domain.LocalCLI(), PolicySetInput{
		MaxTxSat: "100000000", MaxDaySat: "100000000", AllowlistOn: &on,
	}); err != nil {
		t.Fatalf("PolicySet: %v", err)
	}
	const legit = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
	if _, err := svc.PolicyAllow(context.Background(), domain.LocalCLI(), PolicyPinInput{Address: legit}); err != nil {
		t.Fatalf("PolicyAllow: %v", err)
	}
	legitAddr, _ := btcutil.DecodeAddress(legit, &chaincfg.MainNetParams)
	legitScript, _ := txscript.PayToAddrScript(legitAddr)

	b64 := buildOwnedPSBT(t,
		[]psbtInput{{script: ownedScript(t), value: 1_000_000}},
		[]psbtOutput{{script: legitScript, value: 500_000}})

	res, err := svc.PSBTSign(context.Background(), domain.LocalCLI(),
		domain.PSBTSignRequest{PSBT: b64, Wallet: "vec", Yes: true}, PSBTSignInput{})
	if err != nil {
		t.Fatalf("an allowlisted-only sign must succeed: %v", err)
	}
	if res.SignedByUs == 0 {
		t.Fatal("expected a PartialSig on the owned input")
	}
}

// TestPSBTSign_NonStandardSinkUnderNoAllowlistPermitted proves the fix does not
// over-block: with NO allowlist (the default), a non-standard output is permitted
// (the destination guardrail is opt-in), exactly like `tx send` to any address —
// the per-tx/day caps still bound it.
func TestPSBTSign_NonStandardSinkUnderNoAllowlistPermitted(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	svc, teardown := newPolicySendService(t, fake)
	defer teardown()
	programOwnedUTXO(fake, 1_000_000)

	if _, err := svc.PolicySet(context.Background(), domain.LocalCLI(), PolicySetInput{
		MaxTxSat: "100000000", MaxDaySat: "100000000", AllowlistOn: boolFalse(),
	}); err != nil {
		t.Fatalf("PolicySet: %v", err)
	}

	b64 := buildOwnedPSBT(t,
		[]psbtInput{{script: ownedScript(t), value: 1_000_000}},
		[]psbtOutput{{script: nonStandardScript(t), value: 900_000}})

	res, err := svc.PSBTSign(context.Background(), domain.LocalCLI(),
		domain.PSBTSignRequest{PSBT: b64, Wallet: "vec", Yes: true}, PSBTSignInput{})
	if err != nil {
		t.Fatalf("a non-standard sink under no allowlist must be permitted: %v", err)
	}
	if res.SignedByUs == 0 {
		t.Fatal("expected a PartialSig on the owned input")
	}
}

// TestPSBTSign_ForeignInputDoesNotPanic is the regression for the nil-pointer
// SIGSEGV on a partially-owned PSBT: one owned input + one FOREIGN co-signer input.
// The owned input must sign without the missing foreign prevout crashing
// NewTxSigHashes; the foreign input stays unsigned.
func TestPSBTSign_ForeignInputDoesNotPanic(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	svc, teardown := newPolicySendService(t, fake)
	defer teardown()
	programOwnedUTXO(fake, 1_000_000)

	if _, err := svc.PolicySet(context.Background(), domain.LocalCLI(), PolicySetInput{
		MaxTxSat: "100000000", MaxDaySat: "100000000", AllowlistOn: boolFalse(),
	}); err != nil {
		t.Fatalf("PolicySet: %v", err)
	}

	dest := foreignP2WPKHScript(t, 0xC0)
	b64 := buildOwnedPSBT(t,
		[]psbtInput{
			{script: ownedScript(t), value: 1_000_000, hashByte: 0x11},
			{script: foreignP2WPKHScript(t, 0x40), value: 5_000_000, hashByte: 0x22}, // FOREIGN co-signer input
		},
		[]psbtOutput{{script: dest, value: 500_000}})

	res, err := svc.PSBTSign(context.Background(), domain.LocalCLI(),
		domain.PSBTSignRequest{PSBT: b64, Wallet: "vec", Yes: true}, PSBTSignInput{})
	if err != nil {
		t.Fatalf("a partially-owned PSBT must sign the owned input without panicking: %v", err)
	}
	signed := decodePSBT(t, res.PSBT)
	if len(signed.Inputs[0].PartialSigs) != 1 {
		t.Fatalf("owned input must carry exactly one PartialSig, got %d", len(signed.Inputs[0].PartialSigs))
	}
	if len(signed.Inputs[1].PartialSigs) != 0 {
		t.Fatal("the foreign co-signer input must be left unsigned")
	}
}

// TestPSBTSign_MultisigChargesOnlyWalletOutflow is the regression for the
// over-charge: a co-signer funds the bulk of a large external output, but the
// wallet's true net outflow (ownedInputSat - changeBackSat) is tiny. With a per-tx
// cap above the wallet's net outflow but BELOW the full external value, the sign must
// SUCCEED (the co-signer's contributed value is never charged to this wallet).
func TestPSBTSign_MultisigChargesOnlyWalletOutflow(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	svc, teardown := newPolicySendService(t, fake)
	defer teardown()
	programOwnedUTXO(fake, 1_000_000)

	// cap = 2_000_000: ABOVE the wallet's net outflow (1_000_000) but BELOW the full
	// external output (5_500_000). The old code charged externalOutSat=5_500_000 and
	// falsely denied; the fix charges only the wallet's netOut.
	if _, err := svc.PolicySet(context.Background(), domain.LocalCLI(), PolicySetInput{
		MaxTxSat: "2000000", MaxDaySat: "100000000", AllowlistOn: boolFalse(),
	}); err != nil {
		t.Fatalf("PolicySet: %v", err)
	}

	dest := foreignP2WPKHScript(t, 0xC0)
	b64 := buildOwnedPSBT(t,
		[]psbtInput{
			{script: ownedScript(t), value: 1_000_000, hashByte: 0x11},
			{script: foreignP2WPKHScript(t, 0x40), value: 5_000_000, hashByte: 0x22}, // co-signer funds the bulk
		},
		[]psbtOutput{{script: dest, value: 5_500_000}})

	res, err := svc.PSBTSign(context.Background(), domain.LocalCLI(),
		domain.PSBTSignRequest{PSBT: b64, Wallet: "vec", Yes: true}, PSBTSignInput{})
	if err != nil {
		t.Fatalf("a multisig sign the wallet only partly funds must charge ONLY its net outflow, not the co-signer's value: %v", err)
	}
	if res.SignedByUs == 0 {
		t.Fatal("expected a PartialSig on the owned input")
	}

	// The reservation must reflect the wallet's net outflow (1_000_000), NOT the full
	// 5_500_000 external output.
	cr, _ := svc.PolicyCounters(context.Background(), domain.LocalCLI())
	if len(cr.Counters) == 0 || cr.Counters[0].Used24hSat != "1000000" {
		t.Fatalf("multisig sign must charge the wallet's net outflow (1000000), got %+v", cr.Counters)
	}
}

// TestPSBTSign_UnderstatedOwnedValueReverifiedAgainstBackend is the regression for
// the fee-rate cap evaluated against unverified WitnessUtxo values (all-owned case):
// a hostile PSBT understates the owned input's WitnessUtxo.Value to deflate the
// apparent fee/rate. The backend re-verification of the OWNED value (and the
// verified-value fee-rate computation) must surface the true outflow and deny under
// a tight per-tx cap.
func TestPSBTSign_UnderstatedOwnedValueReverifiedAgainstBackend(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	svc, teardown := newPolicySendService(t, fake)
	defer teardown()
	// The LIVE owned value is 1_000_000.
	programOwnedUTXO(fake, 1_000_000)

	// per-tx cap 600_000: a 900_000-sat external spend (true net outflow 1_000_000)
	// must be DENIED.
	if _, err := svc.PolicySet(context.Background(), domain.LocalCLI(), PolicySetInput{
		MaxTxSat: "600000", MaxDaySat: "100000000", AllowlistOn: boolFalse(),
	}); err != nil {
		t.Fatalf("PolicySet: %v", err)
	}

	dest := foreignP2WPKHScript(t, 0xC0)
	// The PSBT UNDERSTATES the owned input value to 650_000 (just above the 600k cap
	// for the *understated* fee math) while paying 900_000 out — impossible unless the
	// value is a lie. Backend re-verification restores 1_000_000.
	b64 := buildOwnedPSBT(t,
		[]psbtInput{{script: ownedScript(t), value: 650_000}},
		[]psbtOutput{{script: dest, value: 900_000}})

	_, err := svc.PSBTSign(context.Background(), domain.LocalCLI(),
		domain.PSBTSignRequest{PSBT: b64, Wallet: "vec", Yes: true}, PSBTSignInput{})
	if err == nil {
		t.Fatal("an understated-value PSBT must be re-verified against the backend and DENIED over the cap")
	}
	if code := domain.AsError(err).Code; code != "policy.denied.tx_limit" {
		t.Fatalf("denied code = %q, want policy.denied.tx_limit", code)
	}
}

// TestPSBTCombine_DoesNotMutateInput is the regression for Combine mutating its
// first argument in place: combining must not alter any caller-supplied packet.
func TestPSBTCombine_DoesNotMutateInput(t *testing.T) {
	owned := ownedScript(t)
	a := buildOwnedPSBT(t,
		[]psbtInput{{script: owned, value: 1_000_000}, {script: foreignP2WPKHScript(t, 0x40), value: 2_000_000}},
		[]psbtOutput{{script: foreignP2WPKHScript(t, 0xC0), value: 2_800_000}})

	pktA := decodePSBT(t, a)
	pktB := decodePSBT(t, a)
	// Attach a PartialSig to input[1] of B only.
	_, pub := btcec.PrivKeyFromBytes([]byte(strings.Repeat("k", 32)))
	pktB.Inputs[1].PartialSigs = append(pktB.Inputs[1].PartialSigs, &btcpsbt.PartialSig{
		PubKey:    pub.SerializeCompressed(),
		Signature: []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01},
	})

	before := len(pktA.Inputs[1].PartialSigs)
	if _, err := psbt.Combine([]*btcpsbt.Packet{pktA, pktB}); err != nil {
		t.Fatalf("Combine: %v", err)
	}
	after := len(pktA.Inputs[1].PartialSigs)
	if before != after {
		t.Fatalf("Combine MUTATED its first argument in place (input1 PartialSigs %d -> %d)", before, after)
	}
}
