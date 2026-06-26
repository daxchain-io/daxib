package coinselect_test

import (
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/mempool"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"github.com/daxchain-io/daxib/internal/coinselect"
)

// TestDustThresholdPinnedToBtcd pins the inlined DustThresholdP2WPKH constant to
// btcd's own mempool.GetDustThreshold for a witness-v0 P2WPKH output at the
// default min-relay fee. If a future btcd bump (or a fat-finger of the constant)
// changes the dust math, this test goes red — the constant can never drift.
func TestDustThresholdPinnedToBtcd(t *testing.T) {
	var program [20]byte
	for i := range program {
		program[i] = byte(i)
	}
	addr, err := btcutil.NewAddressWitnessPubKeyHash(program[:], &chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("address: %v", err)
	}
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatalf("PayToAddrScript: %v", err)
	}
	if !txscript.IsWitnessProgram(pkScript) {
		t.Fatalf("expected a witness program script: %x", pkScript)
	}

	txOut := wire.NewTxOut(0, pkScript)
	want := int64(mempool.GetDustThreshold(txOut))
	if coinselect.DustThresholdP2WPKH != want {
		t.Fatalf("DustThresholdP2WPKH=%d but btcd mempool.GetDustThreshold=%d at DefaultMinRelayTxFee=%d — the inlined constant has drifted",
			coinselect.DustThresholdP2WPKH, want, mempool.DefaultMinRelayTxFee)
	}
}

// TestIsDust exercises the exact dust boundary (293 dust, 294 not).
func TestIsDust(t *testing.T) {
	if !coinselect.IsDust(293) {
		t.Errorf("293 sat should be dust")
	}
	if coinselect.IsDust(294) {
		t.Errorf("294 sat should NOT be dust (the threshold is inclusive)")
	}
	if !coinselect.IsDust(0) {
		t.Errorf("0 sat should be dust")
	}
}
