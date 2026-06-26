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

// TestDustThresholdForScriptPinnedToBtcd pins the per-script dust formula
// (CB-4) to btcd's mempool.GetDustThreshold across the address types daxib can pay:
// P2WPKH (witness v0), P2TR (witness v1), and legacy P2PKH/P2SH. If a btcd bump or
// a fat-finger changes the math for any script type, this goes red.
func TestDustThresholdForScriptPinnedToBtcd(t *testing.T) {
	mkScript := func(addr btcutil.Address) []byte {
		s, err := txscript.PayToAddrScript(addr)
		if err != nil {
			t.Fatalf("script: %v", err)
		}
		return s
	}
	var h20 [20]byte
	var h32 [32]byte
	for i := range h20 {
		h20[i] = byte(i)
	}
	for i := range h32 {
		h32[i] = byte(i)
	}
	p2wpkh, _ := btcutil.NewAddressWitnessPubKeyHash(h20[:], &chaincfg.MainNetParams)
	p2tr, _ := btcutil.NewAddressTaproot(h32[:], &chaincfg.MainNetParams)
	p2pkh, _ := btcutil.NewAddressPubKeyHash(h20[:], &chaincfg.MainNetParams)
	p2sh, _ := btcutil.NewAddressScriptHashFromHash(h20[:], &chaincfg.MainNetParams)

	for _, addr := range []btcutil.Address{p2wpkh, p2tr, p2pkh, p2sh} {
		script := mkScript(addr)
		got := coinselect.DustThresholdForScript(script)
		want := int64(mempool.GetDustThreshold(wire.NewTxOut(0, script)))
		if got != want {
			t.Errorf("DustThresholdForScript(%T) = %d, btcd = %d (script len %d)", addr, got, want, len(script))
		}
	}

	// The P2TR per-script threshold must exceed the P2WPKH 294 (a 43-vB output costs
	// more to keep relayable), so a sub-330 Taproot send is correctly dust.
	p2trThreshold := coinselect.DustThresholdForScript(mkScript(p2tr))
	if p2trThreshold <= coinselect.DustThresholdP2WPKH {
		t.Errorf("P2TR dust threshold %d should exceed the P2WPKH 294", p2trThreshold)
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
