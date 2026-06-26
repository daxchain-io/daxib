package keys

import (
	"context"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/secret"
)

// TestSignInputsEngineVerifies imports the canonical vector wallet, builds a tx
// spending its receive-0 and receive-1 P2WPKH outputs, signs every input via the
// keystore signing path, and runs txscript.NewEngine on each input with
// StandardVerifyFlags. A passing engine PROVES the keystore derived the correct
// (branch,index)→private key and produced a real, spendable BIP-143 signature.
func TestSignInputsEngineVerifies(t *testing.T) {
	s := openLight(t)
	ctx := context.Background()

	if _, err := s.ImportWallet(ctx, "vec", domain.NetworkMainnet,
		secret.NewString(canonicalMnemonic), nil, pass("pw"), pass("pw")); err != nil {
		t.Fatalf("ImportWallet: %v", err)
	}

	// Compute the receive-0 and receive-1 pkScripts (the prevouts being spent).
	_, scan, err := s.ScanAddresses(ctx, "vec", 2)
	if err != nil {
		t.Fatalf("ScanAddresses: %v", err)
	}
	// Pick the two receive-branch addresses at index 0 and 1.
	type in struct {
		branch domain.Branch
		index  uint32
		script []byte
		value  int64
	}
	var ins []in
	for _, a := range scan {
		if a.Branch == domain.BranchReceive && a.Index < 2 {
			script := addrToScript(t, a.Address)
			ins = append(ins, in{branch: a.Branch, index: a.Index, script: script, value: 500_000})
		}
	}
	if len(ins) != 2 {
		t.Fatalf("expected 2 receive inputs, got %d", len(ins))
	}

	// Build the unsigned tx (2 inputs, 1 output to receive-0 again).
	tx := wire.NewMsgTx(2)
	specs := make([]InputSigningSpec, 0, len(ins))
	for i, inp := range ins {
		var hb [32]byte
		hb[0] = byte(i + 1)
		h, herr := chainhash.NewHash(hb[:])
		if herr != nil {
			t.Fatalf("NewHash: %v", herr)
		}
		txin := wire.NewTxIn(wire.NewOutPoint(h, uint32(i)), nil, nil)
		txin.Sequence = 0xfffffffd
		tx.AddTxIn(txin)
		specs = append(specs, InputSigningSpec{
			Index:      i,
			Branch:     inp.branch,
			AddrIndex:  inp.index,
			PrevScript: inp.script,
			PrevValue:  inp.value,
		})
	}
	tx.AddTxOut(wire.NewTxOut(900_000, ins[0].script)) // 100k to fee

	if err := s.SignInputs(ctx, "vec", pass("pw"), tx, specs); err != nil {
		t.Fatalf("SignInputs: %v", err)
	}

	// Engine-verify each input.
	prevOuts := make(map[wire.OutPoint]*wire.TxOut, len(ins))
	for i := range tx.TxIn {
		prevOuts[tx.TxIn[i].PreviousOutPoint] = wire.NewTxOut(ins[i].value, ins[i].script)
	}
	fetcher := txscript.NewMultiPrevOutFetcher(prevOuts)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)
	for i := range tx.TxIn {
		if len(tx.TxIn[i].Witness) == 0 {
			t.Fatalf("input %d has no witness — SignInputs did not sign it", i)
		}
		eng, eerr := txscript.NewEngine(ins[i].script, tx, i, txscript.StandardVerifyFlags, nil, sigHashes, ins[i].value, fetcher)
		if eerr != nil {
			t.Fatalf("NewEngine input %d: %v", i, eerr)
		}
		if eerr := eng.Execute(); eerr != nil {
			t.Fatalf("engine.Execute input %d FAILED (bad key/sig): %v", i, eerr)
		}
	}
}

// TestSignInputsWrongPassphrase proves a wrong passphrase fails closed (exit 4)
// before any signing.
func TestSignInputsWrongPassphrase(t *testing.T) {
	s := openLight(t)
	ctx := context.Background()
	if _, err := s.ImportWallet(ctx, "vec", domain.NetworkMainnet,
		secret.NewString(canonicalMnemonic), nil, pass("pw"), pass("pw")); err != nil {
		t.Fatalf("ImportWallet: %v", err)
	}
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	err := s.SignInputs(ctx, "vec", pass("wrong-pw"), tx, []InputSigningSpec{{Index: 0}})
	if code := codeOf(t, err); code != CodeKeystoreBadPassphrase {
		t.Fatalf("wrong passphrase code=%s, want %s", code, CodeKeystoreBadPassphrase)
	}
}

// addrToScript decodes a bech32 P2WPKH address to its scriptPubKey.
func addrToScript(t *testing.T, addr string) []byte {
	t.Helper()
	a, err := btcutil.DecodeAddress(addr, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("DecodeAddress %q: %v", addr, err)
	}
	script, err := txscript.PayToAddrScript(a)
	if err != nil {
		t.Fatalf("PayToAddrScript: %v", err)
	}
	return script
}
