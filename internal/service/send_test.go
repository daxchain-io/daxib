package service

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"github.com/daxchain-io/daxib/internal/backend"
	fakebackend "github.com/daxchain-io/daxib/internal/backend/fake"
	"github.com/daxchain-io/daxib/internal/domain"
)

// The canonical vector wallet's first change address (m/84'/0'/0'/1/0). The send
// pipeline derives change here on the first send.
const canonicalChange0 = "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"

// newSendService opens a service over a temp keystore + config + state dir with a
// FAKE backend injected via Dial, imports the canonical vector wallet, and returns
// the service + the fake.
func newSendService(t *testing.T, fake *fakebackend.Client) (*Service, func()) {
	t.Helper()
	keystoreDir := t.TempDir()
	configDir := t.TempDir()
	stateDir := t.TempDir()
	env := map[string]string{
		"DAXIB_KEYSTORE":           keystoreDir,
		"DAXIB_KDF_LIGHT":          "1",
		"DAXIB_PASSPHRASE":         "test-pass-12345678",
		"DAXIB_PASSPHRASE_CONFIRM": "test-pass-12345678",
	}
	svc, err := Open(context.Background(), Options{
		Keystore: keystoreDir,
		Config:   configDir,
		State:    stateDir,
		Network:  "mainnet",
		KDFLight: true,
		Dial: func(_ context.Context, _ backend.Options) (backend.Client, error) {
			return fake, nil
		},
		Secret: SecretIO{
			Stdin:     strings.NewReader(canonicalMnemonic),
			LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok },
			IsTTY:     func() bool { return false },
			Prompt:    func(string) ([]byte, error) { return nil, io.EOF },
		},
	})
	if err != nil {
		t.Fatalf("service.Open: %v", err)
	}
	// Register + select a (fake) backend so resolveBackend succeeds; the URL is
	// irrelevant since Dial is injected.
	if _, _, err := svc.BackendAdd(context.Background(), domain.BackendAddRequest{
		Name: "fake-x", Network: "mainnet", Type: domain.BackendEsplora, URL: "http://fake",
	}); err != nil {
		t.Fatalf("BackendAdd: %v", err)
	}
	if _, err := svc.BackendUse(context.Background(), domain.BackendUseRequest{Name: "fake-x"}); err != nil {
		t.Fatalf("BackendUse: %v", err)
	}
	importCanonical(t, svc, "vec")
	return svc, func() { _ = svc.Close() }
}

// programUTXO programs the fake with a confirmed UTXO of value sat on addr.
func programUTXO(fake *fakebackend.Client, addr, txid string, vout uint32, value int64) {
	fake.UTXOsByAddr[addr] = append(fake.UTXOsByAddr[addr], domain.UTXO{
		Txid: txid, Vout: vout, Address: addr, ValueSat: value, Height: 800000, Confirmations: 6,
	})
}

// captureBroadcast installs a BroadcastFn that records the raw bytes and returns
// the tx's real txid.
func captureBroadcast(fake *fakebackend.Client, captured *[]byte) {
	var mu sync.Mutex
	fake.BroadcastFn = func(_ context.Context, raw []byte) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		*captured = append([]byte(nil), raw...)
		tx := wire.NewMsgTx(2)
		if err := tx.Deserialize(bytes.NewReader(raw)); err != nil {
			return "", err
		}
		return tx.TxHash().String(), nil
	}
}

// TestSendTx_EngineVerifiesBroadcast is THE money-correctness proof at the
// send-pipeline level. It programs the fake with confirmed UTXOs on the vector
// wallet's receive addresses, sends, captures the broadcast bytes, deserializes
// the tx, and runs txscript.NewEngine on EVERY input with StandardVerifyFlags.
// Passing engines prove the signatures are real and spendable. It further asserts:
// RBF nSequence, the recipient output, change to a wallet CHANGE-branch address,
// fee == Σin-Σout == result.FeeSat, vsize accuracy, and the journal state.
func TestSendTx_EngineVerifiesBroadcast(t *testing.T) {
	fake := fakebackend.New()
	var captured []byte
	captureBroadcast(fake, &captured)
	fake.Tip = 800000

	svc, teardown := newSendService(t, fake)
	defer teardown()

	// Program a single 1,000,000-sat confirmed UTXO on receive-0.
	programUTXO(fake, canonicalReceive0, "11"+strings.Repeat("0", 62), 0, 1_000_000)

	// Send 0.005 BTC to a known external P2WPKH address at 10 sat/vB.
	const recipient = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
	res, err := svc.SendTx(context.Background(), domain.SendRequest{
		Wallet: "vec", To: recipient, Amount: "0.005", FeeRate: "10", Yes: true,
	}, nil)
	if err != nil {
		t.Fatalf("SendTx: %v", err)
	}

	// (a) Broadcast happened, txid set, status broadcast.
	if res.Txid == "" || res.Status != domain.TxStateBroadcast {
		t.Fatalf("result: txid=%q status=%q, want a txid + broadcast", res.Txid, res.Status)
	}
	if len(captured) == 0 {
		t.Fatalf("no broadcast bytes captured")
	}

	// (b) Deserialize the captured tx.
	tx := wire.NewMsgTx(2)
	if err := tx.Deserialize(bytes.NewReader(captured)); err != nil {
		t.Fatalf("deserialize broadcast: %v", err)
	}

	// (c) Engine-verify each input.
	utxo := fake.UTXOsByAddr[canonicalReceive0][0]
	prevScript := scriptOf(t, canonicalReceive0)
	prevOuts := map[wire.OutPoint]*wire.TxOut{
		tx.TxIn[0].PreviousOutPoint: wire.NewTxOut(utxo.ValueSat, prevScript),
	}
	fetcher := txscript.NewMultiPrevOutFetcher(prevOuts)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)
	for i := range tx.TxIn {
		eng, eerr := txscript.NewEngine(prevScript, tx, i, txscript.StandardVerifyFlags, nil, sigHashes, utxo.ValueSat, fetcher)
		if eerr != nil {
			t.Fatalf("NewEngine input %d: %v", i, eerr)
		}
		if eerr := eng.Execute(); eerr != nil {
			t.Fatalf("engine.Execute input %d FAILED (invalid/unspendable): %v", i, eerr)
		}
		// (d) RBF: every input must signal opt-in RBF.
		if tx.TxIn[i].Sequence != 0xfffffffd {
			t.Errorf("input %d nSequence=%#x, want 0xfffffffd (RBF)", i, tx.TxIn[i].Sequence)
		}
	}

	// (e) Exactly one recipient output for the amount.
	recipScript := scriptOf(t, recipient)
	var foundRecip, foundChange bool
	var sumOut int64
	for _, o := range tx.TxOut {
		sumOut += o.Value
		switch {
		case bytes.Equal(o.PkScript, recipScript):
			foundRecip = true
			if o.Value != 500_000 {
				t.Errorf("recipient output value=%d, want 500000", o.Value)
			}
		case bytes.Equal(o.PkScript, scriptOf(t, canonicalChange0)):
			foundChange = true
		}
	}
	if !foundRecip {
		t.Errorf("no recipient output paying %s", recipient)
	}

	// (f) Change to a wallet CHANGE-branch address, matching res.ChangeAddress.
	if res.ChangeSat > 0 {
		if !foundChange {
			t.Errorf("change present (%d sat) but no output to the wallet change-0 address %s", res.ChangeSat, canonicalChange0)
		}
		if res.ChangeAddress != canonicalChange0 {
			t.Errorf("ChangeAddress=%q, want %q (BIP-84 change-0)", res.ChangeAddress, canonicalChange0)
		}
	}

	// (g) Recovered fee == Σin - Σout == res.FeeSat, and ceil(vsize*rate) covered.
	recoveredFee := utxo.ValueSat - sumOut
	if recoveredFee != res.FeeSat {
		t.Errorf("recovered fee %d != res.FeeSat %d", recoveredFee, res.FeeSat)
	}
	if res.FeeSat < res.Vsize*res.FeeRate {
		t.Errorf("fee %d underpays vsize*rate = %d", res.FeeSat, res.Vsize*res.FeeRate)
	}

	// (h) Actual serialized vsize matches res.Vsize within 1 vB.
	actualVsize := actualVSize(tx)
	if d := res.Vsize - actualVsize; d < -1 || d > 1 {
		t.Errorf("res.Vsize=%d but actual=%d (diff %d > 1)", res.Vsize, actualVsize, d)
	}
	if res.Vsize < actualVsize {
		t.Errorf("predicted vsize %d UNDERSHOOTS actual %d", res.Vsize, actualVsize)
	}

	// (i) Journal: latest record for res.JournalID is broadcast, raw==captured,
	// fee==res.FeeSat, change recorded.
	rec, jerr := svc.journal.ByID(context.Background(), domain.NetworkMainnet, res.JournalID)
	if jerr != nil {
		t.Fatalf("journal ByID: %v", jerr)
	}
	if rec.Status != "broadcast" {
		t.Errorf("journal status=%q, want broadcast", rec.Status)
	}
	if hexRaw(captured) != rec.RawTx {
		t.Errorf("journal RawTx != captured broadcast bytes")
	}
	if rec.FeeSat != res.FeeSat {
		t.Errorf("journal fee %d != res.FeeSat %d", rec.FeeSat, res.FeeSat)
	}
	if rec.ChangeAddr != res.ChangeAddress {
		t.Errorf("journal ChangeAddr=%q != res.ChangeAddress=%q", rec.ChangeAddr, res.ChangeAddress)
	}
}

// scriptOf decodes a bech32 mainnet address to its scriptPubKey.
func scriptOf(t *testing.T, addr string) []byte {
	t.Helper()
	a, err := btcutil.DecodeAddress(addr, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("decode %q: %v", addr, err)
	}
	script, err := txscript.PayToAddrScript(a)
	if err != nil {
		t.Fatalf("script %q: %v", addr, err)
	}
	return script
}

// actualVSize computes the network's vsize from the serialized witness/base sizes:
// ceil((base*3 + total)/4).
func actualVSize(tx *wire.MsgTx) int64 {
	base := tx.SerializeSizeStripped()
	total := tx.SerializeSize()
	weight := int64(base*3 + total)
	return (weight + 3) / 4
}
