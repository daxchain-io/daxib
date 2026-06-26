package service

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	fakebackend "github.com/daxchain-io/daxib/internal/backend/fake"
	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/journal"
)

// A canonical Taproot (bc1p…) mainnet recipient, used to prove the send pipeline
// pays a non-P2WPKH recipient with a CORRECT (recipient-aware) fee/vsize.
const taprootRecipient = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"

// TestSendTx_TaprootRecipientFeeNotUnderpaid is the regression for the
// vsize-nonp2wpkh-recipient-underpay blocker: a send to a Taproot output must
// attach a fee covering the ACTUAL signed vsize (which includes the 43-vB taproot
// output, not an assumed 31-vB P2WPKH). It engine-verifies the broadcast tx and
// asserts the effective feerate (fee / actual vsize) is >= the requested rate, so a
// taproot send near the relay floor is never stranded below the minimum.
func TestSendTx_TaprootRecipientFeeNotUnderpaid(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	var captured []byte
	captureBroadcast(fake, &captured)
	programUTXO(fake, canonicalReceive0, "b1"+strings.Repeat("0", 62), 0, 1_000_000)

	svc, teardown := newSendService(t, fake)
	defer teardown()

	const rate = int64(5)
	res, err := svc.SendTx(context.Background(), domain.SendRequest{
		Wallet: "vec", To: taprootRecipient, Amount: "0.005", FeeRate: "5", Yes: true,
	}, nil)
	if err != nil {
		t.Fatalf("SendTx to taproot: %v", err)
	}

	tx := wire.NewMsgTx(2)
	if err := tx.Deserialize(bytes.NewReader(captured)); err != nil {
		t.Fatalf("deserialize: %v", err)
	}

	// Engine-verify the input (signatures real and spendable).
	utxo := fake.UTXOsByAddr[canonicalReceive0][0]
	prevScript := scriptOf(t, canonicalReceive0)
	prevOuts := map[wire.OutPoint]*wire.TxOut{tx.TxIn[0].PreviousOutPoint: wire.NewTxOut(utxo.ValueSat, prevScript)}
	fetcher := txscript.NewMultiPrevOutFetcher(prevOuts)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)
	eng, eerr := txscript.NewEngine(prevScript, tx, 0, txscript.StandardVerifyFlags, nil, sigHashes, utxo.ValueSat, fetcher)
	if eerr != nil {
		t.Fatalf("NewEngine: %v", eerr)
	}
	if eerr := eng.Execute(); eerr != nil {
		t.Fatalf("engine.Execute FAILED: %v", eerr)
	}

	// The recipient output must be the 43-vB taproot script.
	recipScript := scriptOf(t, taprootRecipient)
	var foundRecip bool
	for _, o := range tx.TxOut {
		if bytes.Equal(o.PkScript, recipScript) {
			foundRecip = true
		}
	}
	if !foundRecip {
		t.Fatalf("no taproot recipient output found")
	}

	// THE FIX: the attached fee covers the ACTUAL signed vsize at the requested rate —
	// the effective feerate is never below the requested rate (no underpay/strand).
	actual := actualVSize(tx)
	if res.FeeSat < actual*rate {
		t.Errorf("fee %d underpays the ACTUAL taproot vsize %d at rate %d (effective %.3f sat/vB < %d)",
			res.FeeSat, actual, rate, float64(res.FeeSat)/float64(actual), rate)
	}
	// The reported vsize must not undershoot the actual signed vsize.
	if res.Vsize < actual {
		t.Errorf("res.Vsize=%d UNDERSHOOTS actual taproot vsize=%d", res.Vsize, actual)
	}
	if d := res.Vsize - actual; d < -1 || d > 1 {
		t.Errorf("res.Vsize=%d vs actual=%d differ by %d (>1 vB)", res.Vsize, actual, d)
	}
}

// TestSendSmallTaprootRejectedAsDust is the CB-4 regression: a 300-sat send to a
// P2TR recipient must be rejected PRE-BUILD with usage.dust_output (the P2TR dust
// threshold is 330 > the P2WPKH 294), never built+signed then bounced by relay.
func TestSendSmallTaprootRejectedAsDust(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	programUTXO(fake, canonicalReceive0, "d0"+strings.Repeat("0", 62), 0, 1_000_000)

	svc, teardown := newSendService(t, fake)
	defer teardown()

	_, err := svc.SendTx(context.Background(), domain.SendRequest{
		Wallet: "vec", To: taprootRecipient, Amount: "300sat", FeeRate: "5", Yes: true,
	}, nil)
	if err == nil {
		t.Fatalf("a 300-sat P2TR send should be rejected as dust")
	}
	de := domain.AsError(err)
	if de == nil || de.Code != domain.CodeUsageDustOutput {
		t.Fatalf("err=%v, want usage.dust_output (P2TR dust threshold is 330)", err)
	}

	// A 294-sat send to a P2WPKH recipient is still accepted (the per-script gate did
	// not over-reject the smaller-output type).
	if _, perr := svc.SendTx(context.Background(), domain.SendRequest{
		Wallet: "vec", To: extRecipient, Amount: "294sat", FeeRate: "5", Yes: true,
	}, nil); perr != nil {
		de := domain.AsError(perr)
		if de != nil && de.Code == domain.CodeUsageDustOutput {
			t.Fatalf("a 294-sat P2WPKH send was wrongly rejected as dust: %v", perr)
		}
		// Any other error (e.g. insufficient after fee) is fine for this assertion.
	}
}

// TestDryRunDoesNotAdvanceChangeWatermark is the regression for
// dryrun-advances-change-watermark: a --dry-run that emits change must PEEK the
// change address (read-only) and never advance NextChange or materialize it in
// meta. A previously-buggy dry-run burned one change index per preview.
func TestDryRunDoesNotAdvanceChangeWatermark(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	programUTXO(fake, canonicalReceive0, "b2"+strings.Repeat("0", 62), 0, 1_000_000)

	svc, teardown := newSendService(t, fake)
	defer teardown()

	before, err := svc.WalletShow(context.Background(), domain.WalletShowRequest{Name: "vec"})
	if err != nil {
		t.Fatalf("WalletShow before: %v", err)
	}

	req := sendReq(extRecipient, "0.005")
	req.DryRun = true
	req.Yes = false
	// Run several dry-runs; each must be a no-op on the watermark.
	for i := 0; i < 5; i++ {
		res, derr := svc.SendTx(context.Background(), req, nil)
		if derr != nil {
			t.Fatalf("dry-run %d: %v", i, derr)
		}
		if !res.DryRun {
			t.Fatalf("dry-run %d: result not marked DryRun", i)
		}
		// The preview still shows the change address it WOULD use (peeked).
		if res.ChangeSat > 0 && res.ChangeAddress != canonicalChange0 {
			t.Errorf("dry-run change preview=%q, want the peeked change-0 %q", res.ChangeAddress, canonicalChange0)
		}
	}

	after, err := svc.WalletShow(context.Background(), domain.WalletShowRequest{Name: "vec"})
	if err != nil {
		t.Fatalf("WalletShow after: %v", err)
	}
	if after.NextChange != before.NextChange {
		t.Errorf("dry-run advanced NextChange %d -> %d (must be a no-op preview)", before.NextChange, after.NextChange)
	}
	// The peeked change-0 must NOT have been materialized in meta (the address count
	// is unchanged — a real DeriveNext would have added one).
	if after.Addresses != before.Addresses {
		t.Errorf("dry-run materialized %d new address(es) in meta (must stay a no-op preview)", after.Addresses-before.Addresses)
	}
}

// TestCrashRecoveryDoesNotReselectStrandedInputs is the regression for
// journal-consumed-outpoints-never-excluded + select-before-lock-reconcile: after a
// transport-exhausted send strands a `signed` record consuming the wallet's only
// coin, a subsequent send must NOT re-select that coin and broadcast a conflicting
// tx. With one coin reserved, the new selection fails insufficient; reconcile
// rebroadcasts the original bytes. No second/conflicting tx is created.
func TestCrashRecoveryDoesNotReselectStrandedInputs(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	programUTXO(fake, canonicalReceive0, "b3"+strings.Repeat("0", 62), 0, 1_000_000)

	// Phase 1: broadcast transport-fails → record stays `signed`.
	fake.BroadcastFn = func(_ context.Context, _ []byte) (string, error) {
		return "", domain.New(domain.CodeBackendUnreachable, "connection refused")
	}
	svc, teardown := newSendService(t, fake)
	defer teardown()
	orig := broadcastBackoff
	broadcastBackoff = []time.Duration{0}
	defer func() { broadcastBackoff = orig }()

	res1, err := svc.SendTx(context.Background(), sendReq(extRecipient, "0.005"), nil)
	if err == nil {
		t.Fatalf("phase1: expected transport error")
	}
	rec1, _ := svc.journal.ByID(context.Background(), domain.NetworkMainnet, res1.JournalID)
	if rec1.Status != journal.StatusSigned {
		t.Fatalf("phase1 record status=%q, want signed", rec1.Status)
	}
	strandedOutpoint := rec1.Inputs[0].Txid + ":" + domain.IndexString(rec1.Inputs[0].Vout)

	// Phase 2: transport restored, the backend still shows the coin unspent (the
	// stranded tx never reached it). A new send must NOT re-select it.
	var broadcasts int32
	var captured [][]byte
	var mu sync.Mutex
	fake.BroadcastFn = func(_ context.Context, raw []byte) (string, error) {
		atomic.AddInt32(&broadcasts, 1)
		mu.Lock()
		captured = append(captured, append([]byte(nil), raw...))
		mu.Unlock()
		return txidOf(raw), nil
	}
	_, err = svc.SendTx(context.Background(), sendReq(extRecipient, "0.005"), nil)
	if err == nil {
		t.Fatalf("phase2: a send re-selected the in-flight coin instead of failing insufficient")
	}
	de := domain.AsError(err)
	if de == nil || de.Exit != domain.ExitInsufficientFunds {
		t.Fatalf("phase2 err=%v, want funds.insufficient (the only coin is reserved)", err)
	}

	// Exactly ONE broadcast happened in phase 2 — the reconcile rebroadcasting the
	// ORIGINAL stranded bytes. No second/conflicting tx was built+broadcast.
	if got := atomic.LoadInt32(&broadcasts); got != 1 {
		t.Fatalf("phase2 broadcast count=%d, want 1 (only the reconcile rebroadcast)", got)
	}
	mu.Lock()
	rebroadcast := captured[0]
	mu.Unlock()
	if hexRaw(rebroadcast) != rec1.RawTx {
		t.Errorf("the rebroadcast bytes != the original stranded signed bytes")
	}
	// The stranded record flipped to broadcast; still consumes the same outpoint.
	recAfter, _ := svc.journal.ByID(context.Background(), domain.NetworkMainnet, res1.JournalID)
	if recAfter.Status != journal.StatusBroadcast {
		t.Errorf("stranded record status=%q after reconcile, want broadcast", recAfter.Status)
	}
	// Exactly one non-terminal record consumes the stranded outpoint (no double-consume).
	unresolved, _ := svc.journal.Unresolved(context.Background(), domain.NetworkMainnet)
	consumers := 0
	for _, r := range unresolved {
		for _, in := range r.Inputs {
			if in.Txid+":"+domain.IndexString(in.Vout) == strandedOutpoint {
				consumers++
			}
		}
	}
	if consumers != 1 {
		t.Errorf("%d non-terminal records consume the stranded outpoint, want 1 (no double-consume)", consumers)
	}
}

// TestConcurrentSendsSpendDistinctOutpoints is the regression for
// selection-outside-sendlock: two concurrent sends, given TWO coins, must select
// DIFFERENT outpoints (selection now runs under the send-lock). The send-lock +
// reserved-outpoint exclusion guarantee no double-select of the same coin.
func TestConcurrentSendsSpendDistinctOutpoints(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	programUTXO(fake, canonicalReceive0, "b4"+strings.Repeat("0", 62), 0, 1_000_000)
	programUTXO(fake, canonicalReceive0, "b4"+strings.Repeat("0", 62), 1, 1_000_000)

	captured := make([][]byte, 0, 2)
	var mu sync.Mutex
	fake.BroadcastFn = func(_ context.Context, raw []byte) (string, error) {
		time.Sleep(15 * time.Millisecond) // widen the race window
		mu.Lock()
		captured = append(captured, append([]byte(nil), raw...))
		mu.Unlock()
		return txidOf(raw), nil
	}

	svc, teardown := newSendService(t, fake)
	defer teardown()

	var wg sync.WaitGroup
	results := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, results[i] = svc.SendTx(context.Background(), sendReq(extRecipient, "0.005"), nil)
		}(i)
	}
	wg.Wait()

	for i, e := range results {
		if e != nil {
			t.Fatalf("send %d failed: %v", i, e)
		}
	}
	// Both broadcast; the two txs must spend DIFFERENT outpoints (no double-spend).
	mu.Lock()
	defer mu.Unlock()
	if len(captured) != 2 {
		t.Fatalf("want 2 broadcasts, got %d", len(captured))
	}
	seen := map[wire.OutPoint]int{}
	for _, raw := range captured {
		tx := wire.NewMsgTx(2)
		if err := tx.Deserialize(bytes.NewReader(raw)); err != nil {
			t.Fatalf("deserialize: %v", err)
		}
		for _, in := range tx.TxIn {
			seen[in.PreviousOutPoint]++
		}
	}
	for op, n := range seen {
		if n > 1 {
			t.Errorf("outpoint %s spent by %d concurrent txs — double-spend (selection not serialized under the lock)", op, n)
		}
	}
}

// TestAcceptedBroadcastRecordWriteFailLeavesSignedNotFailed is the regression for
// accepted-broadcast-terminalized-as-failed: when Broadcast accepts the tx (it is
// live on-chain) but the subsequent SetState(broadcast) write fails, the record
// must stay `signed` (recoverable, idempotent rebroadcast) and NEVER be terminalized
// as `failed`. The fix sets settled=true BEFORE the SetState write.
func TestAcceptedBroadcastRecordWriteFailLeavesSignedNotFailed(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	programUTXO(fake, canonicalReceive0, "b5"+strings.Repeat("0", 62), 0, 1_000_000)

	svc, teardown := newSendService(t, fake)
	defer teardown()

	// Broadcast ACCEPTS the tx (returns a txid → live on-chain), then cancels the
	// caller context so the following journal SetState(broadcast) fails its locked
	// write (fsx.Lock honours the cancelled context → state.lock_timeout).
	ctx, cancel := context.WithCancel(context.Background())
	fake.BroadcastFn = func(_ context.Context, raw []byte) (string, error) {
		txid := txidOf(raw)
		cancel() // accepted, but the record write will now fail
		return txid, nil
	}

	res, err := svc.SendTx(ctx, sendReq(extRecipient, "0.005"), nil)
	// The send returns a recoverable error (record write failed), NOT a terminal fail.
	if err == nil {
		t.Fatalf("expected a recoverable error when the broadcast record write fails")
	}

	// THE FIX: the record stays `signed` (recoverable), never `failed`.
	rec, jerr := svc.journal.ByID(context.Background(), domain.NetworkMainnet, res.JournalID)
	if jerr != nil {
		t.Fatalf("ByID: %v", jerr)
	}
	if rec.Status == journal.StatusFailed {
		t.Fatalf("accepted-but-unrecorded broadcast was wrongly terminalized as FAILED — the live tx is lost from tracking")
	}
	if rec.Status != journal.StatusSigned {
		t.Errorf("record status=%q, want signed (recoverable for idempotent rebroadcast)", rec.Status)
	}
	// The live tx stays in the reconciliation worklist (Unresolved), so it is re-polled.
	unresolved, _ := svc.journal.Unresolved(context.Background(), domain.NetworkMainnet)
	found := false
	for _, r := range unresolved {
		if r.ID == res.JournalID {
			found = true
		}
	}
	if !found {
		t.Errorf("the accepted tx's record is not in Unresolved() — it would never be reconciled/confirmed")
	}
}
