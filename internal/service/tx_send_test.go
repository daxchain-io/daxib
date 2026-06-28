package service

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire"

	fakebackend "github.com/daxchain-io/daxib/internal/backend/fake"
	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/journal"
)

func sendReq(to, amount string) domain.SendRequest {
	return domain.SendRequest{Wallet: "vec", To: to, Amount: amount, FeeRate: "10", Yes: true}
}

const extRecipient = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"

func TestSendTransportExhaustedLeavesSigned(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	programUTXO(fake, canonicalReceive0, "22"+strings.Repeat("0", 62), 0, 1_000_000)

	var attempts int32
	fake.BroadcastFn = func(_ context.Context, _ []byte) (string, error) {
		atomic.AddInt32(&attempts, 1)
		return "", domain.New(domain.CodeBackendUnreachable, "connection refused")
	}

	svc, teardown := newSendService(t, fake)
	defer teardown()

	// Shorten the backoff so the test is fast.
	orig := broadcastBackoff
	broadcastBackoff = []time.Duration{0, time.Millisecond}
	defer func() { broadcastBackoff = orig }()

	res, err := svc.SendTx(context.Background(), domain.LocalCLI(), sendReq(extRecipient, "0.005"), nil)
	if err == nil {
		t.Fatalf("expected a retryable transport error")
	}
	de := domain.AsError(err)
	if de.Code != domain.CodeBackendUnreachable || !de.Retryable {
		t.Errorf("err code=%s retryable=%v, want backend.unreachable retryable", de.Code, de.Retryable)
	}
	if res.Status != domain.TxStateSigned {
		t.Errorf("result status=%q, want signed (recoverable)", res.Status)
	}
	// The journal record must STAY signed (NOT failed) with the raw bytes intact.
	rec, jerr := svc.journal.ByID(context.Background(), domain.NetworkMainnet, res.JournalID)
	if jerr != nil {
		t.Fatalf("ByID: %v", jerr)
	}
	if rec.Status != journal.StatusSigned {
		t.Fatalf("journal status=%q, want signed (transport exhaustion must NOT terminalize)", rec.Status)
	}
	originalRaw := rec.RawTx

	// A follow-up `tx send` (now with transport restored) runs reconcile FIRST under
	// the send-lock: it rebroadcasts the prior `signed` record's IDENTICAL bytes
	// (flipping it to `broadcast`) and reserves its outpoint. The new selection then
	// EXCLUDES that reserved single coin, so the fresh send fails with insufficient
	// funds rather than re-selecting the in-flight UTXO and broadcasting a CONFLICTING
	// second tx (the exact double-spend the reserved-outpoint exclusion prevents).
	var captured []byte
	captureBroadcast(fake, &captured)
	_, err = svc.SendTx(context.Background(), domain.LocalCLI(), sendReq(extRecipient, "0.005"), nil)
	if err == nil {
		t.Fatalf("second send must NOT re-select the in-flight coin; want insufficient funds")
	}
	de2 := domain.AsError(err)
	if de2 == nil || de2.Exit != domain.ExitInsufficientFunds {
		t.Fatalf("second send err=%v, want funds.insufficient (exit 5) — the single coin is reserved by the in-flight tx", err)
	}
	// Reconcile DID rebroadcast the prior signed record's identical bytes and flip it
	// to broadcast, without mutating those bytes.
	if hexRaw(captured) != originalRaw {
		t.Errorf("reconcile rebroadcast bytes != original signed bytes (re-selected/rebuilt instead of rebroadcasting)")
	}
	recAfter, _ := svc.journal.ByID(context.Background(), domain.NetworkMainnet, res.JournalID)
	if recAfter.Status != journal.StatusBroadcast {
		t.Errorf("after reconcile the prior signed record status=%q, want broadcast", recAfter.Status)
	}
	if recAfter.RawTx != originalRaw {
		t.Errorf("reconcile mutated the prior signed raw bytes")
	}
	// Exactly one journal record exists (no second/conflicting record was created).
	recs, _ := svc.journal.List(context.Background(), domain.NetworkMainnet, "vec")
	if len(recs) != 1 {
		t.Errorf("want exactly 1 journal record (no conflicting second tx), got %d", len(recs))
	}
}

func TestSendPermanentRejectMarksFailed(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	programUTXO(fake, canonicalReceive0, "33"+strings.Repeat("0", 62), 0, 1_000_000)
	fake.BroadcastFn = func(_ context.Context, _ []byte) (string, error) {
		return "", errors.New("bad-txns-inputs-missingorspent")
	}

	svc, teardown := newSendService(t, fake)
	defer teardown()

	res, err := svc.SendTx(context.Background(), domain.LocalCLI(), sendReq(extRecipient, "0.005"), nil)
	if err == nil {
		t.Fatalf("expected a reject error")
	}
	de := domain.AsError(err)
	if de.Code != domain.CodeTxInputSpent || de.Exit != domain.ExitTxConflict {
		t.Errorf("err code=%s exit=%d, want tx.input_spent (exit 9)", de.Code, de.Exit)
	}
	_ = res
	// The journal record must be failed.
	recs, _ := svc.journal.List(context.Background(), domain.NetworkMainnet, "vec")
	if len(recs) != 1 || recs[0].Status != journal.StatusFailed {
		t.Fatalf("journal not marked failed: %+v", recs)
	}
	if recs[0].Error == nil || !strings.Contains(*recs[0].Error, "missingorspent") {
		t.Errorf("reject reason not recorded: %+v", recs[0].Error)
	}
}

func TestSendLockSerializesConcurrentSends(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	programUTXO(fake, canonicalReceive0, "44"+strings.Repeat("0", 62), 0, 1_000_000)

	// A broadcast that blocks briefly so the two sends would overlap WITHOUT the
	// send-lock. With the lock they serialize: the second waits, then re-selects
	// and finds the same single UTXO already journaled as consumed.
	var inCritical int32
	var maxConcurrent int32
	captured := make([][]byte, 0, 2)
	var mu sync.Mutex
	fake.BroadcastFn = func(_ context.Context, raw []byte) (string, error) {
		n := atomic.AddInt32(&inCritical, 1)
		for {
			old := atomic.LoadInt32(&maxConcurrent)
			if n <= old || atomic.CompareAndSwapInt32(&maxConcurrent, old, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		atomic.AddInt32(&inCritical, -1)
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
			_, results[i] = svc.SendTx(context.Background(), domain.LocalCLI(), sendReq(extRecipient, "0.005"), nil)
		}(i)
	}
	wg.Wait()

	if atomic.LoadInt32(&maxConcurrent) > 1 {
		t.Errorf("send critical sections overlapped (maxConcurrent=%d); the send-lock must serialize them", maxConcurrent)
	}
	// At least one must succeed; both selecting the SAME single UTXO is prevented by
	// serialization (the second reconciles the first's signed/broadcast record).
	ok := 0
	for _, e := range results {
		if e == nil {
			ok++
		}
	}
	if ok == 0 {
		t.Errorf("expected at least one send to succeed, got %v", results)
	}
}

func TestDryRunNoJournalNoBroadcast(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	programUTXO(fake, canonicalReceive0, "55"+strings.Repeat("0", 62), 0, 1_000_000)
	var broadcasts int32
	fake.BroadcastFn = func(_ context.Context, _ []byte) (string, error) {
		atomic.AddInt32(&broadcasts, 1)
		return "x", nil
	}

	svc, teardown := newSendService(t, fake)
	defer teardown()

	req := sendReq(extRecipient, "0.005")
	req.DryRun = true
	req.Yes = false // dry-run is exempt from the confirmation gate
	res, err := svc.SendTx(context.Background(), domain.LocalCLI(), req, nil)
	if err != nil {
		t.Fatalf("dry-run SendTx: %v", err)
	}
	if !res.DryRun || res.Txid != "" {
		t.Errorf("dry-run result: DryRun=%v Txid=%q, want DryRun + empty txid", res.DryRun, res.Txid)
	}
	if res.FeeSat <= 0 || res.Vsize <= 0 {
		t.Errorf("dry-run should still estimate fee/vsize, got fee=%d vsize=%d", res.FeeSat, res.Vsize)
	}
	if atomic.LoadInt32(&broadcasts) != 0 {
		t.Errorf("dry-run broadcast %d times, want 0", broadcasts)
	}
	recs, _ := svc.journal.List(context.Background(), domain.NetworkMainnet, "")
	if len(recs) != 0 {
		t.Errorf("dry-run wrote %d journal records, want 0", len(recs))
	}
}

func TestSendNonTTYNoYesConfirmRequired(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	programUTXO(fake, canonicalReceive0, "66"+strings.Repeat("0", 62), 0, 1_000_000)
	svc, teardown := newSendService(t, fake)
	defer teardown()

	req := sendReq(extRecipient, "0.005")
	req.Yes = false
	_, err := svc.SendTx(context.Background(), domain.LocalCLI(), req, nil)
	de := domain.AsError(err)
	if de == nil || de.Code != domain.CodeUsageConfirmRequired {
		t.Fatalf("err=%v, want usage.confirmation_required (exit 2)", err)
	}
}

func TestSendInsufficientFundsExit5(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	programUTXO(fake, canonicalReceive0, "77"+strings.Repeat("0", 62), 0, 10_000) // tiny
	var broadcasts int32
	fake.BroadcastFn = func(_ context.Context, _ []byte) (string, error) {
		atomic.AddInt32(&broadcasts, 1)
		return "x", nil
	}
	svc, teardown := newSendService(t, fake)
	defer teardown()

	_, err := svc.SendTx(context.Background(), domain.LocalCLI(), sendReq(extRecipient, "0.005"), nil)
	de := domain.AsError(err)
	if de == nil || de.Exit != domain.ExitInsufficientFunds {
		t.Fatalf("err=%v, want exit 5", err)
	}
	if atomic.LoadInt32(&broadcasts) != 0 {
		t.Errorf("insufficient funds should not broadcast")
	}
}

func TestSendBadAddressExit2(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	programUTXO(fake, canonicalReceive0, "88"+strings.Repeat("0", 62), 0, 1_000_000)
	svc, teardown := newSendService(t, fake)
	defer teardown()

	// A testnet address on mainnet.
	_, err := svc.SendTx(context.Background(), domain.LocalCLI(), sendReq("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", "0.005"), nil)
	de := domain.AsError(err)
	if de == nil || de.Code != domain.CodeUsageBadAddress {
		t.Fatalf("err=%v, want usage.bad_address (exit 2)", err)
	}
}

// txidOf computes the txid of raw signed bytes.
func txidOf(raw []byte) string {
	tx := wire.NewMsgTx(2)
	if err := tx.Deserialize(bytes.NewReader(raw)); err != nil {
		return ""
	}
	return tx.TxHash().String()
}
