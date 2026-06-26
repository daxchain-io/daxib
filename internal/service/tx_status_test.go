package service

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daxchain-io/daxib/internal/backend"
	fakebackend "github.com/daxchain-io/daxib/internal/backend/fake"
	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/journal"
)

// sendOnce performs a happy-path send and returns the result.
func sendOnce(t *testing.T, svc *Service, fake *fakebackend.Client) domain.TxResult {
	t.Helper()
	var captured []byte
	captureBroadcast(fake, &captured)
	res, err := svc.SendTx(context.Background(), sendReq(extRecipient, "0.005"), nil)
	if err != nil {
		t.Fatalf("SendTx: %v", err)
	}
	return res
}

func TestTxWaitConfirms(t *testing.T) {
	defer fastPoll()()
	fake := fakebackend.New()
	fake.Tip = 800000
	programUTXO(fake, canonicalReceive0, "a1"+strings.Repeat("0", 62), 0, 1_000_000)
	svc, teardown := newSendService(t, fake)
	defer teardown()

	res := sendOnce(t, svc, fake)

	// 0-conf on the first tick, then >= target on the second.
	var calls int32
	fake.TxStatusFn = func(_ context.Context, txid string) (domain.TxStatus, error) {
		n := atomic.AddInt32(&calls, 1)
		if n < 2 {
			return domain.TxStatus{Txid: txid}, nil
		}
		return domain.TxStatus{Txid: txid, Confirmed: true, Confirmations: 2, BlockHeight: 800001}, nil
	}

	conf := int64(1)
	wres, err := svc.WaitTx(context.Background(), domain.WaitRequest{
		Txid: res.Txid, Confirmations: &conf, Timeout: domain.Duration{D: 10 * time.Second},
	}, nil)
	if err != nil {
		t.Fatalf("WaitTx: %v", err)
	}
	if wres.Status != domain.TxStateConfirmed || wres.Confirmations < 1 {
		t.Errorf("wait result: status=%q conf=%d, want confirmed >=1", wres.Status, wres.Confirmations)
	}
	// The journal must be promoted to confirmed.
	rec, _ := svc.journal.ByID(context.Background(), domain.NetworkMainnet, res.JournalID)
	if rec.Status != journal.StatusConfirmed {
		t.Errorf("journal status=%q, want confirmed", rec.Status)
	}
}

func TestTxWaitTimeout(t *testing.T) {
	defer fastPoll()()
	fake := fakebackend.New()
	fake.Tip = 800000
	programUTXO(fake, canonicalReceive0, "a2"+strings.Repeat("0", 62), 0, 1_000_000)
	svc, teardown := newSendService(t, fake)
	defer teardown()

	res := sendOnce(t, svc, fake)
	// Always 0-conf.
	fake.TxStatusFn = func(_ context.Context, txid string) (domain.TxStatus, error) {
		return domain.TxStatus{Txid: txid}, nil
	}

	conf := int64(1)
	_, err := svc.WaitTx(context.Background(), domain.WaitRequest{
		Txid: res.Txid, Confirmations: &conf, Timeout: domain.Duration{D: 10 * time.Millisecond},
	}, nil)
	de := domain.AsError(err)
	if de == nil || de.Code != domain.CodeTxWaitTimeout || de.Exit != domain.ExitTimeoutPending {
		t.Fatalf("err=%v, want tx.wait_timeout (exit 8)", err)
	}
	if !de.Retryable {
		t.Errorf("tx.wait_timeout should be retryable")
	}
}

func TestTxWaitRebroadcastsSignedRecord(t *testing.T) {
	defer fastPoll()()
	fake := fakebackend.New()
	fake.Tip = 800000
	programUTXO(fake, canonicalReceive0, "a3"+strings.Repeat("0", 62), 0, 1_000_000)
	svc, teardown := newSendService(t, fake)
	defer teardown()

	// Seed a `signed` record directly (the lost-broadcast window): build+sign a tx
	// via a transport-failing send, leaving it `signed`.
	orig := broadcastBackoff
	broadcastBackoff = []time.Duration{0}
	var firstRaw []byte
	fake.BroadcastFn = func(_ context.Context, raw []byte) (string, error) {
		firstRaw = append([]byte(nil), raw...)
		return "", domain.New(domain.CodeBackendUnreachable, "connection refused")
	}
	res, err := svc.SendTx(context.Background(), sendReq(extRecipient, "0.005"), nil)
	broadcastBackoff = orig
	if err == nil {
		t.Fatalf("expected transport error to leave a signed record")
	}
	rec, _ := svc.journal.ByID(context.Background(), domain.NetworkMainnet, res.JournalID)
	if rec.Status != journal.StatusSigned {
		t.Fatalf("seed record status=%q, want signed", rec.Status)
	}

	// Now wait: it must rebroadcast the stored bytes (identical), then confirm.
	var rebroadcast []byte
	var confCalls int32
	fake.BroadcastFn = func(_ context.Context, raw []byte) (string, error) {
		rebroadcast = append([]byte(nil), raw...)
		return txidOf(raw), nil
	}
	fake.TxStatusFn = func(_ context.Context, txid string) (domain.TxStatus, error) {
		if atomic.AddInt32(&confCalls, 1) >= 1 {
			return domain.TxStatus{Txid: txid, Confirmed: true, Confirmations: 1, BlockHeight: 800001}, nil
		}
		return domain.TxStatus{Txid: txid}, nil
	}
	conf := int64(1)
	wres, werr := svc.WaitTx(context.Background(), domain.WaitRequest{
		Txid: res.Txid, Confirmations: &conf, Timeout: domain.Duration{D: 10 * time.Second},
	}, nil)
	if werr != nil {
		t.Fatalf("WaitTx: %v", werr)
	}
	if hexRaw(rebroadcast) != hexRaw(firstRaw) {
		t.Errorf("wait rebroadcast different bytes than the stored signed tx")
	}
	if wres.Status != domain.TxStateConfirmed {
		t.Errorf("wait status=%q, want confirmed", wres.Status)
	}
}

func TestTxStatusForeignTxid(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	svc, teardown := newSendService(t, fake)
	defer teardown()

	// A foreign txid that IS on-chain returns its backend status (no journal row).
	fake.TxStatusFn = func(_ context.Context, txid string) (domain.TxStatus, error) {
		if txid == "feedface" {
			return domain.TxStatus{Txid: txid, Confirmed: true, Confirmations: 99, BlockHeight: 700000}, nil
		}
		return domain.TxStatus{Txid: txid}, nil // unknown → 0/0/false
	}
	res, err := svc.TxStatus(context.Background(), domain.TxStatusRequest{Txid: "feedface"})
	if err != nil {
		t.Fatalf("TxStatus foreign: %v", err)
	}
	if res.Status != domain.TxStateConfirmed || res.Confirmations != 99 {
		t.Errorf("foreign status: %q conf=%d, want confirmed/99", res.Status, res.Confirmations)
	}

	// An unknown txid (not journaled, not on-chain) → ref.not_found (exit 10).
	_, err = svc.TxStatus(context.Background(), domain.TxStatusRequest{Txid: "00deadbeef"})
	de := domain.AsError(err)
	if de == nil || de.Code != domain.CodeRefNotFound || de.Exit != domain.ExitNotFound {
		t.Fatalf("unknown txid err=%v, want ref.not_found (exit 10)", err)
	}
}

func TestTxListNewestFirst(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	// TWO distinct confirmed UTXOs: each send consumes a different coin. The first
	// send's broadcast record RESERVES its outpoint, so the second send must select
	// the OTHER coin (the reserved-outpoint exclusion under the send-lock), proving
	// no double-select.
	programUTXO(fake, canonicalReceive0, "a4"+strings.Repeat("0", 62), 0, 5_000_000)
	programUTXO(fake, canonicalReceive0, "a4"+strings.Repeat("0", 62), 1, 5_000_000)
	svc, teardown := newSendService(t, fake)
	defer teardown()

	var captured []byte
	captureBroadcast(fake, &captured)
	r1, err := svc.SendTx(context.Background(), sendReq(extRecipient, "0.001"), nil)
	if err != nil {
		t.Fatalf("send1: %v", err)
	}
	r2, err := svc.SendTx(context.Background(), sendReq(extRecipient, "0.002"), nil)
	if err != nil {
		t.Fatalf("send2: %v", err)
	}
	// The two sends must consume DIFFERENT outpoints (no double-select).
	if r1.Inputs[0].Outpoint == r2.Inputs[0].Outpoint {
		t.Fatalf("send2 re-selected send1's outpoint %s — reserved-outpoint exclusion failed", r1.Inputs[0].Outpoint)
	}
	list, err := svc.ListTxs(context.Background(), domain.TxListRequest{})
	if err != nil {
		t.Fatalf("ListTxs: %v", err)
	}
	if len(list.Txs) != 2 {
		t.Fatalf("list len=%d, want 2", len(list.Txs))
	}
	// Newest-first: r2 then r1.
	if list.Txs[0].JournalID != r2.JournalID || list.Txs[1].JournalID != r1.JournalID {
		t.Errorf("list order wrong: got %s,%s want %s,%s",
			list.Txs[0].JournalID, list.Txs[1].JournalID, r2.JournalID, r1.JournalID)
	}
}

func TestReconcileAtOpenLeavesSignedForLazyRebroadcast(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	programUTXO(fake, canonicalReceive0, "a5"+strings.Repeat("0", 62), 0, 1_000_000)

	// First service: a transport-failing send seeds a `signed` record.
	svc, teardown := newSendService(t, fake)
	orig := broadcastBackoff
	broadcastBackoff = []time.Duration{0}
	var broadcasts int32
	fake.BroadcastFn = func(_ context.Context, _ []byte) (string, error) {
		atomic.AddInt32(&broadcasts, 1)
		return "", domain.New(domain.CodeBackendUnreachable, "connection refused")
	}
	res, err := svc.SendTx(context.Background(), sendReq(extRecipient, "0.005"), nil)
	broadcastBackoff = orig
	if err == nil {
		t.Fatalf("expected transport error")
	}
	jID := res.JournalID
	stateDir := svc.stateDir
	_ = svc.Close()

	// Reopen a fresh service over the SAME state dir — reconcileAtOpen must NOT
	// broadcast (offline-safe) and must leave the record `signed`.
	before := atomic.LoadInt32(&broadcasts)
	svc2, err := openOverState(t, fake, stateDir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = svc2.Close() }()
	if atomic.LoadInt32(&broadcasts) != before {
		t.Errorf("reconcileAtOpen broadcast at Open; it must be lazy/offline")
	}
	rec, jerr := svc2.journal.ByID(context.Background(), domain.NetworkMainnet, jID)
	if jerr != nil {
		t.Fatalf("ByID after reopen: %v", jerr)
	}
	if rec.Status != journal.StatusSigned {
		t.Errorf("record status after reopen=%q, want signed (untouched, lazy)", rec.Status)
	}
	_ = teardown
}

// openOverState reopens a service over an existing state dir (reusing the same
// keystore/config from the env the helper sets), injecting the fake.
func openOverState(t *testing.T, fake *fakebackend.Client, stateDir string) (*Service, error) {
	t.Helper()
	keystoreDir := t.TempDir()
	configDir := t.TempDir()
	env := map[string]string{
		"DAXIB_KEYSTORE":           keystoreDir,
		"DAXIB_KDF_LIGHT":          "1",
		"DAXIB_PASSPHRASE":         "test-pass-12345678",
		"DAXIB_PASSPHRASE_CONFIRM": "test-pass-12345678",
	}
	return Open(context.Background(), Options{
		Keystore: keystoreDir, Config: configDir, State: stateDir, Network: "mainnet", KDFLight: true,
		Dial:   func(_ context.Context, _ backend.Options) (backend.Client, error) { return fake, nil },
		Secret: SecretIO{LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok }, IsTTY: func() bool { return false }},
	})
}

// fastPoll shortens the wait poll cadence for tests; the returned func restores it.
func fastPoll() func() {
	orig := waitPollInterval
	waitPollInterval = 2 * time.Millisecond
	return func() { waitPollInterval = orig }
}

// TestRecordResultAdoptsShrinkingConfirmations is the CB-8 regression: when a
// confirmed record's backend depth SHRINKS (a chain reorg), recordResult must adopt
// the current (lower) depth, not retain the stale higher count; and a record the
// backend now reports as fully unconfirmed (0/0) is demoted to pending.
func TestRecordResultAdoptsShrinkingConfirmations(t *testing.T) {
	svc := &Service{net: domain.NetworkMainnet}

	rec := &journal.Record{
		Status:        journal.StatusConfirmed,
		Txid:          "ab",
		Confirmations: 6,
		BlockHeight:   800000,
	}

	// Reorg: the tx is still confirmed but only 2-deep now. The result must show 2,
	// not the stale 6.
	res := svc.recordResult(rec, domain.TxStatus{Txid: "ab", Confirmed: true, Confirmations: 2, BlockHeight: 800004})
	if res.Confirmations != 2 {
		t.Errorf("confirmations=%d, want 2 (must adopt the shrunken backend depth, CB-8)", res.Confirmations)
	}
	if res.Status != domain.TxStateConfirmed {
		t.Errorf("status=%q, want confirmed (still >= 1 conf)", res.Status)
	}

	// Deeper reorg: the tx dropped back to the mempool (0/0/unconfirmed). Demote to
	// pending and zero the stale depth.
	res2 := svc.recordResult(rec, domain.TxStatus{Txid: "ab", Confirmed: false, Confirmations: 0, BlockHeight: 0})
	if res2.Status != domain.TxStatePending {
		t.Errorf("status=%q, want pending (reorg dropped it to the mempool, CB-8)", res2.Status)
	}
	if res2.Confirmations != 0 || res2.BlockHeight != 0 {
		t.Errorf("stale depth retained after reorg: confs=%d height=%d", res2.Confirmations, res2.BlockHeight)
	}
}
