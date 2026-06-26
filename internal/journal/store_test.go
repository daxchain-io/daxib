package journal

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/daxchain-io/daxib/internal/domain"
)

// fixedClock returns a deterministic monotonic clock for record timestamps.
func fixedClock() func() time.Time {
	base := time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	n := 0
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		n++
		return base.Add(time.Duration(n) * time.Second)
	}
}

func openStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(dir, fixedClock())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s, dir
}

// signedRec builds a `signed` record for the canonical mainnet vector.
func signedRec(rawTx string) *Record {
	return &Record{
		Network:       string(domain.NetworkMainnet),
		Wallet:        "vec",
		Status:        StatusSigned,
		Source:        "cli",
		RawTx:         rawTx,
		FeeRate:       10,
		FeeSat:        1410,
		Vsize:         141,
		Inputs:        []JInput{{Txid: "aa", Vout: 0, ValueSat: 500_000, Address: "bc1qsender"}},
		Outputs:       []JOutput{{Address: "bc1qrecipient", ValueSat: 100_000}, {Address: "bc1qchange", ValueSat: 398_590, Change: true}},
		RecipientAddr: "bc1qrecipient",
		RecipientSat:  100_000,
		ChangeAddr:    "bc1qchange",
	}
}

func TestAppendFoldLatestWins(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()
	net := domain.NetworkMainnet

	rec := signedRec("0102signed")
	if err := s.Append(ctx, rec); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if rec.ID == "" || rec.Seq != 1 {
		t.Fatalf("Append did not assign id/seq: id=%q seq=%d", rec.ID, rec.Seq)
	}
	txid := "deadbeef"
	if err := s.SetState(ctx, net, rec.ID, StateMutation{Status: StatusBroadcast, Txid: &txid}); err != nil {
		t.Fatalf("SetState broadcast: %v", err)
	}
	conf := int64(3)
	bh := int64(800_000)
	if err := s.SetState(ctx, net, rec.ID, StateMutation{Status: StatusConfirmed, Confirmations: &conf, BlockHeight: &bh}); err != nil {
		t.Fatalf("SetState confirmed: %v", err)
	}

	got, err := s.ByID(ctx, net, rec.ID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if got.Status != StatusConfirmed || got.Txid != txid || got.Confirmations != 3 || got.BlockHeight != 800_000 {
		t.Errorf("folded record wrong: %+v", got)
	}
	byTxid, err := s.ByTxid(ctx, net, txid)
	if err != nil || byTxid.ID != rec.ID {
		t.Errorf("ByTxid: %v rec=%+v", err, byTxid)
	}
	list, err := s.List(ctx, net, "")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("List len=%d, want 1 (folded)", len(list))
	}
}

func TestAppendBeforeBroadcastDiscriminator(t *testing.T) {
	s, dir := openStore(t)
	ctx := context.Background()
	net := domain.NetworkMainnet

	raw := "02ff44signedbytes"
	rec := signedRec(raw)
	if err := s.Append(ctx, rec); err != nil {
		t.Fatalf("Append: %v", err)
	}
	// "Crash" — reopen a fresh Store over the same dir (no SetState ran).
	s2, err := Open(dir, fixedClock())
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, err := s2.ByID(ctx, net, rec.ID)
	if err != nil {
		t.Fatalf("ByID after crash: %v", err)
	}
	if got.Status != StatusSigned {
		t.Errorf("status after crash = %q, want signed (no recorded broadcast → rebroadcast same bytes)", got.Status)
	}
	if got.RawTx != raw {
		t.Errorf("raw_tx mutated across crash: %q want %q", got.RawTx, raw)
	}
}

func TestCrashAfterBroadcastRecorded(t *testing.T) {
	s, dir := openStore(t)
	ctx := context.Background()
	net := domain.NetworkMainnet

	rec := signedRec("0102signed")
	if err := s.Append(ctx, rec); err != nil {
		t.Fatalf("Append: %v", err)
	}
	txid := "cafe1234"
	if err := s.SetState(ctx, net, rec.ID, StateMutation{Status: StatusBroadcast, Txid: &txid}); err != nil {
		t.Fatalf("SetState: %v", err)
	}
	s2, err := Open(dir, fixedClock())
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, err := s2.ByID(ctx, net, rec.ID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if got.Status != StatusBroadcast || got.Txid != txid {
		t.Errorf("after crash with broadcast recorded: status=%q txid=%q (want broadcast/%s)", got.Status, got.Txid, txid)
	}
}

func TestStateMutationClonesPriorLatest(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()
	net := domain.NetworkMainnet

	rec := signedRec("0102signed")
	if err := s.Append(ctx, rec); err != nil {
		t.Fatalf("Append: %v", err)
	}
	txid := "abc"
	if err := s.SetState(ctx, net, rec.ID, StateMutation{Status: StatusBroadcast, Txid: &txid}); err != nil {
		t.Fatalf("SetState: %v", err)
	}
	got, err := s.ByID(ctx, net, rec.ID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	// The broadcast line must preserve Inputs/Outputs/FeeSat/RecipientAddr from the
	// signed line while flipping Status+Txid — no field zeroed.
	if len(got.Inputs) != 1 || len(got.Outputs) != 2 || got.FeeSat != 1410 || got.RecipientAddr != "bc1qrecipient" || got.ChangeAddr != "bc1qchange" {
		t.Errorf("SetState zeroed a carried field: %+v", got)
	}
}

func TestConcurrentAppendsSerializeUnderFlock(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()
	net := domain.NetworkMainnet

	const n = 25
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = s.Append(ctx, signedRec("raw"))
		}(i)
	}
	wg.Wait()
	for i, e := range errs {
		if e != nil {
			t.Fatalf("Append %d: %v", i, e)
		}
	}
	list, err := s.List(ctx, net, "")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != n {
		t.Fatalf("List len=%d, want %d", len(list), n)
	}
	// Seqs must be strictly increasing, gap-free, unique 1..n.
	seen := map[uint64]bool{}
	for _, r := range list {
		if r.Seq < 1 || r.Seq > n || seen[r.Seq] {
			t.Fatalf("bad/dup seq %d", r.Seq)
		}
		seen[r.Seq] = true
	}
}

func TestTornFinalLineRecovered(t *testing.T) {
	s, dir := openStore(t)
	ctx := context.Background()
	net := domain.NetworkMainnet

	rec := signedRec("valid")
	if err := s.Append(ctx, rec); err != nil {
		t.Fatalf("Append: %v", err)
	}
	// Append a torn partial line (no trailing newline) directly to the file.
	path := filepath.Join(dir, "journal", string(net)+".jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := f.WriteString(`{"v":1,"id":"PARTIAL","status":"sig`); err != nil {
		t.Fatalf("write torn: %v", err)
	}
	_ = f.Close()

	var warn bytes.Buffer
	s.SetWarnSink(&warn)
	// Append again (exclusive lock + repair=true): the torn tail is dropped+truncated.
	rec2 := signedRec("valid2")
	if err := s.Append(ctx, rec2); err != nil {
		t.Fatalf("Append after torn: %v", err)
	}
	list, err := s.List(ctx, net, "")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("List len=%d, want 2 (torn line dropped, both valid survive)", len(list))
	}
	if !bytes.Contains(warn.Bytes(), []byte("torn final line")) {
		t.Errorf("expected a torn-final-line warning, got %q", warn.String())
	}
}

func TestCorruptMidLineSkipped(t *testing.T) {
	s, dir := openStore(t)
	ctx := context.Background()
	net := domain.NetworkMainnet

	r1 := signedRec("one")
	if err := s.Append(ctx, r1); err != nil {
		t.Fatalf("Append r1: %v", err)
	}
	// Inject an unparseable but newline-terminated line between two valid records.
	path := filepath.Join(dir, "journal", string(net)+".jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := f.WriteString("this is not json\n"); err != nil {
		t.Fatalf("write corrupt: %v", err)
	}
	_ = f.Close()

	r2 := signedRec("two")
	if err := s.Append(ctx, r2); err != nil {
		t.Fatalf("Append r2: %v", err)
	}

	var warn bytes.Buffer
	s.SetWarnSink(&warn)
	list, err := s.List(ctx, net, "")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("List len=%d, want 2 valid (corrupt mid-line skipped)", len(list))
	}
	if !bytes.Contains(warn.Bytes(), []byte("corrupt line")) {
		t.Errorf("expected a corrupt-line warning, got %q", warn.String())
	}
}

func TestPerNetworkIsolation(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()

	mainRec := signedRec("main")
	if err := s.Append(ctx, mainRec); err != nil {
		t.Fatalf("Append main: %v", err)
	}
	testRec := signedRec("test")
	testRec.Network = string(domain.NetworkTestnet)
	if err := s.Append(ctx, testRec); err != nil {
		t.Fatalf("Append testnet: %v", err)
	}

	mainList, _ := s.List(ctx, domain.NetworkMainnet, "")
	testList, _ := s.List(ctx, domain.NetworkTestnet, "")
	if len(mainList) != 1 || mainList[0].RawTx != "main" {
		t.Errorf("mainnet list wrong: %+v", mainList)
	}
	if len(testList) != 1 || testList[0].RawTx != "test" {
		t.Errorf("testnet list wrong: %+v", testList)
	}
}

func TestByTxidNotFound(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()
	_, err := s.ByTxid(ctx, domain.NetworkMainnet, "nope")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("ByTxid unknown = %v, want ErrNotFound", err)
	}
	_, err = s.ByID(ctx, domain.NetworkMainnet, "nope")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("ByID unknown = %v, want ErrNotFound", err)
	}
}

func TestUnresolvedFiltersTerminal(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()
	net := domain.NetworkMainnet

	a := signedRec("a")
	b := signedRec("b")
	if err := s.Append(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(ctx, b); err != nil {
		t.Fatal(err)
	}
	// Terminalize a.
	if err := s.SetState(ctx, net, a.ID, StateMutation{Status: StatusFailed}); err != nil {
		t.Fatal(err)
	}
	un, err := s.Unresolved(ctx, net)
	if err != nil {
		t.Fatalf("Unresolved: %v", err)
	}
	if len(un) != 1 || un[0].ID != b.ID {
		t.Errorf("Unresolved = %+v, want only b (%s)", un, b.ID)
	}
	// List keeps both (terminal kept as history).
	list, _ := s.List(ctx, net, "")
	if len(list) != 2 {
		t.Errorf("List len=%d, want 2 (terminal kept)", len(list))
	}
}

func TestLockTimeoutMapsToStateCode(t *testing.T) {
	s, dir := openStore(t)
	ctx := context.Background()
	net := domain.NetworkMainnet

	// Hold the exclusive journal lock from a separate Store handle, then a second
	// withLock (via Append) must time out → state.lock_timeout.
	if err := s.Append(ctx, signedRec("warmup")); err != nil { // ensure dirs exist
		t.Fatalf("warmup: %v", err)
	}

	// Manually take the flock through fsx and hold it.
	blocker, _ := Open(dir, fixedClock())
	releaseCh := make(chan struct{})
	heldCh := make(chan struct{})
	go func() {
		_ = blocker.withLock(ctx, net, func() error {
			close(heldCh)
			<-releaseCh
			return nil
		})
	}()
	<-heldCh

	// A short-deadline context so the second acquisition fails fast.
	shortCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	err := s.Append(shortCtx, signedRec("blocked"))
	close(releaseCh)
	if err == nil {
		t.Fatalf("expected a lock-timeout error")
	}
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != CodeStateLockTimeout {
		t.Fatalf("err=%v, want %s (exit 11)", err, CodeStateLockTimeout)
	}
}
