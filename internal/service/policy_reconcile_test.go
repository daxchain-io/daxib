package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	fakebackend "github.com/daxchain-io/daxib/internal/backend/fake"
	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/journal"
)

// policy_reconcile_test.go is the POL-1 regression: the OFFLINE orphan reconciler at
// Open must NOT release a `signed` orphan's reservation. A `signed` record carries
// journaled bytes that MAY already be live on the network (the accepted path commits
// the reservation BEFORE SetState(broadcast); reconcileWallet rebroadcasts `signed`
// records). Refunding its rolling-24h budget offline would let an agent re-spend a
// budget a live tx already consumed (fail-OPEN). Over-counting is the safe direction:
// the reservation stays RESERVED until an ONLINE path positively settles it.

// TestSignedOrphanSurvivesOfflineOpenReservationIntact forces a transport-exhausted
// send (record stays `signed`, reservation stays `reserved`), then re-Opens the
// service OFFLINE (reconcilePolicyOrphans runs, no backend dial that could settle the
// tx). The reservation must remain INTACT — the rolling-24h window still counts the
// spend after recovery.
func TestSignedOrphanSurvivesOfflineOpenReservationIntact(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000

	svc, teardown := newPolicySendService(t, fake)
	defer teardown()

	if _, err := svc.PolicySet(context.Background(), domain.LocalCLI(), PolicySetInput{
		MaxDaySat: "100000000", AllowlistOn: boolFalse(),
	}); err != nil {
		t.Fatalf("PolicySet: %v", err)
	}
	programUTXO(fake, canonicalReceive0, "11"+strings.Repeat("0", 62), 0, 1_000_000)

	// Force transport exhaustion: the broadcast never succeeds, so the record stays
	// `signed` and its reservation stays `reserved` (never committed, never released).
	fake.BroadcastFn = func(_ context.Context, _ []byte) (string, error) {
		return "", domain.New(domain.CodeBackendUnreachable, "simulated transport failure")
	}
	res, _ := svc.SendTx(context.Background(), domain.LocalCLI(), domain.SendRequest{
		Wallet: "vec", To: extRecipient, Amount: "0.005", FeeRate: "10", Yes: true,
	}, nil)

	// Precondition: the record is `signed` (the bytes may be live; we just couldn't
	// confirm acceptance) and the reservation is counted in the window.
	rec, _ := svc.journal.ByID(context.Background(), svc.net, res.JournalID)
	if rec == nil || rec.Status != journal.StatusSigned {
		t.Fatalf("precondition: record must be signed, got %+v", rec)
	}
	before := windowUsed(t, svc)
	if before == 0 {
		t.Fatal("precondition: the signed send must have reserved a non-zero window charge")
	}

	// Re-Open OFFLINE: make any dial fail so reconcileAtOpen cannot settle the tx, then
	// the only thing touching the reservation is reconcilePolicyOrphans. A `signed`
	// orphan must be left RESERVED.
	svc2 := reopenPolicyService(t, svc, fake)
	defer func() { _ = svc2.Close() }()

	after := windowUsed(t, svc2)
	if after != before {
		t.Fatalf("POL-1: a signed orphan's reservation was released on offline Open; window %d -> %d (budget refunded for a possibly-live tx)", before, after)
	}

	// And the record is still `signed` (untouched), and the reservation is still
	// `reserved` (an online settle, not this offline reconcile, must resolve it).
	rec2, _ := svc2.journal.ByID(context.Background(), svc2.net, res.JournalID)
	if rec2 == nil || rec2.Status != journal.StatusSigned {
		t.Fatalf("the signed record must be untouched by offline reconcile, got %+v", rec2)
	}
}

// TestFailedOrphanReleasedOnOfflineOpen is the POL-1 companion: a positively
// pre-broadcast record (terminalized `failed`) IS safe to release offline — no bytes
// could be live. The reservation is freed so the budget is not over-counted forever.
func TestFailedOrphanReleasedOnOfflineOpen(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000

	svc, teardown := newPolicySendService(t, fake)
	defer teardown()

	if _, err := svc.PolicySet(context.Background(), domain.LocalCLI(), PolicySetInput{
		MaxDaySat: "100000000", AllowlistOn: boolFalse(),
	}); err != nil {
		t.Fatalf("PolicySet: %v", err)
	}
	programUTXO(fake, canonicalReceive0, "11"+strings.Repeat("0", 62), 0, 1_000_000)

	// A transport-exhausted send leaves a `signed` record + `reserved` reservation.
	fake.BroadcastFn = func(_ context.Context, _ []byte) (string, error) {
		return "", domain.New(domain.CodeBackendUnreachable, "simulated transport failure")
	}
	res, _ := svc.SendTx(context.Background(), domain.LocalCLI(), domain.SendRequest{
		Wallet: "vec", To: extRecipient, Amount: "0.005", FeeRate: "10", Yes: true,
	}, nil)
	before := windowUsed(t, svc)
	if before == 0 {
		t.Fatal("precondition: a non-zero reservation")
	}

	// Operator abandons the never-broadcast signed tx: record -> failed, reservation
	// released. (This is the GAP-1 path; here we use it to terminalize the record so
	// the reconciler treats it as positively pre-broadcast.) Simulate the failed state
	// directly via the journal so this test stays focused on the reconciler.
	reason := "operator abandoned"
	if err := svc.journal.SetState(context.Background(), svc.net, res.JournalID,
		journal.StateMutation{Status: journal.StatusFailed, Error: &reason}); err != nil {
		t.Fatalf("SetState failed: %v", err)
	}

	// Re-Open OFFLINE: the reconciler sees a `failed` record ⇒ release the orphan.
	svc2 := reopenPolicyService(t, svc, fake)
	defer func() { _ = svc2.Close() }()

	after := windowUsed(t, svc2)
	if after != 0 {
		t.Fatalf("a failed (pre-broadcast) orphan must be released on offline Open; window=%d, want 0", after)
	}
}

// TestSignedOrphanReservedWhenJournalReadErrors is the POL-1 fail-CLOSED regression
// for journalByReservation: a journal-READ fault at Open (lock timeout, IO/permission
// fault, read-only mount) is NOT a "no record" signal. The reconciler must leave the
// orphan RESERVED (over-counting is safe), never release it — releasing on a read
// error refunds a budget a possibly-live `signed` tx already consumed (fail-OPEN).
func TestSignedOrphanReservedWhenJournalReadErrors(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 000 does not deny root; skip the permission-fault simulation")
	}
	fake := fakebackend.New()
	fake.Tip = 800000

	svc, teardown := newPolicySendService(t, fake)
	defer teardown()

	if _, err := svc.PolicySet(context.Background(), domain.LocalCLI(), PolicySetInput{
		MaxDaySat: "100000000", AllowlistOn: boolFalse(),
	}); err != nil {
		t.Fatalf("PolicySet: %v", err)
	}
	programUTXO(fake, canonicalReceive0, "11"+strings.Repeat("0", 62), 0, 1_000_000)

	// Transport exhaustion ⇒ a `signed` record carrying a `reserved` reservation.
	fake.BroadcastFn = func(_ context.Context, _ []byte) (string, error) {
		return "", domain.New(domain.CodeBackendUnreachable, "simulated transport failure")
	}
	res, _ := svc.SendTx(context.Background(), domain.LocalCLI(), domain.SendRequest{
		Wallet: "vec", To: extRecipient, Amount: "0.005", FeeRate: "10", Yes: true,
	}, nil)
	rec, _ := svc.journal.ByID(context.Background(), svc.net, res.JournalID)
	if rec == nil || rec.Status != journal.StatusSigned {
		t.Fatalf("precondition: record must be signed, got %+v", rec)
	}
	before := windowUsed(t, svc)
	if before == 0 {
		t.Fatal("precondition: the signed send must reserve a non-zero window charge")
	}

	// Make the journal file UNREADABLE so List() errors at the reopen (a permission
	// fault, like an IO fault or a concurrent-process lock timeout would), while the
	// spend counter stays readable so Orphans() still yields the orphan.
	journalFile := filepath.Join(svc.opts.State, "journal", "mainnet.jsonl")
	if _, err := os.Stat(journalFile); err != nil {
		t.Fatalf("journal file %q not found: %v", journalFile, err)
	}
	if err := os.Chmod(journalFile, 0o000); err != nil {
		t.Fatalf("chmod journal: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(journalFile, 0o600) })

	// Re-Open OFFLINE: reconcilePolicyOrphans runs and journalByReservation's List()
	// errors. The orphan MUST stay RESERVED — the window is unchanged.
	svc2 := reopenPolicyService(t, svc, fake)
	defer func() { _ = svc2.Close() }()

	// Restore read access so windowUsed (which reads the spend counter, not the
	// journal) and any further reads work; the reservation state we assert was already
	// decided by the reconcile that ran during reopen.
	_ = os.Chmod(journalFile, 0o600)

	after := windowUsed(t, svc2)
	if after != before {
		t.Fatalf("POL-1 FAIL-OPEN: a journal read error released a signed orphan's reservation; window %d -> %d", before, after)
	}
}

// TestPolicyReleaseFreesStuckReservation is the GAP-4 service wiring: an operator
// releases a STUCK pending reservation by id (admin-gated). The rolling-24h budget is
// refunded.
func TestPolicyReleaseFreesStuckReservation(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000

	svc, teardown := newPolicySendService(t, fake)
	defer teardown()

	if _, err := svc.PolicySet(context.Background(), domain.LocalCLI(), PolicySetInput{
		MaxDaySat: "100000000", AllowlistOn: boolFalse(),
	}); err != nil {
		t.Fatalf("PolicySet: %v", err)
	}
	programUTXO(fake, canonicalReceive0, "11"+strings.Repeat("0", 62), 0, 1_000_000)

	// Transport exhaustion ⇒ a `signed` record carrying a `reserved` reservation id.
	fake.BroadcastFn = func(_ context.Context, _ []byte) (string, error) {
		return "", domain.New(domain.CodeBackendUnreachable, "simulated transport failure")
	}
	res, _ := svc.SendTx(context.Background(), domain.LocalCLI(), domain.SendRequest{
		Wallet: "vec", To: extRecipient, Amount: "0.005", FeeRate: "10", Yes: true,
	}, nil)
	rec, _ := svc.journal.ByID(context.Background(), svc.net, res.JournalID)
	if rec == nil || rec.ReservationID == "" {
		t.Fatalf("precondition: a signed record carrying a reservation id, got %+v", rec)
	}
	if windowUsed(t, svc) == 0 {
		t.Fatal("precondition: a non-zero reservation")
	}

	// Operator releases the stuck reservation by id (admin passphrase via env).
	rel, err := svc.PolicyRelease(context.Background(), domain.LocalCLI(), PolicyReleaseInput{ReservationID: rec.ReservationID})
	if err != nil {
		t.Fatalf("PolicyRelease: %v", err)
	}
	if !rel.Released {
		t.Fatal("PolicyRelease must report the reservation released")
	}
	if got := windowUsed(t, svc); got != 0 {
		t.Fatalf("release must refund the reservation; window=%d, want 0", got)
	}
}

// TestPolicyReleaseRefusesCommitted is the GAP-4 service wiring for the refusal: a
// committed reservation (a live broadcast spend) cannot be released — exit 8.
func TestPolicyReleaseRefusesCommitted(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	captureBroadcast(fake, new([]byte))

	svc, teardown := newPolicySendService(t, fake)
	defer teardown()

	if _, err := svc.PolicySet(context.Background(), domain.LocalCLI(), PolicySetInput{
		MaxDaySat: "100000000", AllowlistOn: boolFalse(),
	}); err != nil {
		t.Fatalf("PolicySet: %v", err)
	}
	programUTXO(fake, canonicalReceive0, "11"+strings.Repeat("0", 62), 0, 1_000_000)

	// A successful send commits the reservation.
	sent, err := svc.SendTx(context.Background(), domain.LocalCLI(), domain.SendRequest{
		Wallet: "vec", To: extRecipient, Amount: "0.005", FeeRate: "10", Yes: true,
	}, nil)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	rec, _ := svc.journal.ByTxid(context.Background(), svc.net, sent.Txid)
	if rec == nil || rec.ReservationID == "" {
		t.Fatalf("precondition: a broadcast record with a reservation id, got %+v", rec)
	}

	_, rerr := svc.PolicyRelease(context.Background(), domain.LocalCLI(), PolicyReleaseInput{ReservationID: rec.ReservationID})
	if rerr == nil {
		t.Fatal("PolicyRelease must refuse a committed reservation")
	}
	if de := domain.AsError(rerr); de.Code != "policy.state_error" || de.Exit != domain.ExitTimeoutPending {
		t.Fatalf("refuse-committed: code=%s exit=%d; want policy.state_error / exit 8", de.Code, de.Exit)
	}
	// The committed spend stays counted.
	if windowUsed(t, svc) == 0 {
		t.Fatal("a refused release must NOT free the committed reservation")
	}
}
