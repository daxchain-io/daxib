package service

import (
	"context"
	"strings"
	"testing"

	fakebackend "github.com/daxchain-io/daxib/internal/backend/fake"
	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/journal"
)

// tx_abandon_test.go is the GAP-1 regression: `tx abandon` frees a never-broadcast
// signed tx's UTXOs + refunds its reservation, and REFUSES a broadcast tx.

// TestAbandonNeverBroadcastFreesUTXOsAndRefundsReservation drives a transport-exhausted
// send (record stays `signed`, reservation `reserved`, inputs locked out of
// selection), then abandons it. After abandon: the record is `failed`, the
// rolling-24h reservation is refunded, and a fresh send can re-select the freed UTXO.
func TestAbandonNeverBroadcastFreesUTXOsAndRefundsReservation(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000

	svc, teardown := newPolicySendService(t, fake)
	defer teardown()

	if _, err := svc.PolicySet(context.Background(), PolicySetInput{
		MaxDaySat: "100000000", AllowlistOn: boolFalse(),
	}); err != nil {
		t.Fatalf("PolicySet: %v", err)
	}
	// A SINGLE confirmed UTXO: if abandon does not free it, the retry send below would
	// fail with insufficient funds (the input stays selection-blocked).
	programUTXO(fake, canonicalReceive0, "11"+strings.Repeat("0", 62), 0, 1_000_000)

	// Transport exhaustion ⇒ the record stays `signed`, reservation `reserved`.
	fake.BroadcastFn = func(_ context.Context, _ []byte) (string, error) {
		return "", domain.New(domain.CodeBackendUnreachable, "simulated transport failure")
	}
	stranded, _ := svc.SendTx(context.Background(), domain.SendRequest{
		Wallet: "vec", To: extRecipient, Amount: "0.005", FeeRate: "10", Yes: true,
	}, nil)
	if stranded.Status != domain.TxStateSigned {
		t.Fatalf("precondition: stranded send must be signed, got %s", stranded.Status)
	}
	if windowUsed(t, svc) == 0 {
		t.Fatal("precondition: the stranded send must hold a reservation")
	}

	// Abandon the never-broadcast signed tx.
	res, err := svc.AbandonTx(context.Background(), domain.AbandonRequest{
		Wallet: "vec", Txid: stranded.Txid, Yes: true,
	})
	if err != nil {
		t.Fatalf("AbandonTx: %v", err)
	}
	if !res.ReservationReleased {
		t.Fatal("abandon must release the policy reservation")
	}
	if res.FreedInputs == 0 {
		t.Fatal("abandon must report the freed inputs")
	}

	// The record is now `failed`.
	rec, _ := svc.journal.ByID(context.Background(), svc.net, stranded.JournalID)
	if rec == nil || rec.Status != journal.StatusFailed {
		t.Fatalf("abandoned record must be failed, got %+v", rec)
	}

	// The reservation is refunded (rolling-24h window back to 0).
	if got := windowUsed(t, svc); got != 0 {
		t.Fatalf("abandon must refund the reservation; window=%d, want 0", got)
	}

	// The freed UTXO is re-selectable: a fresh send (broadcast working now) succeeds.
	captureBroadcast(fake, new([]byte))
	retry, rerr := svc.SendTx(context.Background(), domain.SendRequest{
		Wallet: "vec", To: extRecipient, Amount: "0.005", FeeRate: "10", Yes: true,
	}, nil)
	if rerr != nil {
		t.Fatalf("after abandon the freed UTXO must be re-selectable: %v", rerr)
	}
	if retry.Status != domain.TxStateBroadcast {
		t.Fatalf("retry send status=%s, want broadcast", retry.Status)
	}
}

// TestAbandonRefusesBroadcastTx proves abandon REFUSES a tx with a recorded broadcast
// (it may still confirm) — tx.already_broadcast (exit 9), and the record is untouched.
func TestAbandonRefusesBroadcastTx(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	captureBroadcast(fake, new([]byte))

	svc, teardown := newPolicySendService(t, fake)
	defer teardown()

	if _, err := svc.PolicySet(context.Background(), PolicySetInput{
		MaxDaySat: "100000000", AllowlistOn: boolFalse(),
	}); err != nil {
		t.Fatalf("PolicySet: %v", err)
	}
	programUTXO(fake, canonicalReceive0, "11"+strings.Repeat("0", 62), 0, 1_000_000)

	// A normal send that broadcasts successfully ⇒ record `broadcast`.
	sent, err := svc.SendTx(context.Background(), domain.SendRequest{
		Wallet: "vec", To: extRecipient, Amount: "0.005", FeeRate: "10", Yes: true,
	}, nil)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if sent.Status != domain.TxStateBroadcast {
		t.Fatalf("precondition: send must be broadcast, got %s", sent.Status)
	}

	// Abandon must be REFUSED (exit 9) — a broadcast tx may still confirm.
	_, aerr := svc.AbandonTx(context.Background(), domain.AbandonRequest{
		Wallet: "vec", Txid: sent.Txid, Yes: true,
	})
	if aerr == nil {
		t.Fatal("abandon must refuse a tx with a recorded broadcast")
	}
	de := domain.AsError(aerr)
	if de.Code != domain.CodeTxAlreadyBroadcast || de.Exit != domain.ExitTxConflict {
		t.Fatalf("refuse-broadcast: code=%s exit=%d; want tx.already_broadcast / exit 9", de.Code, de.Exit)
	}

	// The record is untouched (still broadcast) and the reservation still committed.
	rec, _ := svc.journal.ByTxid(context.Background(), svc.net, sent.Txid)
	if rec == nil || rec.Status != journal.StatusBroadcast {
		t.Fatalf("a refused abandon must leave the record broadcast, got %+v", rec)
	}
	if windowUsed(t, svc) == 0 {
		t.Fatal("a refused abandon must NOT release the committed reservation")
	}
}

// TestAbandonRefusesSignedWithCommittedReservation is the GAP-1 double-spend
// regression: the send pipeline commits the reservation BEFORE writing
// SetState(broadcast), so a crash/SetState-failure between those two durable writes
// leaves a record at `signed` while its reservation is `committed` and the bytes are
// LIVE on the network. Abandon must REFUSE such a record (the committed reservation is
// the authoritative live signal) — terminalizing it would free the inputs of a live
// tx for re-selection (a fresh send could double-spend them). Status `signed` ALONE
// is not "never broadcast".
func TestAbandonRefusesSignedWithCommittedReservation(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	captureBroadcast(fake, new([]byte))

	svc, teardown := newPolicySendService(t, fake)
	defer teardown()

	if _, err := svc.PolicySet(context.Background(), PolicySetInput{
		MaxDaySat: "100000000", AllowlistOn: boolFalse(),
	}); err != nil {
		t.Fatalf("PolicySet: %v", err)
	}
	programUTXO(fake, canonicalReceive0, "11"+strings.Repeat("0", 62), 0, 1_000_000)

	// A successful send: reservation COMMITTED, record `broadcast`, bytes live.
	sent, err := svc.SendTx(context.Background(), domain.SendRequest{
		Wallet: "vec", To: extRecipient, Amount: "0.005", FeeRate: "10", Yes: true,
	}, nil)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	rec, _ := svc.journal.ByTxid(context.Background(), svc.net, sent.Txid)
	if rec == nil || rec.ReservationID == "" {
		t.Fatalf("precondition: a broadcast record carrying a reservation id, got %+v", rec)
	}
	committedWindow := windowUsed(t, svc)
	if committedWindow == 0 {
		t.Fatal("precondition: the committed send must count the rolling-24h window")
	}

	// Reproduce the exact crash-window on-disk state: revert ONLY the journal record to
	// `signed` (the reservation stays committed). This is the state left by a crash
	// between resv.Commit() and SetState(broadcast).
	if serr := svc.journal.SetState(context.Background(), svc.net, rec.ID,
		journal.StateMutation{Status: journal.StatusSigned}); serr != nil {
		t.Fatalf("revert-to-signed: %v", serr)
	}
	reverted, _ := svc.journal.ByID(context.Background(), svc.net, rec.ID)
	if reverted == nil || reverted.Status != journal.StatusSigned {
		t.Fatalf("precondition: record must be reverted to signed, got %+v", reverted)
	}

	// Abandon MUST be refused (the reservation is committed ⇒ the bytes may be live).
	_, aerr := svc.AbandonTx(context.Background(), domain.AbandonRequest{
		Wallet: "vec", Txid: sent.Txid, Yes: true,
	})
	if aerr == nil {
		t.Fatal("GAP-1: abandon must refuse a signed record whose reservation is committed (the bytes may be live)")
	}
	de := domain.AsError(aerr)
	if de.Code != domain.CodeTxAlreadyBroadcast || de.Exit != domain.ExitTxConflict {
		t.Fatalf("refuse-committed-signed: code=%s exit=%d; want tx.already_broadcast / exit 9", de.Code, de.Exit)
	}

	// The record is untouched (still `signed`, NOT terminalized to `failed`) so the
	// inputs remain reserved/non-selectable, and the committed reservation still counts.
	rec2, _ := svc.journal.ByID(context.Background(), svc.net, rec.ID)
	if rec2 == nil || rec2.Status != journal.StatusSigned {
		t.Fatalf("a refused abandon must NOT terminalize the record, got %+v", rec2)
	}
	if got := windowUsed(t, svc); got != committedWindow {
		t.Fatalf("a refused abandon must NOT release the committed reservation; window %d -> %d", committedWindow, got)
	}
}

// TestAbandonUnknownTxidNotFound proves an unknown txid is ref.not_found (exit 10).
func TestAbandonUnknownTxidNotFound(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000

	svc, teardown := newPolicySendService(t, fake)
	defer teardown()

	_, err := svc.AbandonTx(context.Background(), domain.AbandonRequest{
		Wallet: "vec", Txid: strings.Repeat("ab", 32), Yes: true,
	})
	if err == nil {
		t.Fatal("abandon of an unknown txid must fail")
	}
	if got := domain.AsError(err).Code; got != domain.CodeRefNotFound {
		t.Fatalf("unknown txid code=%s, want %s", got, domain.CodeRefNotFound)
	}
}
