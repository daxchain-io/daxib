package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	fakebackend "github.com/daxchain-io/daxib/internal/backend/fake"
	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/journal"
)

// TestClassifyBroadcastErr is the TC-2/KNOWN-2 regression table: it pins the
// broadcast classifier's (outcome, retryable, mapped-code) for every reason class.
// The headline contract is conservative transient handling — a backend.rpc_error,
// a warming/-28 node, a 5xx, and an UNKNOWN/novel error all classify as
// transport-exhausted (record left `signed`, recoverable), while only the
// positively-matched permanent consensus/policy rejects terminalize.
func TestClassifyBroadcastErr(t *testing.T) {
	cases := []struct {
		name  string
		err   error
		want  broadcastOutcome
		retry bool
		code  string // expected mapped domain code (skip when accepted/nil)
	}{
		// Already-known => accepted (idempotent), no mapped error.
		{"already-in-mempool", errors.New("txn-already-in-mempool"), outcomeAccepted, false, ""},
		{"already-known", errors.New("Transaction already known"), outcomeAccepted, false, ""},

		// Permanent consensus/policy rejects => terminalize.
		{"missingorspent", errors.New("bad-txns-inputs-missingorspent"), outcomeRejected, false, domain.CodeTxInputSpent},
		{"min-relay", errors.New("min relay fee not met"), outcomeRejected, false, domain.CodeTxFeeTooLow},
		{"fee-too-low", errors.New("256: fee too low"), outcomeRejected, false, domain.CodeTxFeeTooLow},
		{"dust", errors.New("dust"), outcomeRejected, false, domain.CodeTxBroadcastRejected},
		{"non-final", errors.New("non-final"), outcomeRejected, false, domain.CodeTxBroadcastRejected},

		// Transport / recoverable.
		{"deadline", context.DeadlineExceeded, outcomeTransportExhausted, true, domain.CodeBackendUnreachable},
		{"wrapped-unreachable", domain.New(domain.CodeBackendUnreachable, "connection refused"), outcomeTransportExhausted, true, domain.CodeBackendUnreachable},
		// A node that ANSWERED with an rpc_error has NOT proven the tx invalid (TXR-1).
		{"rpc-error-warmup", domain.New(domain.CodeBackendRPCError, "Loading block index... (-28)"), outcomeTransportExhausted, true, domain.CodeBackendUnreachable},
		{"http-503", errors.New("backend returned 503 service unavailable"), outcomeTransportExhausted, true, domain.CodeBackendUnreachable},
		{"warming-up", errors.New("the node is warming up"), outcomeTransportExhausted, true, domain.CodeBackendUnreachable},
		{"rate-limit", errors.New("429 rate limit exceeded"), outcomeTransportExhausted, true, domain.CodeBackendUnreachable},
		// THE KNOWN-2 fix: an UNKNOWN/novel string is NOT terminalized.
		{"novel-unknown", errors.New("flux capacitor desynchronized"), outcomeTransportExhausted, true, domain.CodeBackendUnreachable},

		// CLS-1: a TRANSIENT envelope that ALSO embeds a permanent-reject substring must
		// classify transient (the transient signal wins) — the permanent scan no longer
		// runs first. A 5xx proxy page mentioning "scriptpubkey", a `backend.rpc_error`
		// whose detail echoes "dust", and a warming-node string mentioning "non-final"
		// are all retryable, NOT terminal.
		{"503-with-scriptpubkey", errors.New("HTTP 503 Service Unavailable: <html>scriptpubkey gateway</html>"), outcomeTransportExhausted, true, domain.CodeBackendUnreachable},
		{"rpcerror-503-with-dust", domain.New(domain.CodeBackendRPCError, "HTTP 503: upstream proxy says dust"), outcomeTransportExhausted, true, domain.CodeBackendUnreachable},
		{"warmup-with-non-final", errors.New("Loading block index... (-28); non-final"), outcomeTransportExhausted, true, domain.CodeBackendUnreachable},
		// The GENUINE consensus reject (no transient marker) STILL terminalizes.
		{"genuine-reject-rpc-25", errors.New("RPC error -25: bad-txns-inputs-missingorspent"), outcomeRejected, false, domain.CodeTxInputSpent},
		{"rpcerror-genuine-dust", domain.New(domain.CodeBackendRPCError, "RPC error -26: dust"), outcomeRejected, false, domain.CodeTxBroadcastRejected},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o, mapped, retry := classifyBroadcastErr(tc.err)
			if o != tc.want {
				t.Fatalf("outcome=%v, want %v", o, tc.want)
			}
			if retry != tc.retry {
				t.Fatalf("retry=%v, want %v", retry, tc.retry)
			}
			if tc.code == "" {
				if mapped != nil {
					t.Fatalf("mapped=%v, want nil (accepted)", mapped)
				}
				return
			}
			de := domain.AsError(mapped)
			if de == nil || de.Code != tc.code {
				t.Fatalf("mapped code=%v, want %s", mapped, tc.code)
			}
		})
	}
}

// TestSendRPCErrorLeavesSignedAndRebroadcasts is the end-to-end TXR-1 regression: a
// fake backend returning a -28-style rpc_error on the first broadcast must leave the
// record `signed` (recoverable), NOT `failed`; a follow-up send (transport restored)
// reconciles by rebroadcasting the SAME bytes.
func TestSendRPCErrorLeavesSignedAndRebroadcasts(t *testing.T) {
	fake := newClassifyFake(t)
	defer fake.teardown()

	orig := broadcastBackoff
	broadcastBackoff = []time.Duration{0}
	defer func() { broadcastBackoff = orig }()

	// Phase 1: the node answers with a warming-up rpc_error on every broadcast.
	fake.client.BroadcastFn = func(_ context.Context, _ []byte) (string, error) {
		return "", domain.New(domain.CodeBackendRPCError, "Loading block index... (-28)")
	}
	res1, err := fake.svc.SendTx(context.Background(), sendReq(extRecipient, "0.005"), nil)
	if err == nil {
		t.Fatalf("phase1: expected a recoverable error")
	}
	rec1, _ := fake.svc.journal.ByID(context.Background(), domain.NetworkMainnet, res1.JournalID)
	if rec1.Status != journal.StatusSigned {
		t.Fatalf("phase1 record status=%q, want signed (rpc_error must NOT terminalize)", rec1.Status)
	}

	// Phase 2: transport restored; the reconcile rebroadcasts the SAME bytes.
	var captured []byte
	fake.client.BroadcastFn = func(_ context.Context, raw []byte) (string, error) {
		captured = append([]byte(nil), raw...)
		return txidOf(raw), nil
	}
	// A second send insufficient (the only coin is reserved) but reconcile flips the
	// stranded record to broadcast first.
	_, _ = fake.svc.SendTx(context.Background(), sendReq(extRecipient, "0.005"), nil)
	recAfter, _ := fake.svc.journal.ByID(context.Background(), domain.NetworkMainnet, res1.JournalID)
	if recAfter.Status != journal.StatusBroadcast {
		t.Fatalf("after reconcile record status=%q, want broadcast", recAfter.Status)
	}
	if hexRaw(captured) != rec1.RawTx {
		t.Errorf("rebroadcast bytes != original signed bytes")
	}
}

// TestReconcileTransientRejectLeavesSigned is the TC-7 companion: when reconcile
// rebroadcasts a stranded `signed` record and the backend returns a TRANSIENT /
// unknown error, the record stays `signed` (recoverable), not `failed`. (The
// permanent-reject reconcile path is covered by TestSendPermanentRejectMarksFailed
// and the existing reconcile tests.)
func TestReconcileTransientRejectLeavesSigned(t *testing.T) {
	fake := newClassifyFake(t)
	defer fake.teardown()

	orig := broadcastBackoff
	broadcastBackoff = []time.Duration{0}
	defer func() { broadcastBackoff = orig }()

	// Strand a `signed` record via a transport failure.
	fake.client.BroadcastFn = func(_ context.Context, _ []byte) (string, error) {
		return "", domain.New(domain.CodeBackendUnreachable, "connection refused")
	}
	res1, _ := fake.svc.SendTx(context.Background(), sendReq(extRecipient, "0.005"), nil)
	rec1, _ := fake.svc.journal.ByID(context.Background(), domain.NetworkMainnet, res1.JournalID)
	if rec1.Status != journal.StatusSigned {
		t.Fatalf("strand record status=%q, want signed", rec1.Status)
	}

	// On reconcile the backend answers with an UNKNOWN reject string. Conservative
	// classification keeps the record `signed`, never `failed`.
	fake.client.BroadcastFn = func(_ context.Context, _ []byte) (string, error) {
		return "", domain.New(domain.CodeBackendRPCError, "node says: spline reticulation pending")
	}
	_, _ = fake.svc.SendTx(context.Background(), sendReq(extRecipient, "0.005"), nil)
	recAfter, _ := fake.svc.journal.ByID(context.Background(), domain.NetworkMainnet, res1.JournalID)
	if recAfter.Status == journal.StatusFailed {
		t.Fatalf("transient reconcile reject wrongly terminalized the record as failed")
	}
	if recAfter.Status != journal.StatusSigned {
		t.Errorf("record status=%q after transient reconcile, want signed (recoverable)", recAfter.Status)
	}
}

// classifyFake bundles a service over a fake backend with a single programmed coin,
// for the classifier end-to-end tests.
type classifyFake struct {
	svc      *Service
	client   *fakebackend.Client
	teardown func()
}

func newClassifyFake(t *testing.T) *classifyFake {
	t.Helper()
	fake := fakebackend.New()
	fake.Tip = 800000
	programUTXO(fake, canonicalReceive0, "cf"+strings.Repeat("0", 62), 0, 1_000_000)
	svc, teardown := newSendService(t, fake)
	return &classifyFake{svc: svc, client: fake, teardown: teardown}
}
