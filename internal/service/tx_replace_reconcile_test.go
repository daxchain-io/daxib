package service

import (
	"context"
	"strings"
	"testing"

	"github.com/daxchain-io/daxib/internal/backend"
	fakebackend "github.com/daxchain-io/daxib/internal/backend/fake"
	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/journal"
)

// reopenPolicyService re-Opens a Service against the SAME dirs + backend so that
// reconcileAtOpen / reconcilePolicyOrphans runs against the journal — the path that
// resolves an orphaned (still-`reserved`) spend reservation at startup.
func reopenPolicyService(t *testing.T, old *Service, fake *fakebackend.Client) *Service {
	t.Helper()
	env := map[string]string{
		"DAXIB_KEYSTORE":           old.opts.Keystore,
		"DAXIB_KDF_LIGHT":          "1",
		"DAXIB_PASSPHRASE":         "test-pass-12345678",
		"DAXIB_PASSPHRASE_CONFIRM": "test-pass-12345678",
		"DAXIB_ADMIN_PASSPHRASE":   "admin-secret-xyz",
	}
	svc, err := Open(context.Background(), Options{
		Keystore: old.opts.Keystore,
		Config:   old.opts.Config,
		State:    old.opts.State,
		Network:  "mainnet",
		KDFLight: true,
		Dial: func(_ context.Context, _ backend.Options) (backend.Client, error) {
			return fake, nil
		},
		Secret: SecretIO{
			Stdin:     strings.NewReader(canonicalMnemonic),
			LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok },
			IsTTY:     func() bool { return false },
			Prompt:    func(string) ([]byte, error) { return nil, nil },
		},
	})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	return svc
}

// TestSpeedupReconcileKeepsReplacedOriginalReservationCommitted is the RBF-policy
// reconciliation regression: when the original send's spend reservation was left
// `reserved` (a transport-exhausted broadcast that never committed), replacing it
// charges ONLY the fee delta on the assumption that the original's reservation is
// still counted. At the next Open, reconcilePolicyOrphans must COMMIT (not release)
// the orphaned reservation of a `replaced` original — releasing it would drop the
// original payment amount from the rolling-24h window and let an RBF cycle bypass
// the daily limit.
func TestSpeedupReconcileKeepsReplacedOriginalReservationCommitted(t *testing.T) {
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

	// Force the ORIGINAL broadcast to be transport-exhausted: the record stays `signed`
	// and the reservation stays `reserved` (never committed).
	fake.BroadcastFn = func(_ context.Context, _ []byte) (string, error) {
		return "", domain.New(domain.CodeBackendUnreachable, "simulated transport failure")
	}
	orig, _ := svc.SendTx(context.Background(), domain.LocalCLI(), domain.SendRequest{
		Wallet: "vec", To: extRecipient, Amount: "0.005", FeeRate: "5", Yes: true,
	}, nil)

	// The network recovers: broadcasts succeed from here.
	captureBroadcast(fake, new([]byte))

	repl, err := svc.SpeedupTx(context.Background(), domain.LocalCLI(), domain.SpeedupRequest{
		Wallet: "vec", Txid: orig.Txid, FeeRate: "20", Yes: true,
	}, nil)
	if err != nil {
		t.Fatalf("speedup: %v", err)
	}

	// Sanity: the original is now `replaced` and its reservation is still an orphan
	// (reserved) — the precondition for the reconcile path under test.
	origRec, _ := svc.journal.ByTxid(context.Background(), svc.net, orig.Txid)
	if origRec.Status != journal.StatusReplaced {
		t.Fatalf("original status=%q, want replaced", origRec.Status)
	}

	trueOutflow := repl.AmountSat + repl.FeeSat

	// Re-Open: reconcilePolicyOrphans resolves the orphaned reservation against the
	// journal. The replaced original's reservation must be COMMITTED, not released.
	svc2 := reopenPolicyService(t, svc, fake)
	defer func() { _ = svc2.Close() }()

	got := windowUsed(t, svc2)
	if got != trueOutflow {
		t.Fatalf("after reconcile the window=%d, want %d (amount+newFee); a release of the replaced original's reservation under-counts the live spend by %d",
			got, trueOutflow, trueOutflow-got)
	}
}
