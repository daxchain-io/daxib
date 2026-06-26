package service

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/wire"

	"github.com/daxchain-io/daxib/internal/backend"
	fakebackend "github.com/daxchain-io/daxib/internal/backend/fake"
	"github.com/daxchain-io/daxib/internal/domain"
)

// policy_send_test.go proves the §2.7/§5.1 chokepoint: the send pipeline DENIES an
// over-limit/non-allowlisted send (exit 3) BEFORE the keystore signs — nothing is
// signed or broadcast — and ALLOWS a within-limit send (the engine-verified send
// still works with a policy active). It also proves the reservation accumulates the
// rolling-24h window and frees it on a pre-sign failure.

// newPolicySendService is newSendService with the admin-passphrase env wired so the
// test can bootstrap a sealed policy.
func newPolicySendService(t *testing.T, fake *fakebackend.Client) (*Service, func()) {
	t.Helper()
	keystoreDir := t.TempDir()
	configDir := t.TempDir()
	stateDir := t.TempDir()
	env := map[string]string{
		"DAXIB_KEYSTORE":           keystoreDir,
		"DAXIB_KDF_LIGHT":          "1",
		"DAXIB_PASSPHRASE":         "test-pass-12345678",
		"DAXIB_PASSPHRASE_CONFIRM": "test-pass-12345678",
		"DAXIB_ADMIN_PASSPHRASE":   "admin-secret-xyz",
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

// countingBroadcast records whether Broadcast was ever called (to prove a denied
// send never reaches the wire).
func countingBroadcast(fake *fakebackend.Client, calls *int) {
	var mu sync.Mutex
	fake.BroadcastFn = func(_ context.Context, raw []byte) (string, error) {
		mu.Lock()
		*calls++
		mu.Unlock()
		tx := wire.NewMsgTx(2)
		if err := tx.Deserialize(bytes.NewReader(raw)); err != nil {
			return "", err
		}
		return tx.TxHash().String(), nil
	}
}

func TestSendDeniedOverLimitBeforeSigning(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	var broadcasts int
	countingBroadcast(fake, &broadcasts)

	svc, teardown := newPolicySendService(t, fake)
	defer teardown()

	// Bootstrap a policy with a per-tx cap WELL below the send (allowlist off so the
	// only gate is the amount limit). max-tx = 100_000 sat.
	if _, err := svc.PolicySet(context.Background(), PolicySetInput{
		MaxTxSat: "100000", AllowlistOn: boolFalse(),
	}); err != nil {
		t.Fatalf("PolicySet: %v", err)
	}

	programUTXO(fake, canonicalReceive0, "11"+strings.Repeat("0", 62), 0, 1_000_000)

	// Send 0.005 BTC (500_000 sat) — over the 100_000 cap ⇒ DENIED (exit 3) before
	// any signature exists.
	_, err := svc.SendTx(context.Background(), domain.SendRequest{
		Wallet: "vec", To: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
		Amount: "0.005", FeeRate: "10", Yes: true,
	}, nil)
	if err == nil {
		t.Fatal("over-limit send must be denied")
	}
	de := domain.AsError(err)
	if de.Code != "policy.denied.tx_limit" || de.Exit != domain.ExitPolicyDenied {
		t.Fatalf("denied send: code=%s exit=%d; want policy.denied.tx_limit / exit 3", de.Code, de.Exit)
	}

	// NOTHING was broadcast — the denial happened before signing.
	if broadcasts != 0 {
		t.Fatalf("a denied send must NOT broadcast; got %d broadcast calls", broadcasts)
	}
	// And no journal record exists (the send never reached Append).
	recs, _ := svc.journal.List(context.Background(), svc.net, "")
	for _, r := range recs {
		if r.Status == "signed" || r.Status == "broadcast" {
			t.Fatalf("a denied send must leave NO signed/broadcast journal record; found %s", r.Status)
		}
	}
}

func TestSendAllowedWithinLimit(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	var broadcasts int
	countingBroadcast(fake, &broadcasts)

	svc, teardown := newPolicySendService(t, fake)
	defer teardown()

	// A generous cap (allowlist off): a normal send proceeds and broadcasts.
	if _, err := svc.PolicySet(context.Background(), PolicySetInput{
		MaxTxSat: "100000000", MaxDaySat: "100000000", AllowlistOn: boolFalse(),
	}); err != nil {
		t.Fatalf("PolicySet: %v", err)
	}
	programUTXO(fake, canonicalReceive0, "11"+strings.Repeat("0", 62), 0, 1_000_000)

	res, err := svc.SendTx(context.Background(), domain.SendRequest{
		Wallet: "vec", To: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
		Amount: "0.005", FeeRate: "10", Yes: true,
	}, nil)
	if err != nil {
		t.Fatalf("within-limit send must succeed: %v", err)
	}
	if res.Status != domain.TxStateBroadcast || broadcasts != 1 {
		t.Fatalf("within-limit send: status=%s broadcasts=%d; want broadcast/1", res.Status, broadcasts)
	}

	// The reservation was committed: the rolling-24h counter shows the spend.
	cr, cerr := svc.PolicyCounters(context.Background())
	if cerr != nil {
		t.Fatal(cerr)
	}
	if len(cr.Counters) == 0 || cr.Counters[0].Used24hSat == "0" {
		t.Fatalf("a committed send must accumulate the rolling-24h counter: %+v", cr.Counters)
	}
}

func TestSendDayLimitDeniesSecondSendAndReleaseFrees(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	var broadcasts int
	countingBroadcast(fake, &broadcasts)

	svc, teardown := newPolicySendService(t, fake)
	defer teardown()

	// max-day = 700_000 sat (allowlist off). The first 0.005 BTC (500_000 + fee)
	// commits; a second 0.005 BTC would exceed the rolling-24h window ⇒ denied.
	if _, err := svc.PolicySet(context.Background(), PolicySetInput{
		MaxDaySat: "700000", AllowlistOn: boolFalse(),
	}); err != nil {
		t.Fatalf("PolicySet: %v", err)
	}
	// Two independent confirmed UTXOs so the second send has spendable coins.
	programUTXO(fake, canonicalReceive0, "11"+strings.Repeat("0", 62), 0, 1_000_000)
	programUTXO(fake, canonicalReceive0, "22"+strings.Repeat("0", 62), 0, 1_000_000)

	// First send commits.
	if _, err := svc.SendTx(context.Background(), domain.SendRequest{
		Wallet: "vec", To: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
		Amount: "0.005", FeeRate: "10", Yes: true,
	}, nil); err != nil {
		t.Fatalf("first send: %v", err)
	}

	// Second send would push the rolling-24h total over 700_000 ⇒ denied (exit 3).
	_, err := svc.SendTx(context.Background(), domain.SendRequest{
		Wallet: "vec", To: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
		Amount: "0.005", FeeRate: "10", Yes: true,
	}, nil)
	if err == nil {
		t.Fatal("second send over the day limit must be denied")
	}
	if de := domain.AsError(err); de.Code != "policy.denied.day_limit" {
		t.Fatalf("second send: code=%s; want policy.denied.day_limit", de.Code)
	}
	// Exactly one broadcast (the first send); the second never reached the wire.
	if broadcasts != 1 {
		t.Fatalf("expected exactly 1 broadcast, got %d", broadcasts)
	}
}

func boolFalse() *bool { v := false; return &v }
