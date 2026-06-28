package service

import (
	"context"
	"math/big"
	"strings"
	"testing"

	fakebackend "github.com/daxchain-io/daxib/internal/backend/fake"
	"github.com/daxchain-io/daxib/internal/domain"
)

// windowUsed reads the rolling-24h counter total for the active network.
func windowUsed(t *testing.T, svc *Service) int64 {
	t.Helper()
	cr, err := svc.PolicyCounters(context.Background(), domain.LocalCLI())
	if err != nil {
		t.Fatalf("PolicyCounters: %v", err)
	}
	if len(cr.Counters) == 0 {
		return 0
	}
	v, ok := new(big.Int).SetString(cr.Counters[0].Used24hSat, 10)
	if !ok {
		t.Fatalf("counter not an int: %q", cr.Counters[0].Used24hSat)
	}
	return v.Int64()
}

// TestSpeedupPolicyChargesFeeDeltaOnly is the TC-9/TXR-4 double-count guard: after a
// send then a speedup, the rolling-24h counter increases by EXACTLY the fee delta
// (newFee - origFee), not by amount+fee twice.
func TestSpeedupPolicyChargesFeeDeltaOnly(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	captureBroadcast(fake, new([]byte))

	svc, teardown := newPolicySendService(t, fake)
	defer teardown()

	// A generous day cap so neither the send nor the speedup is denied.
	if _, err := svc.PolicySet(context.Background(), domain.LocalCLI(), PolicySetInput{
		MaxDaySat: "100000000", AllowlistOn: boolFalse(),
	}); err != nil {
		t.Fatalf("PolicySet: %v", err)
	}
	programUTXO(fake, canonicalReceive0, "11"+strings.Repeat("0", 62), 0, 1_000_000)

	orig, err := svc.SendTx(context.Background(), domain.LocalCLI(), domain.SendRequest{
		Wallet: "vec", To: extRecipient, Amount: "0.005", FeeRate: "5", Yes: true,
	}, nil)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	usedAfterSend := windowUsed(t, svc)
	// The send charged amount+fee.
	if want := orig.AmountSat + orig.FeeSat; usedAfterSend != want {
		t.Fatalf("after send window=%d, want %d (amount+fee)", usedAfterSend, want)
	}

	repl, err := svc.SpeedupTx(context.Background(), domain.LocalCLI(), domain.SpeedupRequest{
		Wallet: "vec", Txid: orig.Txid, FeeRate: "20", Yes: true,
	}, nil)
	if err != nil {
		t.Fatalf("speedup: %v", err)
	}
	usedAfterSpeedup := windowUsed(t, svc)

	// The window grew by EXACTLY the fee delta (no double-count of the 500_000 payment).
	delta := repl.FeeSat - orig.FeeSat
	if got := usedAfterSpeedup - usedAfterSend; got != delta {
		t.Fatalf("window grew by %d after speedup, want the fee delta %d (no double-count)", got, delta)
	}
	// Total window == amount + newFee (the original payment counted ONCE + the bump).
	if want := orig.AmountSat + repl.FeeSat; usedAfterSpeedup != want {
		t.Fatalf("total window=%d, want %d (amount + newFee, single-count)", usedAfterSpeedup, want)
	}
}

// TestSpeedupPerTxCapUsesFullOutflow: a speedup whose amount+newFee exceeds max_tx is
// denied exit 3 even though only the delta hits the daily window (Stage 3 sees the
// full outflow).
func TestSpeedupPerTxCapUsesFullOutflow(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	captureBroadcast(fake, new([]byte))

	svc, teardown := newPolicySendService(t, fake)
	defer teardown()

	programUTXO(fake, canonicalReceive0, "11"+strings.Repeat("0", 62), 0, 1_000_000)

	// Send under a generous policy first.
	if _, e := svc.PolicySet(context.Background(), domain.LocalCLI(), PolicySetInput{
		MaxTxSat: "100000000", MaxDaySat: "100000000", AllowlistOn: boolFalse(),
	}); e != nil {
		t.Fatalf("PolicySet: %v", e)
	}
	o, e := svc.SendTx(context.Background(), domain.LocalCLI(), domain.SendRequest{
		Wallet: "vec", To: extRecipient, Amount: "0.005", FeeRate: "5", Yes: true,
	}, nil)
	if e != nil {
		t.Fatalf("send: %v", e)
	}
	// Tighten max-tx to just above the original spend (amount+fee) but below
	// amount+newFee at the bumped rate.
	maxTx := o.AmountSat + o.FeeSat + 100
	if _, e := svc.PolicySet(context.Background(), domain.LocalCLI(), PolicySetInput{
		MaxTxSat: bigStr(maxTx), AllowlistOn: boolFalse(),
	}); e != nil {
		t.Fatalf("PolicySet tighten: %v", e)
	}

	// A big fee bump pushes amount+newFee over the per-tx cap ⇒ denied exit 3, even
	// though only the fee delta would hit the daily window.
	_, err := svc.SpeedupTx(context.Background(), domain.LocalCLI(), domain.SpeedupRequest{
		Wallet: "vec", Txid: o.Txid, FeeRate: "500", Yes: true,
	}, nil)
	de := domain.AsError(err)
	if de == nil || de.Code != "policy.denied.tx_limit" || de.Exit != domain.ExitPolicyDenied {
		t.Fatalf("speedup over max_tx: err=%v, want policy.denied.tx_limit exit 3", err)
	}
}

// TestSpeedupDeniedToDeAllowlistedRecipient: with the allowlist ON, removing the
// recipient after the original send must DENY a speedup (RBF cannot launder a
// now-forbidden destination).
func TestSpeedupDeniedToDeAllowlistedRecipient(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	captureBroadcast(fake, new([]byte))

	svc, teardown := newPolicySendService(t, fake)
	defer teardown()

	on := true
	if _, err := svc.PolicySet(context.Background(), domain.LocalCLI(), PolicySetInput{
		MaxTxSat: "100000000", MaxDaySat: "100000000", AllowlistOn: &on,
	}); err != nil {
		t.Fatalf("PolicySet: %v", err)
	}
	// Allow the recipient, send, then REMOVE it from the allowlist.
	if _, err := svc.PolicyAllow(context.Background(), domain.LocalCLI(), PolicyPinInput{Address: extRecipient}); err != nil {
		t.Fatalf("PolicyAllow: %v", err)
	}
	programUTXO(fake, canonicalReceive0, "11"+strings.Repeat("0", 62), 0, 1_000_000)
	orig, err := svc.SendTx(context.Background(), domain.LocalCLI(), domain.SendRequest{
		Wallet: "vec", To: extRecipient, Amount: "0.005", FeeRate: "5", Yes: true,
	}, nil)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if _, err := svc.PolicyAllow(context.Background(), domain.LocalCLI(), PolicyPinInput{Address: extRecipient, Remove: true}); err != nil {
		t.Fatalf("PolicyAllow remove: %v", err)
	}

	// The speedup re-evaluates the (still-original) recipient under the allowlist ⇒
	// DENIED (no bypass).
	_, serr := svc.SpeedupTx(context.Background(), domain.LocalCLI(), domain.SpeedupRequest{
		Wallet: "vec", Txid: orig.Txid, FeeRate: "20", Yes: true,
	}, nil)
	de := domain.AsError(serr)
	if de == nil || !strings.HasPrefix(de.Code, "policy.denied") || de.Exit != domain.ExitPolicyDenied {
		t.Fatalf("speedup to de-allowlisted recipient: err=%v, want policy.denied.* exit 3", serr)
	}
}

// TestCancelToSelfAllowedWhenIncludeSelfOff: with the allowlist ON and include_self
// OFF, a cancel still succeeds because the change addr is sealed into Check.ChangeAddr
// so isSelf passes — cancel-to-self is always permitted.
func TestCancelToSelfAllowedWhenIncludeSelfOff(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	captureBroadcast(fake, new([]byte))

	svc, teardown := newPolicySendService(t, fake)
	defer teardown()

	on, off := true, false
	if _, err := svc.PolicySet(context.Background(), domain.LocalCLI(), PolicySetInput{
		MaxTxSat: "100000000", MaxDaySat: "100000000", AllowlistOn: &on, IncludeSelf: &off,
	}); err != nil {
		t.Fatalf("PolicySet: %v", err)
	}
	// Allow the recipient so the original send is permitted.
	if _, err := svc.PolicyAllow(context.Background(), domain.LocalCLI(), PolicyPinInput{Address: extRecipient}); err != nil {
		t.Fatalf("PolicyAllow: %v", err)
	}
	programUTXO(fake, canonicalReceive0, "11"+strings.Repeat("0", 62), 0, 1_000_000)
	orig, err := svc.SendTx(context.Background(), domain.LocalCLI(), domain.SendRequest{
		Wallet: "vec", To: extRecipient, Amount: "0.005", FeeRate: "5", Yes: true,
	}, nil)
	if err != nil {
		t.Fatalf("send: %v", err)
	}

	// Cancel redirects to a fresh change addr. Even with include_self OFF and the
	// allowlist ON, the sealed ChangeAddr passes isSelf ⇒ the cancel is permitted.
	res, cerr := svc.CancelTx(context.Background(), domain.LocalCLI(), domain.CancelRequest{
		Wallet: "vec", Txid: orig.Txid, FeeRate: "20", Yes: true,
	}, nil)
	if cerr != nil {
		t.Fatalf("cancel-to-self must be permitted with include_self off: %v", cerr)
	}
	if !res.Replacement {
		t.Fatalf("cancel result not a replacement: %+v", res)
	}
}

// bigStr renders an int64 as a decimal string.
func bigStr(n int64) string { return big.NewInt(n).String() }
