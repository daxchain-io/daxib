package service

import (
	"context"
	"errors"
	"testing"

	fakebackend "github.com/daxchain-io/daxib/internal/backend/fake"
	"github.com/daxchain-io/daxib/internal/domain"
)

func TestFeeFloorApplied(t *testing.T) {
	fake := fakebackend.New()
	fake.Fees = domain.FeeEstimates{
		Slow: 0, Normal: 5, Fast: 25, // a 0-tier from a cold backend → floored to 1
		ByTarget: map[int]int64{6: 0, 3: 5, 1: 25},
	}
	svc, teardown := newSendService(t, fake)
	defer teardown()

	res, err := svc.Fee(context.Background(), domain.FeeRequest{Speed: "normal"})
	if err != nil {
		t.Fatalf("Fee: %v", err)
	}
	if res.Slow != 1 {
		t.Errorf("Slow=%d, want 1 (floor applied to a 0 tier)", res.Slow)
	}
	if res.Normal != 5 || res.Fast != 25 {
		t.Errorf("Normal=%d Fast=%d, want 5/25", res.Normal, res.Fast)
	}
	if res.SelectedRate != 5 || res.Selected != "normal" {
		t.Errorf("selected=%s rate=%d, want normal/5", res.Selected, res.SelectedRate)
	}
	if res.FloorSatVB != 1 {
		t.Errorf("FloorSatVB=%d, want 1", res.FloorSatVB)
	}
}

func TestResolveFeeRate(t *testing.T) {
	est := domain.FeeEstimates{Slow: 6, Normal: 12, Fast: 30}

	// Explicit --fee-rate verbatim.
	if r, err := resolveFeeRate("20", "normal", est); err != nil || r != 20 {
		t.Errorf("explicit 20: r=%d err=%v, want 20", r, err)
	}
	// Missing → tier by speed.
	if r, err := resolveFeeRate("", "fast", est); err != nil || r != 30 {
		t.Errorf("speed fast: r=%d err=%v, want 30", r, err)
	}
	if r, err := resolveFeeRate("", "slow", est); err != nil || r != 6 {
		t.Errorf("speed slow: r=%d err=%v, want 6", r, err)
	}
	// Backend-zero tier → floor 1.
	zero := domain.FeeEstimates{Slow: 0, Normal: 0, Fast: 0}
	if r, err := resolveFeeRate("", "normal", zero); err != nil || r != 1 {
		t.Errorf("zero tier: r=%d err=%v, want 1 (floor)", r, err)
	}
	// --fee-rate 0 → usage.bad_fee_rate (below relay floor).
	_, err := resolveFeeRate("0", "normal", est)
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != domain.CodeUsageBadFeeRate {
		t.Errorf("--fee-rate 0 err=%v, want usage.bad_fee_rate", err)
	}
	// Non-integer --fee-rate.
	_, err = resolveFeeRate("1.5", "normal", est)
	if !errors.As(err, &de) || de.Code != domain.CodeUsageBadFeeRate {
		t.Errorf("--fee-rate 1.5 err=%v, want usage.bad_fee_rate", err)
	}
}

// TestParseFeeRateOverflowRejected is the regression for feerate-int64-overflow: an
// over-range --fee-rate must be rejected with usage.bad_fee_rate (exit 2), never
// silently int64-wrapped to a garbage positive value (which previously produced a
// corrupt selection — a negative fee / change larger than inputs).
func TestParseFeeRateOverflowRejected(t *testing.T) {
	for _, s := range []string{
		"99999999999999999999",  // overflows int64 → would wrap positive
		"9223372036854775808",   // math.MaxInt64 + 1
		"10000001",              // just over the maxFeeRate sanity cap
		"170141183460469231731", // 2^127-ish
	} {
		_, err := parseFeeRate(s)
		var de *domain.Error
		if !errors.As(err, &de) || de.Code != domain.CodeUsageBadFeeRate || de.Exit != domain.ExitUsage {
			t.Errorf("parseFeeRate(%q)=err %v, want usage.bad_fee_rate (exit 2)", s, err)
		}
	}
	// The cap boundary itself is accepted.
	if r, err := parseFeeRate("10000000"); err != nil || r != maxFeeRate {
		t.Errorf("parseFeeRate(maxFeeRate) r=%d err=%v, want %d accepted", r, err, maxFeeRate)
	}
}

// TestValidateSendInputs_FeeRateAndSpeedPreDial is the regression for
// feerate-speed-validated-after-dial: a malformed --fee-rate / --speed must be a
// usage error (exit 2) caught by validateSendInputs BEFORE any backend dial — not a
// backend.not_configured (exit 10) / backend.unreachable (exit 6) surfaced after the
// dial. validateSendInputs runs with no backend at all.
func TestValidateSendInputs_FeeRateAndSpeedPreDial(t *testing.T) {
	// A service with NO backend configured: if validation reached the dial, a
	// malformed fee input would surface as backend.not_configured (exit 10).
	keystoreDir := t.TempDir()
	svc, err := Open(context.Background(), Options{
		Keystore: keystoreDir, Config: t.TempDir(), State: t.TempDir(),
		Network: "mainnet", KDFLight: true,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = svc.Close() }()

	base := domain.SendRequest{Wallet: "vec", To: extRecipient, Amount: "0.005", Yes: true}

	// Malformed --fee-rate → usage.bad_fee_rate (exit 2), pre-dial.
	bad := base
	bad.FeeRate = "abc"
	if err := svc.validateSendInputs(bad); err == nil {
		t.Errorf("validateSendInputs accepted --fee-rate abc")
	} else if de := domain.AsError(err); de == nil || de.Exit != domain.ExitUsage {
		t.Errorf("--fee-rate abc err=%v, want exit 2", err)
	}

	// Over-range --fee-rate → exit 2, pre-dial.
	over := base
	over.FeeRate = "99999999999999999999"
	if err := svc.validateSendInputs(over); err == nil {
		t.Errorf("validateSendInputs accepted an over-range --fee-rate")
	} else if de := domain.AsError(err); de == nil || de.Exit != domain.ExitUsage {
		t.Errorf("over-range --fee-rate err=%v, want exit 2", err)
	}

	// Unknown --speed → usage.speed (exit 2), pre-dial.
	speed := base
	speed.Speed = "warp"
	if err := svc.validateSendInputs(speed); err == nil {
		t.Errorf("validateSendInputs accepted --speed warp")
	} else if de := domain.AsError(err); de == nil || de.Exit != domain.ExitUsage {
		t.Errorf("--speed warp err=%v, want exit 2", err)
	}

	// A valid fee-rate + valid speed pass pre-dial validation.
	okFee := base
	okFee.FeeRate = "10"
	if err := svc.validateSendInputs(okFee); err != nil {
		t.Errorf("valid --fee-rate 10 rejected: %v", err)
	}
	okSpeed := base
	okSpeed.Speed = "fast"
	if err := svc.validateSendInputs(okSpeed); err != nil {
		t.Errorf("valid --speed fast rejected: %v", err)
	}
}
