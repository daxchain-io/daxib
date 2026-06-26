package coinselect_test

import (
	"errors"
	"math/rand"
	"testing"

	"github.com/daxchain-io/daxib/internal/coinselect"
	"github.com/daxchain-io/daxib/internal/domain"
)

// coin builds a Coin with a deterministic outpoint from an id.
func coin(id string, value int64) coinselect.Coin {
	return coinselect.Coin{Outpoint: id + ":0", Branch: domain.BranchReceive, Index: 0, ValueSat: value}
}

// assertConserved checks the value-conservation invariant and the fee-floor
// invariant on a successful Result. Σinputs == Target + Fee + Change, and the fee
// is at least the fee for the predicted vsize at the (clamped) feerate.
func assertConserved(t *testing.T, r coinselect.Result, target, feeRate int64) {
	t.Helper()
	if feeRate < 1 {
		feeRate = 1
	}
	var sumIn int64
	for _, c := range r.Inputs {
		sumIn += c.ValueSat
	}
	if sumIn != target+r.FeeSat+r.ChangeSat {
		t.Errorf("value conservation broken: Σinputs=%d != target=%d + fee=%d + change=%d (=%d)",
			sumIn, target, r.FeeSat, r.ChangeSat, target+r.FeeSat+r.ChangeSat)
	}
	if r.FeeSat < 0 || r.ChangeSat < 0 {
		t.Errorf("negative fee/change: fee=%d change=%d", r.FeeSat, r.ChangeSat)
	}
	nout := 1
	if r.HasChange {
		nout = 2
	}
	minFee := coinselect.FeeFor(coinselect.EstimateVSize(len(r.Inputs), nout), feeRate)
	if r.HasChange {
		// With change, the fee is exactly the predicted fee.
		if r.FeeSat != minFee {
			t.Errorf("with-change fee=%d != predicted %d", r.FeeSat, minFee)
		}
		if coinselect.IsDust(r.ChangeSat) {
			t.Errorf("emitted a DUST change output of %d sat (< %d)", r.ChangeSat, coinselect.DustThresholdP2WPKH)
		}
	} else {
		// Changeless legitimately overpays the absorbed sub-dust surplus, but never
		// UNDERpays relay.
		if r.FeeSat < minFee {
			t.Errorf("changeless fee=%d UNDERPAYS predicted %d", r.FeeSat, minFee)
		}
	}
	if r.VSizeVB != coinselect.EstimateVSize(len(r.Inputs), nout) {
		t.Errorf("VSizeVB=%d != EstimateVSize(%d,%d)=%d", r.VSizeVB, len(r.Inputs), nout, coinselect.EstimateVSize(len(r.Inputs), nout))
	}
}

func TestSelect_SingleCoinWithChange(t *testing.T) {
	// One big coin, modest target → a change output must be produced.
	coins := []coinselect.Coin{coin("a", 1_000_000)}
	target := int64(100_000)
	r, err := coinselect.Select(coins, coinselect.Params{Target: target, FeeRateSatVB: 10})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if !r.HasChange {
		t.Fatalf("expected a change output for a coin much larger than target+fee+dust")
	}
	if len(r.Inputs) != 1 {
		t.Fatalf("expected 1 input, got %d", len(r.Inputs))
	}
	assertConserved(t, r, target, 10)
}

func TestSelect_OverpayGuard_LargeCoinProducesChange(t *testing.T) {
	// A coin FAR larger than target+fee+dust MUST yield a change output, never burn
	// the surplus to fee.
	coins := []coinselect.Coin{coin("big", 50_000_000)}
	target := int64(1_000_000)
	r, err := coinselect.Select(coins, coinselect.Params{Target: target, FeeRateSatVB: 5})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if !r.HasChange {
		t.Fatalf("a 0.5 BTC coin spending 0.01 BTC MUST produce change, not burn 0.49 BTC to fee")
	}
	// Change ≈ coin - target - fee.
	wantChange := 50_000_000 - target - r.FeeSat
	if r.ChangeSat != wantChange {
		t.Errorf("ChangeSat=%d, want %d", r.ChangeSat, wantChange)
	}
	assertConserved(t, r, target, 5)
}

func TestSelect_DustChangeCollapsesToFee(t *testing.T) {
	// Construct inputs so the leftover change is exactly at the dust boundary.
	// With 1 input, 1-out fee at rate 1 = EstimateVSize(1,1)=110. With change the
	// 2-out fee = 141. Pick a coin so (coin - target - feeWithChange) sits at 293
	// (dust → collapse) vs 294 (emit).
	const rate = 1
	target := int64(50_000)
	feeWithChange := coinselect.FeeFor(coinselect.EstimateVSize(1, 2), rate) // 141

	// change = coin - target - feeWithChange. For change=293 (dust): coin = target+141+293.
	coinDust := target + feeWithChange + 293
	rDust, err := coinselect.Select([]coinselect.Coin{coin("d", coinDust)}, coinselect.Params{Target: target, FeeRateSatVB: rate})
	if err != nil {
		t.Fatalf("Select dust: %v", err)
	}
	if rDust.HasChange {
		t.Errorf("change of 293 sat (dust) must collapse to changeless, got HasChange=true change=%d", rDust.ChangeSat)
	}
	assertConserved(t, rDust, target, rate)

	// For change=294 (non-dust): coin = target+141+294 → a change output is emitted.
	coinEmit := target + feeWithChange + 294
	rEmit, err := coinselect.Select([]coinselect.Coin{coin("e", coinEmit)}, coinselect.Params{Target: target, FeeRateSatVB: rate})
	if err != nil {
		t.Fatalf("Select emit: %v", err)
	}
	if !rEmit.HasChange || rEmit.ChangeSat != 294 {
		t.Errorf("change of 294 sat must be emitted, got HasChange=%v change=%d", rEmit.HasChange, rEmit.ChangeSat)
	}
	assertConserved(t, rEmit, target, rate)
}

func TestSelect_ChangelessAbsorbedSurplusBounded(t *testing.T) {
	// A coin whose surplus over target+fee is just under dust+costOfChange → a
	// changeless tx; the absorbed surplus must be < dust + costOfChange.
	const rate = 2
	target := int64(40_000)
	feeNoChange := coinselect.FeeFor(coinselect.EstimateVSize(1, 1), rate)
	costOfChange := coinselect.FeeFor(coinselect.EstimateVSize(0, 1)-coinselect.EstimateVSize(0, 0), rate) // 31*rate
	// Pick coin so surplus = feeNoChange + (dust-1). Changeless, absorbed = surplus.
	coinVal := target + feeNoChange + (coinselect.DustThresholdP2WPKH - 1)
	r, err := coinselect.Select([]coinselect.Coin{coin("c", coinVal)}, coinselect.Params{Target: target, FeeRateSatVB: rate})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if r.HasChange {
		t.Fatalf("expected changeless absorb, got change=%d", r.ChangeSat)
	}
	absorbed := r.FeeSat - feeNoChange
	if absorbed >= coinselect.DustThresholdP2WPKH+costOfChange {
		t.Errorf("absorbed surplus %d sat exceeds dust+costOfChange bound %d — a change output should have been created",
			absorbed, coinselect.DustThresholdP2WPKH+costOfChange)
	}
	assertConserved(t, r, target, rate)
}

func TestSelect_ExactMatchNoChange(t *testing.T) {
	// Σeff lands exactly on target: coin = target + fee(1,1). No change, fee exact.
	const rate = 3
	target := int64(75_000)
	feeNoChange := coinselect.FeeFor(coinselect.EstimateVSize(1, 1), rate)
	coinVal := target + feeNoChange
	r, err := coinselect.Select([]coinselect.Coin{coin("x", coinVal)}, coinselect.Params{Target: target, FeeRateSatVB: rate})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if r.HasChange {
		t.Fatalf("exact spend must be changeless, got change=%d", r.ChangeSat)
	}
	if r.FeeSat != feeNoChange {
		t.Errorf("exact-spend fee=%d, want %d", r.FeeSat, feeNoChange)
	}
	assertConserved(t, r, target, rate)
}

func TestSelect_InsufficientFunds(t *testing.T) {
	// Total available far below target.
	coins := []coinselect.Coin{coin("a", 10_000), coin("b", 20_000)}
	_, err := coinselect.Select(coins, coinselect.Params{Target: 1_000_000, FeeRateSatVB: 10})
	if err == nil {
		t.Fatalf("expected insufficient funds error")
	}
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != domain.CodeFundsInsufficient {
		t.Fatalf("err=%v, want %s (exit 5)", err, domain.CodeFundsInsufficient)
	}
	if de.Exit != domain.ExitInsufficientFunds {
		t.Errorf("exit=%d, want 5", de.Exit)
	}
	if de.Data["available_sat"] == nil || de.Data["needed_sat"] == nil {
		t.Errorf("insufficient error missing data hints: %v", de.Data)
	}
}

func TestSelect_InsufficientBoundary_TotalEffEqualsTarget(t *testing.T) {
	// totalEff exactly == target means we can cover the recipient but NOT the fee
	// once an output is added — the no-change branch needs target+feeNoChange.
	const rate = 5
	inputFee := coinselect.FeeFor(68, rate)
	// One coin with effVal exactly == target: value = target + inputFee.
	target := int64(100_000)
	coinVal := target + inputFee
	// This makes totalEff == target. Σval == target+inputFee, but feeNoChange =
	// EstimateVSize(1,1)*rate = 110*rate = 550 > inputFee(340)? 68*5=340; 110*5=550.
	// So Σval - target = 340 < 550 → insufficient.
	_, err := coinselect.Select([]coinselect.Coin{coin("k", coinVal)}, coinselect.Params{Target: target, FeeRateSatVB: rate})
	if err == nil {
		t.Fatalf("expected insufficient at the totalEff==target boundary")
	}
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != domain.CodeFundsInsufficient {
		t.Fatalf("err=%v, want funds.insufficient", err)
	}
}

func TestSelect_UneconomicInputsFiltered(t *testing.T) {
	// A wallet of tiny dust UTXOs at a high feerate: each effVal<0, so even though
	// raw Σvalue looks like it covers a small target, selection fails.
	const rate = 100
	// inputFee = 68*100 = 6800. A 300-sat UTXO has effVal = -6500 → filtered.
	coins := []coinselect.Coin{coin("d1", 300), coin("d2", 400), coin("d3", 500)}
	_, err := coinselect.Select(coins, coinselect.Params{Target: 1_000, FeeRateSatVB: rate})
	if err == nil {
		t.Fatalf("expected insufficient when every input is uneconomic")
	}
	var de *domain.Error
	if !errors.As(err, &de) || de.Exit != domain.ExitInsufficientFunds {
		t.Fatalf("err=%v, want exit 5", err)
	}
}

func TestSelect_FeeRateClampedToFloor(t *testing.T) {
	// rate 0 must be treated as 1 sat/vB (the relay floor).
	coins := []coinselect.Coin{coin("a", 1_000_000)}
	target := int64(100_000)
	r0, err := coinselect.Select(coins, coinselect.Params{Target: target, FeeRateSatVB: 0})
	if err != nil {
		t.Fatalf("Select rate 0: %v", err)
	}
	r1, err := coinselect.Select(coins, coinselect.Params{Target: target, FeeRateSatVB: 1})
	if err != nil {
		t.Fatalf("Select rate 1: %v", err)
	}
	if r0.FeeSat != r1.FeeSat || r0.HasChange != r1.HasChange {
		t.Errorf("rate 0 not clamped to 1: r0.fee=%d r1.fee=%d", r0.FeeSat, r1.FeeSat)
	}
	assertConserved(t, r0, target, 1)
}

func TestSelect_AmountBelowDust(t *testing.T) {
	coins := []coinselect.Coin{coin("a", 1_000_000)}
	_, err := coinselect.Select(coins, coinselect.Params{Target: 293, FeeRateSatVB: 1})
	if err == nil {
		t.Fatalf("expected usage.dust_output for a 293-sat target")
	}
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != domain.CodeUsageDustOutput {
		t.Fatalf("err=%v, want %s (exit 2)", err, domain.CodeUsageDustOutput)
	}
	// 294 is exactly the dust threshold and must be accepted.
	if _, err := coinselect.Select(coins, coinselect.Params{Target: 294, FeeRateSatVB: 1}); err != nil {
		t.Fatalf("294-sat target should be accepted: %v", err)
	}
}

func TestSelect_NonPositiveTarget(t *testing.T) {
	coins := []coinselect.Coin{coin("a", 1_000_000)}
	_, err := coinselect.Select(coins, coinselect.Params{Target: 0, FeeRateSatVB: 1})
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != domain.CodeUsageBadAmount {
		t.Fatalf("Target 0 err=%v, want usage.bad_amount", err)
	}
}

func TestSelect_Convergence_AddingInputRaisesFee(t *testing.T) {
	// Many medium UTXOs where adding the Nth input bumps the fee enough to require
	// an N+1th. At rate 50, inputFee=3400. Target needs ~3 coins of 50k each.
	const rate = 50
	coins := make([]coinselect.Coin, 0, 10)
	for i := 0; i < 10; i++ {
		coins = append(coins, coin(string(rune('a'+i)), 50_000))
	}
	target := int64(120_000)
	r, err := coinselect.Select(coins, coinselect.Params{Target: target, FeeRateSatVB: rate})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	// The final fee must match the FINAL input count (no stale-count underpay).
	nout := 1
	if r.HasChange {
		nout = 2
	}
	wantMinFee := coinselect.FeeFor(coinselect.EstimateVSize(len(r.Inputs), nout), rate)
	if r.FeeSat < wantMinFee {
		t.Errorf("fee=%d underpays the final %d-input vsize fee %d", r.FeeSat, len(r.Inputs), wantMinFee)
	}
	var sumIn int64
	for _, c := range r.Inputs {
		sumIn += c.ValueSat
	}
	if sumIn < target+r.FeeSat {
		t.Errorf("selected Σ=%d does not cover target+fee=%d", sumIn, target+r.FeeSat)
	}
	assertConserved(t, r, target, rate)
}

func TestSelect_Deterministic_ShuffleInvariant(t *testing.T) {
	base := []coinselect.Coin{
		coin("a", 30_000), coin("b", 70_000), coin("c", 120_000),
		coin("d", 45_000), coin("e", 200_000), coin("f", 15_000),
	}
	target := int64(150_000)
	params := coinselect.Params{Target: target, FeeRateSatVB: 8}

	want, err := coinselect.Select(base, params)
	if err != nil {
		t.Fatalf("Select base: %v", err)
	}

	rng := rand.New(rand.NewSource(42))
	for trial := 0; trial < 20; trial++ {
		shuffled := make([]coinselect.Coin, len(base))
		copy(shuffled, base)
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		got, gerr := coinselect.Select(shuffled, params)
		if gerr != nil {
			t.Fatalf("Select shuffled: %v", gerr)
		}
		if got.FeeSat != want.FeeSat || got.ChangeSat != want.ChangeSat || got.HasChange != want.HasChange || len(got.Inputs) != len(want.Inputs) {
			t.Fatalf("non-deterministic result on shuffle: want %+v got %+v", want, got)
		}
		for i := range got.Inputs {
			if got.Inputs[i].Outpoint != want.Inputs[i].Outpoint {
				t.Fatalf("input order differs on shuffle at %d: want %s got %s", i, want.Inputs[i].Outpoint, got.Inputs[i].Outpoint)
			}
		}
	}
	assertConserved(t, want, target, 8)
}
