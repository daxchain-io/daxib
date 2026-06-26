package coinselect

import (
	"sort"

	"github.com/daxchain-io/daxib/internal/domain"
)

// Coin is a candidate UTXO plus its derivation coordinates, so the signer can map
// a selected coin back to its private key (branch/index under the wallet's BIP-84
// account). ValueSat is the UTXO's value in satoshis. Outpoint ("txid:vout") is
// carried for deterministic tie-breaking and for the journal's record of consumed
// outpoints.
type Coin struct {
	Outpoint string
	Branch   domain.Branch
	Index    uint32
	ValueSat int64
}

// Params configures one Select run. Target is the recipient amount in sats;
// FeeRateSatVB is the resolved fee rate (< 1 is clamped to the 1 sat/vB relay
// floor). RecipientVBytes is the recipient output's REAL serialized vsize
// (coinselect.OutputVBytes of its scriptPubKey: P2WPKH 31, P2SH 32, P2PKH 34,
// P2TR/P2WSH 43); a non-positive value falls back to the P2WPKH size. The change
// output is always P2WPKH (31 vB).
type Params struct {
	Target          int64
	FeeRateSatVB    int64
	RecipientVBytes int64
}

// Result is the outcome of a successful selection. Inputs are the selected coins
// in deterministic order. HasChange/ChangeSat describe the change output (when a
// change output would be dust it is dropped and absorbed into FeeSat, so HasChange
// is false and ChangeSat is 0). VSizeVB is the predicted vsize of the SIGNED tx
// (with or without change). The value-conservation invariant holds:
//
//	Σ Inputs.ValueSat == Target + FeeSat + ChangeSat
type Result struct {
	Inputs    []Coin
	ChangeSat int64
	FeeSat    int64
	VSizeVB   int64
	HasChange bool
}

// maxBnBIterations bounds the branch-and-bound DFS so a pathological UTXO set
// cannot blow up the worst case; on the cap we fall through to the deterministic
// knapsack fallback.
const maxBnBIterations = 100_000

// Select chooses inputs to fund Target at FeeRateSatVB. It runs Bitcoin-Core-style
// branch-and-bound on effective values first (preferring a changeless tx whose
// surplus is cheaper to burn than a change output), then a largest-first knapsack
// fallback that emits a non-dust change output. It NEVER selects more value than
// available (insufficient → funds.insufficient, exit 5), NEVER creates a dust
// output, and accounts for the marginal fee of the change output itself.
//
// The confirmed/unconfirmed split is the CALLER's responsibility: Select is given
// the already-filtered set of spendable coins (mirroring balance.go's
// Confirmations>0 split); it does not reason about confirmations.
func Select(coins []Coin, p Params) (Result, error) {
	feeRate := p.FeeRateSatVB
	if feeRate < 1 {
		feeRate = 1 // min-relay floor; never produce a sub-1-sat/vB tx
	}
	// The recipient output's real serialized vsize (P2WPKH 31, P2SH 32, P2PKH 34,
	// P2TR/P2WSH 43). A non-positive value (an unset/unknown recipient) falls back to
	// the P2WPKH size so the legacy P2WPKH→P2WPKH path is unchanged. The change
	// output is always P2WPKH (p2wpkhOutputVBytes).
	recipVB := p.RecipientVBytes
	if recipVB <= 0 {
		recipVB = p2wpkhOutputVBytes
	}
	if p.Target <= 0 {
		return Result{}, domain.Newf(domain.CodeUsageBadAmount,
			"send amount %d sat must be positive", p.Target)
	}
	if p.Target < DustThresholdP2WPKH {
		return Result{}, domain.Newf(domain.CodeUsageDustOutput,
			"amount %d sat is below the dust threshold of %d sat", p.Target, DustThresholdP2WPKH)
	}

	// Per-input marginal fee, the marginal fee of adding the change output, and the
	// FIXED non-input fee of a changeless tx (overhead + the single recipient
	// output). The fixed fee is what the effective-value bookkeeping does NOT
	// capture (effVal subtracts only the per-input fee), so the BnB target in
	// effective-value space is Target + fixedFee.
	inputFee := FeeFor(p2wpkhInputVBytes, feeRate)
	costOfChange := FeeFor(p2wpkhOutputVBytes, feeRate)
	// The FIXED non-input fee of a changeless tx: overhead + the single recipient
	// output at its REAL size (not assumed P2WPKH).
	fixedFee := FeeFor(EstimateVSizeOut(0, recipVB, 0), feeRate)

	// Effective value = value - the fee to include the input. Filter uneconomic
	// inputs (effVal <= 0): selecting one would REDUCE the spendable total.
	type ec struct {
		coin   Coin
		effVal int64
	}
	kept := make([]ec, 0, len(coins))
	var totalAvail, totalEff int64
	for _, c := range coins {
		if c.ValueSat <= 0 {
			continue
		}
		ev := c.ValueSat - inputFee
		if ev <= 0 {
			continue // uneconomic at this feerate
		}
		kept = append(kept, ec{coin: c, effVal: ev})
		totalAvail += c.ValueSat
		totalEff += ev
	}

	// Fast insufficiency gate (effective-value space): a changeless tx needs
	// Σeff >= Target + fixedFee (the fixed fee is the overhead + recipient output,
	// which the per-input effVal does not capture). If even the sum of every kept
	// coin's effective value cannot reach that, no subset can.
	if totalEff < p.Target+fixedFee {
		needed := p.Target + FeeFor(EstimateVSizeOut(1, recipVB, 0), feeRate)
		return Result{}, domain.WithData(
			domain.Newf(domain.CodeFundsInsufficient,
				"insufficient funds: need ~%d sat (amount %d + fee) but only %d sat is economically spendable",
				needed, p.Target, totalAvail),
			map[string]any{
				"available_sat": totalAvail,
				"needed_sat":    needed,
				"target_sat":    p.Target,
			})
	}

	// Deterministic order: effective value DESC, tie-break Outpoint ASC. Both the
	// BnB exploration and the knapsack fallback consume this order, so the same
	// (utxo set, target, feerate) always selects the same coins.
	sort.SliceStable(kept, func(i, j int) bool {
		if kept[i].effVal != kept[j].effVal {
			return kept[i].effVal > kept[j].effVal
		}
		return kept[i].coin.Outpoint < kept[j].coin.Outpoint
	})

	effVals := make([]int64, len(kept))
	coinsByIdx := make([]Coin, len(kept))
	for i := range kept {
		effVals[i] = kept[i].effVal
		coinsByIdx[i] = kept[i].coin
	}

	// ── Branch-and-bound: find a changeless subset whose Σeff lands in the
	// HALF-OPEN window [Target + fixedFee, Target + fixedFee + costOfChange + dust).
	// Σeff at the lower bound means Σval == Target + (the exact no-change fee); a
	// surplus strictly below costOfChange + dust is cheaper to burn into the fee
	// than to pay for a change output, so we make a changeless tx. AT exactly
	// costOfChange + dust a non-dust (294-sat) change output becomes economical, so
	// the window is exclusive at the top (upperBound is the last INCLUSIVE value).
	bnbTarget := p.Target + fixedFee
	upperBound := bnbTarget + costOfChange + DustThresholdP2WPKH - 1
	if sel, ok := bnb(effVals, bnbTarget, upperBound); ok {
		picked := make([]Coin, 0, len(sel))
		var sumVal int64
		for _, i := range sel {
			picked = append(picked, coinsByIdx[i])
			sumVal += coinsByIdx[i].ValueSat
		}
		// Changeless: the entire surplus over Target is the fee. By window
		// construction the surplus over the exact no-change fee is < costOfChange +
		// dust, so the overpay is bounded (asserted in tests). actualFee is at least
		// the no-change fee because Σeff >= bnbTarget == Target + fixedFee.
		actualFee := sumVal - p.Target
		return Result{
			Inputs:    sortInputs(picked),
			ChangeSat: 0,
			FeeSat:    actualFee,
			VSizeVB:   EstimateVSizeOut(len(picked), recipVB, 0),
			HasChange: false,
		}, nil
	}

	// ── Knapsack / largest-first fallback: accumulate coins (already sorted by
	// effVal desc) until Σval covers Target + fee(with change) + dust, producing a
	// WITH-CHANGE tx. The per-iteration `needed` is recomputed from the CURRENT
	// input count, so the "add an input → bigger fee → maybe need another" case is
	// the loop re-evaluating `needed`; it converges in ≤ len(coins) iterations
	// because each added coin contributes effVal>0 while the fee grows by a fixed
	// inputFee.
	picked := make([]Coin, 0, len(coinsByIdx))
	var sumVal int64
	for _, c := range coinsByIdx {
		picked = append(picked, c)
		sumVal += c.ValueSat
		nin := len(picked)
		// With-change vsize: recipient output at its real size + one P2WPKH change.
		vsizeWithChange := EstimateVSizeOut(nin, recipVB, 1)
		feeWithChange := FeeFor(vsizeWithChange, feeRate)
		needed := p.Target + feeWithChange + DustThresholdP2WPKH
		if sumVal >= needed {
			change := sumVal - p.Target - feeWithChange
			// change >= dust by construction.
			return Result{
				Inputs:    sortInputs(picked),
				ChangeSat: change,
				FeeSat:    feeWithChange,
				VSizeVB:   vsizeWithChange,
				HasChange: true,
			}, nil
		}
	}

	// Ran out of coins without room for a non-dust change. We may still afford a
	// CHANGELESS spend (enough for the recipient + the no-change fee, with the
	// sub-dust surplus burned to fee).
	nin := len(picked)
	vsizeNoChange := EstimateVSizeOut(nin, recipVB, 0)
	feeNoChange := FeeFor(vsizeNoChange, feeRate)
	if sumVal >= p.Target+feeNoChange {
		actualFee := sumVal - p.Target
		return Result{
			Inputs:    sortInputs(picked),
			ChangeSat: 0,
			FeeSat:    actualFee,
			VSizeVB:   vsizeNoChange,
			HasChange: false,
		}, nil
	}

	// Genuinely insufficient once the with-change/no-change fees are paid.
	needed := p.Target + feeNoChange
	return Result{}, domain.WithData(
		domain.Newf(domain.CodeFundsInsufficient,
			"insufficient funds: need %d sat (amount %d + fee %d) but only %d sat is available",
			needed, p.Target, feeNoChange, sumVal),
		map[string]any{
			"available_sat": sumVal,
			"needed_sat":    needed,
			"target_sat":    p.Target,
		})
}

// bnb runs a depth-first branch-and-bound over effVals (sorted DESC) searching for
// a subset whose sum lands in [target, upperBound]. It prefers the subset with the
// FEWEST inputs, then the SMALLEST sum (least waste). It returns the selected
// indices and whether a window subset was found. The iteration count is bounded by
// maxBnBIterations; on the cap it returns ok=false so the caller falls through to
// the knapsack fallback.
func bnb(effVals []int64, target, upperBound int64) ([]int, bool) {
	n := len(effVals)
	// suffix[i] = sum of effVals[i:].
	suffix := make([]int64, n+1)
	for i := n - 1; i >= 0; i-- {
		suffix[i] = suffix[i+1] + effVals[i]
	}

	var (
		bestSel   []int
		bestCount = int(^uint(0) >> 1) // max int
		bestSum   int64
		haveBest  bool
		cur       []int
		iters     int
	)

	var dfs func(depth int, sum int64)
	dfs = func(depth int, sum int64) {
		if iters >= maxBnBIterations {
			return
		}
		iters++

		if sum > upperBound {
			return // overshoot beyond the change-creation cost; prune
		}
		if sum >= target {
			// In-window subset. Prefer fewer inputs, then smaller sum.
			if !haveBest || len(cur) < bestCount || (len(cur) == bestCount && sum < bestSum) {
				bestSel = append(bestSel[:0], cur...)
				bestCount = len(cur)
				bestSum = sum
				haveBest = true
			}
			return // any superset only adds value → moves away from the window
		}
		if depth >= n {
			return
		}
		if sum+suffix[depth] < target {
			return // even taking everything left cannot reach target; prune
		}

		// Include coins[depth] first (the DESC order makes this the greedy branch).
		cur = append(cur, depth)
		dfs(depth+1, sum+effVals[depth])
		cur = cur[:len(cur)-1]

		// Exclude coins[depth].
		dfs(depth+1, sum)
	}
	dfs(0, 0)

	if !haveBest {
		return nil, false
	}
	out := make([]int, len(bestSel))
	copy(out, bestSel)
	return out, true
}

// sortInputs returns the selected coins in a deterministic order (Outpoint ASC)
// independent of the selection path, so two equivalent selections produce an
// identical Result.Inputs (testable, reproducible). The actual tx-build area may
// re-sort to BIP-69; this only fixes the Result's ordering.
func sortInputs(in []Coin) []Coin {
	out := make([]Coin, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Outpoint < out[j].Outpoint })
	return out
}
