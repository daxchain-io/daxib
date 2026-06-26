package coinselect_test

import (
	"testing"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"github.com/daxchain-io/daxib/internal/coinselect"
)

// txWeight is the test-only bridge to btcd's own transaction-weight math
// (blockchain.GetTransactionWeight). PRODUCTION code in this package must NEVER
// import blockchain (it drags the validation/chainstate tree in and threatens the
// offline CGO0+windows build); a _test.go may, so the inlined 68/31/11 constants
// are pinned to btcd's ground truth here and can never silently drift.
func txWeight(tx *wire.MsgTx) int64 {
	return blockchain.GetTransactionWeight(btcutil.NewTx(tx))
}

// TestEstimateVSizeMatchesActual is THE vsize-accuracy proof. For a matrix of
// (inputs, outputs) it builds + signs a real P2WPKH tx from the canonical vector
// wallet, runs the engine on every input (so the signatures are real, not
// padding), serializes it, computes the network's actual vsize via btcd's weight
// math, and asserts the estimate is a CONSERVATIVE match of the actual signed
// vsize. This pins the inlined constants and guarantees the fee is never an
// underpayment.
//
// The estimator models a WORST-CASE 72-byte low-S DER signature per input (the
// maximum a P2WPKH witness ever carries). A realized signature is 71 OR 72 bytes
// depending on whether r/s have a high bit, so a real tx is occasionally 1 byte
// shorter per input. The estimate therefore NEVER undershoots (the money-critical
// property — an underpayment risks non-relay) and overshoots by at most the
// signature-length-variance slack (~1 vB per 8 inputs). For the realistic 1–2
// input case it is exact-to-1-vB.
func TestEstimateVSizeMatchesActual(t *testing.T) {
	const inAmount = 1_000_000
	const outAmount = 100_000

	for _, nin := range []int{1, 2, 5, 20} {
		for _, nout := range []int{1, 2} {
			s := buildSignedP2WPKHTx(t, nin, nout, inAmount, outAmount)
			engineVerify(t, s) // signatures must be real and spendable

			actual := serializedVSize(s.tx)
			predicted := coinselect.EstimateVSize(nin, nout)

			// (1) NEVER undershoot — the load-bearing relay-safety assertion.
			if predicted < actual {
				t.Errorf("EstimateVSize(%d,%d)=%d UNDERSHOOTS actual signed vsize=%d — risks relay underpayment",
					nin, nout, predicted, actual)
			}
			// (2) Conservative bound: overshoot is at most the sig-length-variance
			// slack (1 vB per 8 inputs, +1 for the witness-marker rounding). A drift
			// beyond this means a constant is wrong.
			slack := int64((nin+7)/8) + 1
			if over := predicted - actual; over > slack {
				t.Errorf("EstimateVSize(%d,%d)=%d overshoots actual=%d by %d vB (> %d slack) — a vsize constant has drifted",
					nin, nout, predicted, actual, over, slack)
			}
			// (3) For the common 1–2 input send, the estimate is exact within 1 vB
			// (the design's "within 1 vB rounding" target).
			if nin <= 2 {
				if d := predicted - actual; d > 1 {
					t.Errorf("EstimateVSize(%d,%d)=%d not within 1 vB of actual=%d for the common case (diff %d)",
						nin, nout, predicted, actual, d)
				}
			}

			// The raw bytes must round-trip.
			if raw := rawBytes(t, s.tx); len(raw) == 0 {
				t.Errorf("empty serialized tx for (%d,%d)", nin, nout)
			}
		}
	}
}

// TestOutputVBytesMatchesActual pins coinselect.OutputVBytes (the recipient-aware
// output sizer) to btcd's real serialized TxOut size for every standard recipient
// scriptPubKey type. This is the proof that threading OutputVBytes into Select fixes
// the fee/vsize underpayment for non-P2WPKH recipients (the previous flat 31-vB
// model undershot P2TR/P2WSH by 12 vB, P2PKH by 3, P2SH by 1).
func TestOutputVBytesMatchesActual(t *testing.T) {
	for _, tc := range []struct {
		name   string
		script []byte
		want   int64
	}{
		{"p2wpkh", scriptP2WPKH(t), 31},
		{"p2sh", scriptP2SH(t), 32},
		{"p2pkh", scriptP2PKH(t), 34},
		{"p2wsh", scriptP2WSH(t), 43},
		{"p2tr", scriptP2TR(t), 43},
	} {
		actual := int64(wire.NewTxOut(0, tc.script).SerializeSize())
		got := coinselect.OutputVBytes(len(tc.script))
		if got != actual {
			t.Errorf("%s: OutputVBytes(%d)=%d but actual serialized TxOut size=%d", tc.name, len(tc.script), got, actual)
		}
		if got != tc.want {
			t.Errorf("%s: OutputVBytes=%d, want %d", tc.name, got, tc.want)
		}
	}
}

// TestEstimateVSizeMatchesActual_NonP2WPKHRecipient is the recipient-aware vsize
// proof: for a Taproot, P2WSH, P2PKH, and P2SH recipient (with a P2WPKH change
// output), it builds + signs a real tx, engine-verifies the input, and asserts the
// recipient-aware estimate (EstimateVSizeOut with the recipient's real output size)
// equals the actual signed vsize within 1 vB and NEVER undershoots. The old
// EstimateVSize(1,2) (flat 31-vB outputs) undershot these by up to 12 vB — that is
// the relay underpayment this fix closes.
func TestEstimateVSizeMatchesActual_NonP2WPKHRecipient(t *testing.T) {
	const inAmount = 1_000_000
	const outAmount = 100_000
	for _, tc := range []struct {
		name   string
		script []byte
	}{
		{"p2tr", scriptP2TR(t)},
		{"p2wsh", scriptP2WSH(t)},
		{"p2pkh", scriptP2PKH(t)},
		{"p2sh", scriptP2SH(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// 1 input + recipient(tc.script) + 1 P2WPKH change output.
			s := buildSignedP2WPKHTx(t, 1, 0, inAmount, outAmount) // 1-input scaffold
			// Replace its single output set: recipient (tc.script) + a P2WPKH change.
			s.tx.TxOut = s.tx.TxOut[:0]
			s.tx.AddTxOut(wire.NewTxOut(outAmount, tc.script))
			_, changeScript := vectorLeafKey(t, vectorAccountKey(t), 1, 0)
			s.tx.AddTxOut(wire.NewTxOut(50_000, changeScript))
			// Re-sign the input over the new outputs.
			resignInput0(t, &s)
			engineVerify(t, s)

			actual := serializedVSize(s.tx)
			recipVB := coinselect.OutputVBytes(len(tc.script))
			predicted := coinselect.EstimateVSizeOut(1, recipVB, 1) // 1 in, recipient, 1 P2WPKH change
			if predicted < actual {
				t.Errorf("EstimateVSizeOut UNDERSHOOTS: predicted=%d actual=%d (relay underpayment)", predicted, actual)
			}
			if d := predicted - actual; d > 1 {
				t.Errorf("EstimateVSizeOut=%d not within 1 vB of actual=%d (diff %d)", predicted, actual, d)
			}
			// The OLD flat-31 model would have undershot for the larger scripts.
			old := coinselect.EstimateVSize(1, 2)
			if recipVB > 31 && old >= actual {
				t.Errorf("expected the old flat-31 EstimateVSize(1,2)=%d to undershoot actual=%d for %s", old, actual, tc.name)
			}
		})
	}
}

// TestSelect_NonP2WPKHRecipientFeeNotUnderpaid proves the SELECTOR attaches a fee
// covering the recipient-aware vsize at a feerate near the relay floor — the exact
// "below relay min" stranding the old flat-31 model produced for a Taproot recipient.
func TestSelect_NonP2WPKHRecipientFeeNotUnderpaid(t *testing.T) {
	const rate = 1
	target := int64(100_000)
	p2trVB := coinselect.OutputVBytes(len(scriptP2TR(t))) // 43
	// One coin large enough to need NO change (changeless), so vsize is in+recipient.
	feeNoChange := coinselect.FeeFor(coinselect.EstimateVSizeOut(1, p2trVB, 0), rate)
	coinVal := target + feeNoChange
	r, err := coinselect.Select([]coinselect.Coin{coin("t", coinVal)},
		coinselect.Params{Target: target, FeeRateSatVB: rate, RecipientVBytes: p2trVB})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	// The effective feerate (fee/vsize) must be >= the requested rate (no underpay).
	if r.VSizeVB <= 0 || r.FeeSat < r.VSizeVB*rate {
		t.Errorf("fee=%d underpays the recipient-aware vsize %d at rate %d", r.FeeSat, r.VSizeVB, rate)
	}
	if r.VSizeVB != coinselect.EstimateVSizeOut(len(r.Inputs), p2trVB, 0) {
		t.Errorf("VSizeVB=%d not the recipient-aware estimate", r.VSizeVB)
	}
}

// scriptP2WPKH/P2SH/P2PKH/P2WSH/P2TR return canonical scriptPubKeys for the size
// pins above (deterministic 20/32-byte programs).
func scriptP2WPKH(t *testing.T) []byte {
	t.Helper()
	var h [20]byte
	a, err := btcutil.NewAddressWitnessPubKeyHash(h[:], &chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("p2wpkh: %v", err)
	}
	return mustScript(t, a)
}

func scriptP2SH(t *testing.T) []byte {
	t.Helper()
	var h [20]byte
	a, err := btcutil.NewAddressScriptHashFromHash(h[:], &chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("p2sh: %v", err)
	}
	return mustScript(t, a)
}

func scriptP2PKH(t *testing.T) []byte {
	t.Helper()
	var h [20]byte
	a, err := btcutil.NewAddressPubKeyHash(h[:], &chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("p2pkh: %v", err)
	}
	return mustScript(t, a)
}

func scriptP2WSH(t *testing.T) []byte {
	t.Helper()
	var h [32]byte
	a, err := btcutil.NewAddressWitnessScriptHash(h[:], &chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("p2wsh: %v", err)
	}
	return mustScript(t, a)
}

func scriptP2TR(t *testing.T) []byte {
	t.Helper()
	var h [32]byte
	a, err := btcutil.NewAddressTaproot(h[:], &chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("p2tr: %v", err)
	}
	return mustScript(t, a)
}

func mustScript(t *testing.T, a btcutil.Address) []byte {
	t.Helper()
	s, err := txscript.PayToAddrScript(a)
	if err != nil {
		t.Fatalf("PayToAddrScript: %v", err)
	}
	return s
}

// resignInput0 re-signs input 0 of a 1-input signedTx over its (possibly mutated)
// outputs, using the canonical receive-0 leaf key.
func resignInput0(t *testing.T, s *signedTx) {
	t.Helper()
	priv, _ := vectorLeafKey(t, vectorAccountKey(t), 0, 0)
	prevOuts := map[wire.OutPoint]*wire.TxOut{
		s.tx.TxIn[0].PreviousOutPoint: wire.NewTxOut(s.prevAmount[0], s.prevScript[0]),
	}
	fetcher := txscript.NewMultiPrevOutFetcher(prevOuts)
	sigHashes := txscript.NewTxSigHashes(s.tx, fetcher)
	subscript := p2wpkhSubscript(t, s.prevScript[0])
	w, err := txscript.WitnessSignature(s.tx, sigHashes, 0, s.prevAmount[0], subscript, txscript.SigHashAll, priv, true)
	if err != nil {
		t.Fatalf("resign: %v", err)
	}
	s.tx.TxIn[0].Witness = w
}

// TestFeeFor is the exact-multiply fee check (no float, no rounding surprises).
func TestFeeFor(t *testing.T) {
	cases := []struct{ vsize, rate, want int64 }{
		{110, 10, 1100},
		{141, 1, 141},
		{0, 50, 0},
		{200, 0, 0},
		{-5, 10, 0}, // defensive clamp
	}
	for _, c := range cases {
		if got := coinselect.FeeFor(c.vsize, c.rate); got != c.want {
			t.Errorf("FeeFor(%d,%d)=%d, want %d", c.vsize, c.rate, got, c.want)
		}
	}
}

// TestEstimateVSizeClosedForm sanity-checks the closed form against the constants.
func TestEstimateVSizeClosedForm(t *testing.T) {
	// 1-in/2-out (a typical send with change): 11 + 68 + 2*31 = 141 vB.
	if got := coinselect.EstimateVSize(1, 2); got != 141 {
		t.Errorf("EstimateVSize(1,2)=%d, want 141", got)
	}
	// 2-in/1-out: 11 + 2*68 + 31 = 178 vB.
	if got := coinselect.EstimateVSize(2, 1); got != 178 {
		t.Errorf("EstimateVSize(2,1)=%d, want 178", got)
	}
}
