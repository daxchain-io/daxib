package policy

import "testing"

// TestEvaluateFailsClosedOnUnparseableLimit pins the defense-in-depth posture: a
// PRESENT but unparseable limit (a unit-suffixed/garbage value that slipped past
// write-time validation, or a tampered body) must FAIL CLOSED — the guardrail denies
// the spend rather than silently collapsing to "no limit". Regression for the
// fail-OPEN hole where parseSat/overrideSat returned nil (= no limit) on a bad value.
func TestEvaluateFailsClosedOnUnparseableLimit(t *testing.T) {
	// Default-block unparseable max_tx ⇒ deny (not "no limit").
	p := Policy{Rules: Rules{Default: Limits{MaxTxSat: satPtr("100000sat")}}}
	d := Evaluate(p, Check{Network: "regtest", Recipient: recipA, AmountSat: 1, FeeSat: 0}, nil, fixedClock()())
	if d.Allowed {
		t.Fatal("an unparseable default max_tx must FAIL CLOSED (deny), not be treated as no limit")
	}
	if d.Code != codeDeniedTxLimit {
		t.Fatalf("code = %s, want %s", d.Code, codeDeniedTxLimit)
	}

	// Per-network unparseable override ⇒ deny (a bad override must not silently
	// inherit/lift the cap either).
	p2 := Policy{Rules: Rules{
		Default:  Limits{MaxTxSat: satPtr("100000000")},
		Networks: []NetworkRule{{Network: "regtest", Limits: Limits{MaxTxSat: satPtr("garbage")}}},
	}}
	d2 := Evaluate(p2, Check{Network: "regtest", Recipient: recipA, AmountSat: 1, FeeSat: 0}, nil, fixedClock()())
	if d2.Allowed {
		t.Fatal("an unparseable per-network max_tx override must FAIL CLOSED")
	}
}
