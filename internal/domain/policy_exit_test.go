package domain

import "testing"

// policy_exit_test.go pins the ECC-2 contract: the fee-rate-cap denial
// (policy.denied.fee_rate) is the ONE policy.denied.* that projects to exit 7
// (FEE_POLICY_DENIED) and is retryable, while every OTHER policy.denied.* stays
// at exit 3 (POLICY_DENIED) and is NOT retryable. The dotted code is stable; only
// the exit/retryable projection differs.

// TestFeeRateCapDeniedMapsToExit7 asserts the fee-rate-cap denial revives exit 7
// (the dead lane before ECC-2) and is retryable (the fee market moves).
func TestFeeRateCapDeniedMapsToExit7(t *testing.T) {
	e := New("policy.denied.fee_rate", "fee rate exceeds the max-fee-rate cap")
	if e.Exit != ExitFeePolicyDenied {
		t.Errorf("policy.denied.fee_rate exit = %d, want %d (FEE_POLICY_DENIED)", e.Exit, ExitFeePolicyDenied)
	}
	if !e.Retryable {
		t.Error("policy.denied.fee_rate must be retryable=true (the fee market moves)")
	}
	if got := ExitOf("policy.denied.fee_rate"); got != ExitFeePolicyDenied {
		t.Errorf("ExitOf(policy.denied.fee_rate) = %d, want %d", got, ExitFeePolicyDenied)
	}
}

// TestOtherPolicyDenialsStayExit3 asserts the rest of the policy.denied.* family
// is unchanged by ECC-2: exit 3, and retryable only where it already was (the
// rolling-24h day limit ages out; the rest do not).
func TestOtherPolicyDenialsStayExit3(t *testing.T) {
	cases := []struct {
		code      string
		retryable bool
	}{
		{"policy.denied.tx_limit", false},
		{"policy.denied.not_allowlisted", false},
		{"policy.denied.denylisted", false},
		{"policy.denied.day_limit", true}, // rolling window ages out
		{"policy.denied", false},          // the bare family prefix
	}
	for _, c := range cases {
		e := New(c.code, "denied")
		if e.Exit != ExitPolicyDenied {
			t.Errorf("%s exit = %d, want %d (POLICY_DENIED)", c.code, e.Exit, ExitPolicyDenied)
		}
		if e.Retryable != c.retryable {
			t.Errorf("%s retryable = %v, want %v", c.code, e.Retryable, c.retryable)
		}
	}
}
