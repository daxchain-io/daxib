package backend

import "testing"

// TestDecimalBTCToSats proves the exact, float-free BTC->sat conversion (the
// classic 0.1-is-not-representable cases included).
func TestDecimalBTCToSats(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"0.00150000", 150000},
		{"0", 0},
		{"21", 2_100_000_000},
		{"0.1", 10_000_000},
		{"0.00000001", 1},
		{"-0.5", -50_000_000},
		{"1.23456789", 123_456_789},
		{"0.00150000000", 150000}, // trailing-zero tolerance beyond 8 places
	}
	for _, tc := range cases {
		got, err := decimalBTCToSats(tc.in)
		if err != nil {
			t.Errorf("decimalBTCToSats(%q): unexpected error %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("decimalBTCToSats(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestDecimalBTCToSats_SubSatoshi rejects a real sub-satoshi (9-place) amount.
func TestDecimalBTCToSats_SubSatoshi(t *testing.T) {
	if _, err := decimalBTCToSats("0.000000001"); err == nil {
		t.Fatal("expected an error for a sub-satoshi amount")
	}
}
