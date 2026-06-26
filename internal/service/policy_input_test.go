package service

import "testing"

// TestNormSatLimit pins the write-time canonicalization of "in sats" policy limits.
// Regression for the fail-OPEN bug where `policy set --max-tx 100000sat` stored the
// raw "100000sat", which then parsed to "no limit" at eval and silently disabled the
// guardrail. A valid value (with or without a sat suffix) canonicalizes to a bare
// integer; a malformed/BTC-style value is a usage error rather than silently stored.
func TestNormSatLimit(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "", false},
		{"none", "none", false},
		{"null", "null", false},
		{"100000", "100000", false},
		{"100000sat", "100000", false},
		{"100000sats", "100000", false},
		{"0", "0", false},
		{"0.001btc", "", true}, // BTC form rejected — the flag is "in sats"
		{"0.001", "", true},    // fractional sats are not a thing
		{"garbage", "", true},
		{"-5", "", true},
		{"sat", "", true},           // suffix with no number
		{"100000satoshi", "", true}, // not a recognized suffix
	}
	for _, c := range cases {
		got, err := normSatLimit("--max-tx", c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("normSatLimit(%q): want error, got %q", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("normSatLimit(%q): unexpected error %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("normSatLimit(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestNormalizeLimitsCanonicalizesAll confirms all three limit fields are normalized
// and a bad one aborts with a usage error (so it never reaches the sealed body).
func TestNormalizeLimitsCanonicalizes(t *testing.T) {
	in := PolicySetInput{MaxTxSat: "100000sat", MaxDaySat: "500000", MaxFeeRate: "50sat"}
	out, err := in.normalizeLimits()
	if err != nil {
		t.Fatalf("normalizeLimits: unexpected error %v", err)
	}
	if out.MaxTxSat != "100000" || out.MaxDaySat != "500000" || out.MaxFeeRate != "50" {
		t.Fatalf("normalizeLimits = {%q,%q,%q}, want {100000,500000,50}", out.MaxTxSat, out.MaxDaySat, out.MaxFeeRate)
	}
	if _, err := (PolicySetInput{MaxTxSat: "0.5btc"}).normalizeLimits(); err == nil {
		t.Fatal("a BTC-form max-tx must be a usage error")
	}
}
