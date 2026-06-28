package service

import (
	"context"
	"testing"

	fakebackend "github.com/daxchain-io/daxib/internal/backend/fake"
	"github.com/daxchain-io/daxib/internal/domain"
)

// TestConvertSatBTC is the convert correctness proof: BTC↔sat round-trips, the
// bare-number BTC convention, explicit + default target units, and the bad-unit
// usage error — all float-free through domain.ParseAmountToSats + SatsToBTC.
func TestConvertSatBTC(t *testing.T) {
	svc, done := newSendService(t, fakebackend.New())
	defer done()
	ctx := context.Background()

	cases := []struct {
		name       string
		amount, to string
		wantValue  string
		wantSat    string
		wantBTC    string
		wantFrom   string
		wantToUnit string
	}{
		{"btc->sat default", "0.001btc", "", "100000", "100000", "0.00100000", "btc", "sat"},
		{"sat->btc default", "100000sat", "", "0.00100000", "100000", "0.00100000", "sat", "btc"},
		{"bare number is btc", "0.5", "", "50000000", "50000000", "0.50000000", "btc", "sat"},
		{"one btc to sat", "1btc", "sat", "100000000", "100000000", "1.00000000", "btc", "sat"},
		{"sats suffix to btc", "150000sats", "btc", "0.00150000", "150000", "0.00150000", "sat", "btc"},
		{"sat to sat is identity", "42sat", "sat", "42", "42", "0.00000042", "sat", "sat"},
		{"btc to btc is identity", "0.001btc", "btc", "0.00100000", "100000", "0.00100000", "btc", "btc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := svc.Convert(ctx, domain.LocalCLI(), domain.ConvertRequest{Amount: tc.amount, To: tc.to})
			if err != nil {
				t.Fatalf("Convert(%q,%q): %v", tc.amount, tc.to, err)
			}
			if res.Value != tc.wantValue {
				t.Errorf("Value=%q; want %q", res.Value, tc.wantValue)
			}
			if res.Sat != tc.wantSat {
				t.Errorf("Sat=%q; want %q", res.Sat, tc.wantSat)
			}
			if res.BTC != tc.wantBTC {
				t.Errorf("BTC=%q; want %q", res.BTC, tc.wantBTC)
			}
			if res.From != tc.wantFrom || res.To != tc.wantToUnit {
				t.Errorf("from/to=%q/%q; want %q/%q", res.From, res.To, tc.wantFrom, tc.wantToUnit)
			}
		})
	}

	// A bad target unit is a usage error (exit 2).
	if _, err := svc.Convert(ctx, domain.LocalCLI(), domain.ConvertRequest{Amount: "1btc", To: "gwei"}); err == nil {
		t.Fatal("Convert bad unit: want error, got nil")
	} else if de := domain.AsError(err); de.Exit != domain.ExitUsage {
		t.Errorf("bad-unit exit=%d; want %d (usage)", de.Exit, domain.ExitUsage)
	}

	// A malformed amount surfaces the parser's usage.bad_amount (exit 2).
	if _, err := svc.Convert(ctx, domain.LocalCLI(), domain.ConvertRequest{Amount: "not-a-number"}); err == nil {
		t.Fatal("Convert bad amount: want error, got nil")
	} else if de := domain.AsError(err); de.Exit != domain.ExitUsage {
		t.Errorf("bad-amount exit=%d; want %d (usage)", de.Exit, domain.ExitUsage)
	}
}
