package domain

import (
	"errors"
	"testing"
)

func TestParseAmountToSats(t *testing.T) {
	cases := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"0.001", 100_000, false},
		{"0.001btc", 100_000, false},
		{"0.001BTC", 100_000, false},
		{"1", 100_000_000, false},
		{"1btc", 100_000_000, false},
		{"21000000", 2_100_000_000_000_000, false}, // exactly the money cap
		{"0.00000001", 1, false},                   // one sat in BTC
		{"150000sat", 150_000, false},
		{"150000sats", 150_000, false},
		{"150000SAT", 150_000, false},
		{"  150000sat  ", 150_000, false},
		{"+0.5", 50_000_000, false},
		{".5", 50_000_000, false},
		{"0", 0, false},
		{"0sat", 0, false},
		// errors
		{"", 0, true},
		{"-1", 0, true},
		{"-0.5", 0, true},
		{"abc", 0, true},
		{"0.001.2", 0, true},
		{"21000000.000000001", 0, true}, // over cap (and sub-satoshi)
		{"21000001", 0, true},           // over the money cap
		{"100.5sat", 0, true},           // sats must be whole
		{"0.000000001", 0, true},        // sub-satoshi precision
		{"sat", 0, true},                // no number before suffix
		{"btc", 0, true},
	}
	for _, c := range cases {
		got, err := ParseAmountToSats(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseAmountToSats(%q) = %d, want error", c.in, got)
				continue
			}
			var de *Error
			if !errors.As(err, &de) || de.Code != CodeUsageBadAmount {
				t.Errorf("ParseAmountToSats(%q) err code = %v, want %s", c.in, err, CodeUsageBadAmount)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseAmountToSats(%q) unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseAmountToSats(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestExitCodeRegistry_TxCodes(t *testing.T) {
	cases := []struct {
		code string
		want ExitCode
	}{
		{CodeUsageBadAmount, ExitUsage},
		{CodeUsageBadAddress, ExitUsage},
		{CodeUsageBadFeeRate, ExitUsage},
		{CodeUsageBadTimeout, ExitUsage},
		{CodeUsageDustOutput, ExitUsage},
		{CodeUsageConfirmRequired, ExitUsage},
		{CodeFundsInsufficient, ExitInsufficientFunds},
		{CodeCoinSelectionFailed, ExitInsufficientFunds},
		{"funds.insufficient_confirmed", ExitInsufficientFunds},
		{CodeTxBroadcastRejected, ExitNetwork},
		{"tx.rejected", ExitNetwork},
		{CodeTxFeeTooLow, ExitNetwork},
		{CodeTxInputSpent, ExitTxConflict},
		{CodeTxWaitTimeout, ExitTimeoutPending},
		{CodeStateLockTimeout, ExitState},
		{CodeStateCorrupt, ExitState},
		{CodeRefNotFound, ExitNotFound},
	}
	for _, c := range cases {
		if got := ExitOf(c.code); got != c.want {
			t.Errorf("ExitOf(%q) = %d, want %d", c.code, got, c.want)
		}
	}
}

func TestTxFeeTooLowRetryable(t *testing.T) {
	if !New(CodeTxFeeTooLow, "x").Retryable {
		t.Errorf("tx.fee_too_low should be retryable (the fee market moves)")
	}
	if New(CodeTxBroadcastRejected, "x").Retryable {
		t.Errorf("tx.broadcast_rejected should NOT be retryable (a permanent reject)")
	}
}
