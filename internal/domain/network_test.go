package domain

import (
	"errors"
	"testing"
)

func TestParseNetwork(t *testing.T) {
	cases := []struct {
		in      string
		want    Network
		wantErr bool
	}{
		{"", NetworkMainnet, false},
		{"mainnet", NetworkMainnet, false},
		{"testnet", NetworkTestnet, false},
		{"testnet4", NetworkTestnet4, false},
		{"signet", NetworkSignet, false},
		{"regtest", NetworkRegtest, false},
		{"bogus", "", true},
		{"MAINNET", "", true}, // case-sensitive by design
	}
	for _, tc := range cases {
		got, err := ParseNetwork(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseNetwork(%q): expected error, got %q", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseNetwork(%q): unexpected error %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseNetwork(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCoinType(t *testing.T) {
	if NetworkMainnet.CoinType() != 0 {
		t.Errorf("mainnet coin type = %d, want 0", NetworkMainnet.CoinType())
	}
	for _, n := range []Network{NetworkTestnet, NetworkTestnet4, NetworkSignet, NetworkRegtest} {
		if n.CoinType() != 1 {
			t.Errorf("%s coin type = %d, want 1", n, n.CoinType())
		}
	}
}

func TestBadNetworkIsUsageExit(t *testing.T) {
	_, err := ParseNetwork("nope")
	if err == nil {
		t.Fatal("expected an error")
	}
	var de *Error
	if !errors.As(err, &de) {
		t.Fatalf("ParseNetwork error is not *Error: %v", err)
	}
	if de.Exit != ExitUsage {
		t.Errorf("bad-network exit = %d, want %d (usage)", de.Exit, ExitUsage)
	}
}
