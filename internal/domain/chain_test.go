package domain

import "testing"

// TestSatsToBTC proves the exact, float-free satoshi->BTC decimal rendering.
func TestSatsToBTC(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{0, "0.00000000"},
		{1, "0.00000001"},
		{150000, "0.00150000"},
		{100_000_000, "1.00000000"},
		{2_100_000_000, "21.00000000"},
		{-50_000_000, "-0.50000000"},
	}

	for _, tc := range cases {
		if got := SatsToBTC(tc.in); got != tc.want {
			t.Errorf("SatsToBTC(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestBackendExitCodes pins the backend code -> exit-code projections.
func TestBackendExitCodes(t *testing.T) {
	cases := map[string]ExitCode{
		CodeBackendUnreachable:   ExitNetwork,
		CodeBackendRPCError:      ExitNetwork,
		CodeBackendNotFound:      ExitNotFound,
		CodeBackendNotConfigured: ExitNotFound,
		CodeBackendExists:        ExitUsage,
		"secret.unresolved":      ExitAuth,
		"config.invalid":         ExitUsage,
	}
	for code, want := range cases {
		if got := ExitOf(code); got != want {
			t.Errorf("ExitOf(%q) = %d, want %d", code, got, want)
		}
	}
}
