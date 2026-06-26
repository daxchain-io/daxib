package domain

import "testing"

// TestKeystoreExitCodes pins the M2 keystore/wallet/mnemonic codes to their
// documented exit numbers (the agent-branchable contract).
func TestKeystoreExitCodes(t *testing.T) {
	cases := map[string]ExitCode{
		"keystore.bad_passphrase":       ExitAuth,      // 4
		"keystore.passphrase_required":  ExitAuth,      // 4
		"keystore.confirm_required":     ExitUsage,     // 2
		"keystore.read_only":            ExitNotFound,  // 10
		"keystore.not_found":            ExitNotFound,  // 10
		"wallet.not_found":              ExitNotFound,  // 10
		"wallet.exists":                 ExitUsage,     // 2
		"mnemonic.invalid":              ExitUsage,     // 2
		"mnemonic.required":             ExitUsage,     // 2 (missing mnemonic input, no env channel)
		"keystore.derivation_watermark": ExitIntegrity, // 12
		"keystore.perms_insecure":       ExitIntegrity, // 12
		"usage.network_mismatch":        ExitUsage,     // 2 (via usage prefix)
		"usage.words":                   ExitUsage,     // 2
	}
	for code, want := range cases {
		if got := ExitOf(code); got != want {
			t.Errorf("ExitOf(%q) = %d, want %d", code, got, want)
		}
	}
}
