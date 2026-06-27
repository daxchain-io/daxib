package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/daxchain-io/daxib/internal/domain"
)

// TestNetworkRequiredFiresWhenUnset proves a network-requiring command with NO
// network selected (flag/env/config all empty) fails with usage.network_required
// (exit 2) — AF-1: no silent default to mainnet.
func TestNetworkRequiredFiresWhenUnset(t *testing.T) {
	isolateKeystore(t)
	isolateConfig(t)
	t.Setenv("DAXIB_NETWORK", "") // override isolateKeystore's mainnet pin

	// import an agnostic wallet (no network needed for an agnostic create) so the
	// guard, not a missing-wallet error, is what fires.
	if _, stderr, code := execCLI(t, "wallet", "import", "agno", "--mnemonic-file", mnemonicFile(t)); code != 0 {
		t.Fatalf("agnostic import exit %d: %s", code, stderr)
	}

	for _, args := range [][]string{
		{"wallet", "list"},
		{"wallet", "show", "agno"},
		{"address", "new", "--wallet", "agno"},
		{"balance", "--wallet", "agno"},
		{"fee"},
	} {
		_, stderr, code := execCLI(t, args...)
		if code != 2 {
			t.Errorf("%v exit = %d, want 2:\n%s", args, code, stderr)
		}
		if !strings.Contains(stderr, "usage.network_required") {
			t.Errorf("%v expected usage.network_required:\n%s", args, stderr)
		}
	}
}

// TestNetworkNounRoundtrip exercises `network use`/`show`/`list` and proves a flag
// overrides a persisted default.
func TestNetworkNounRoundtrip(t *testing.T) {
	isolateKeystore(t)
	isolateConfig(t)
	t.Setenv("DAXIB_NETWORK", "")

	// list always returns the five networks.
	out, stderr, code := execCLI(t, "--json", "network", "list")
	if code != 0 {
		t.Fatalf("network list exit %d: %s", code, stderr)
	}
	var list domain.NetworkListResult
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		t.Fatalf("network list --json: %v\n%s", err, out)
	}
	if len(list.Networks) != 5 {
		t.Fatalf("network list len = %d, want 5", len(list.Networks))
	}

	// show with nothing selected reports unset.
	out, stderr, code = execCLI(t, "--json", "network", "show")
	if code != 0 {
		t.Fatalf("network show (unset) exit %d: %s", code, stderr)
	}
	var show domain.NetworkShowResult
	_ = json.Unmarshal([]byte(out), &show)
	if show.Resolved || show.Source != "unset" {
		t.Fatalf("show unset = %+v, want unresolved/unset", show)
	}

	// use persists signet.
	if _, stderr, code := execCLI(t, "network", "use", "signet"); code != 0 {
		t.Fatalf("network use signet exit %d: %s", code, stderr)
	}

	// show now reports signet from config.
	out, stderr, code = execCLI(t, "--json", "network", "show")
	if code != 0 {
		t.Fatalf("network show (config) exit %d: %s", code, stderr)
	}
	_ = json.Unmarshal([]byte(out), &show)
	if !show.Resolved || show.Network != "signet" || show.Source != "config" {
		t.Fatalf("show after use = %+v, want signet/config/resolved", show)
	}

	// A --network flag overrides the persisted default for one call.
	out, stderr, code = execCLI(t, "--network", "regtest", "--json", "network", "show")
	if code != 0 {
		t.Fatalf("network show (flag) exit %d: %s", code, stderr)
	}
	_ = json.Unmarshal([]byte(out), &show)
	if show.Network != "regtest" || show.Source != "flag" {
		t.Fatalf("show with --network = %+v, want regtest/flag", show)
	}

	// DAXIB_NETWORK env overrides config too.
	t.Setenv("DAXIB_NETWORK", "testnet")
	out, stderr, code = execCLI(t, "--json", "network", "show")
	if code != 0 {
		t.Fatalf("network show (env) exit %d: %s", code, stderr)
	}
	_ = json.Unmarshal([]byte(out), &show)
	if show.Network != "testnet" || show.Source != "env" {
		t.Fatalf("show with env = %+v, want testnet/env", show)
	}
}

// TestExplicitNetworkStillWorks proves an explicit --network resolves cleanly and a
// network-requiring op proceeds past the guard.
func TestExplicitNetworkStillWorks(t *testing.T) {
	isolateKeystore(t)
	isolateConfig(t)
	t.Setenv("DAXIB_NETWORK", "")

	if _, stderr, code := execCLI(t, "wallet", "import", "w", "--network", "mainnet", "--bind", "--mnemonic-file", mnemonicFile(t)); code != 0 {
		t.Fatalf("bind import --network mainnet exit %d: %s", code, stderr)
	}
	// address new with an explicit --network resolves and does NOT hit network_required.
	if _, stderr, code := execCLI(t, "--network", "mainnet", "address", "new", "--wallet", "w"); code != 0 {
		t.Fatalf("address new --network mainnet exit %d: %s", code, stderr)
	}
}
