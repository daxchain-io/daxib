package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/daxchain-io/daxib/internal/domain"
)

// TestAddressNewListCLI imports the canonical vector and asserts `address new`
// returns the 0/1 vector and `address list` is valid JSON, through the real CLI
// funnel (address ops need NO passphrase — derivation is from the stored xpub).
func TestAddressNewListCLI(t *testing.T) {
	isolateKeystore(t)
	importVec(t, "vec", "mainnet")

	out, stderr, code := execCLI(t, "address", "new", "--wallet", "vec", "--network", "mainnet")
	if code != 0 {
		t.Fatalf("address new exit = %d:\n%s", code, stderr)
	}
	if got := strings.TrimSpace(out); got != canonReceive1 {
		t.Fatalf("address new = %q, want %q", got, canonReceive1)
	}

	out, _, code = execCLI(t, "address", "list", "--wallet", "vec", "--network", "mainnet", "--json")
	if code != 0 {
		t.Fatalf("address list exit = %d:\n%s", code, out)
	}
	var res domain.AddressListResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("address list --json invalid: %v (%q)", err, out)
	}
	// receive 0/0 (materialized at import) + 0/1 (just allocated) = 2 addresses.
	if len(res.Addresses) != 2 {
		t.Fatalf("address list = %d entries, want 2: %+v", len(res.Addresses), res.Addresses)
	}
	if res.Addresses[0].Address != canonReceive0 || res.Addresses[1].Address != canonReceive1 {
		t.Errorf("address list = %q, %q; want canonical 0/0, 0/1",
			res.Addresses[0].Address, res.Addresses[1].Address)
	}
}

// TestAddressNewDefaultWalletCLI asserts `address new` with no --wallet resolves
// to the default wallet.
func TestAddressNewDefaultWalletCLI(t *testing.T) {
	isolateKeystore(t)
	importVec(t, "vec", "mainnet")
	out, stderr, code := execCLI(t, "address", "new", "--network", "mainnet")
	if code != 0 {
		t.Fatalf("address new (default wallet) exit = %d:\n%s", code, stderr)
	}
	if got := strings.TrimSpace(out); got != canonReceive1 {
		t.Fatalf("default-wallet address new = %q, want %q", got, canonReceive1)
	}
}

// TestAddressNewBoundNetworkMismatchCLI asserts an address op against a BOUND
// wallet locked to a different network than the active --network is refused with
// usage.network_mismatch (exit 2).
func TestAddressNewBoundNetworkMismatchCLI(t *testing.T) {
	isolateKeystore(t)
	importVecBound(t, "tnet", "testnet")
	// Active network mainnet, wallet bound to testnet -> mismatch.
	_, stderr, code := execCLI(t, "address", "new", "--wallet", "tnet", "--network", "mainnet", "--json")
	if code != int(domain.ExitUsage) {
		t.Fatalf("network-mismatch exit = %d, want 2 (USAGE)", code)
	}
	if !strings.Contains(stderr, "usage.network_mismatch") {
		t.Errorf("error envelope missing usage.network_mismatch: %q", stderr)
	}
}

// TestAddressNewAgnosticCrossNetworkCLI asserts an AGNOSTIC wallet derives on any
// active network: the same wallet yields a bc1 address on mainnet and a tb1
// address on testnet, both exit 0.
func TestAddressNewAgnosticCrossNetworkCLI(t *testing.T) {
	isolateKeystore(t)
	importVec(t, "any", "mainnet") // agnostic (no --bind)

	out, stderr, code := execCLI(t, "address", "new", "--wallet", "any", "--network", "mainnet")
	if code != 0 {
		t.Fatalf("address new mainnet exit = %d:\n%s", code, stderr)
	}
	if got := strings.TrimSpace(out); !strings.HasPrefix(got, "bc1") {
		t.Fatalf("mainnet address = %q, want bc1...", got)
	}

	out, stderr, code = execCLI(t, "address", "new", "--wallet", "any", "--network", "testnet")
	if code != 0 {
		t.Fatalf("address new testnet (agnostic) exit = %d:\n%s", code, stderr)
	}
	if got := strings.TrimSpace(out); !strings.HasPrefix(got, "tb1") {
		t.Fatalf("testnet address = %q, want tb1...", got)
	}
}

// TestAddressNewNoWalletExit10CLI asserts a fresh keystore (no wallet, no
// default) fails wallet.not_found (exit 10).
func TestAddressNewNoWalletExit10CLI(t *testing.T) {
	isolateKeystore(t)
	_, stderr, code := execCLI(t, "address", "new", "--network", "mainnet", "--json")
	if code != int(domain.ExitNotFound) {
		t.Fatalf("no-wallet address new exit = %d, want 10 (NOT_FOUND):\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "wallet.not_found") {
		t.Errorf("error envelope missing wallet.not_found: %q", stderr)
	}
}
