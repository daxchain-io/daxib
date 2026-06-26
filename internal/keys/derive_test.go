package keys

import (
	"testing"

	bip39 "github.com/tyler-smith/go-bip39"

	"github.com/daxchain-io/daxib/internal/domain"
)

// canonicalMnemonic is the standard BIP-39 test vector (all-"abandon" + "about").
const canonicalMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// TestBIP84CanonicalVectors asserts daxib's BIP-84 derivation against the
// canonical mainnet vectors for the abandon-about mnemonic (the same vectors
// published in BIP-84 and reproduced by every reference wallet). These are the
// load-bearing correctness vectors for the whole derivation path.
func TestBIP84CanonicalVectors(t *testing.T) {
	seed := bip39.NewSeed(canonicalMnemonic, "")
	account, err := deriveAccountKey(seed, domain.NetworkMainnet)
	if err != nil {
		t.Fatalf("deriveAccountKey: %v", err)
	}
	xpub, err := neuterToXpub(account)
	if err != nil {
		t.Fatalf("neuterToXpub: %v", err)
	}
	account.Zero()

	cases := []struct {
		name   string
		branch domain.Branch
		index  uint32
		want   string
	}{
		{"m/84'/0'/0'/0/0", domain.BranchReceive, 0, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"},
		{"m/84'/0'/0'/0/1", domain.BranchReceive, 1, "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"},
		{"m/84'/0'/0'/1/0", domain.BranchChange, 0, "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := addressFromAccountXpub(xpub, domain.NetworkMainnet, tc.branch, tc.index)
			if err != nil {
				t.Fatalf("addressFromAccountXpub: %v", err)
			}
			if got != tc.want {
				t.Fatalf("%s: got %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}

// TestNetworkAddressVectors pins a full known-answer address per network (0/0 for
// the abandon-about mnemonic) so a chaincfg param swap (e.g. SigNet<->TestNet3) is
// caught — the prefix-only check below would not notice it because testnet and
// signet share the "tb" HRP and coin type 1.
func TestNetworkAddressVectors(t *testing.T) {
	seed := bip39.NewSeed(canonicalMnemonic, "")
	cases := []struct {
		net  domain.Network
		want string
	}{
		{domain.NetworkTestnet, "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl"},
		{domain.NetworkTestnet4, "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl"},
		{domain.NetworkSignet, "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl"},
		{domain.NetworkRegtest, "bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk"},
	}
	for _, tc := range cases {
		t.Run(string(tc.net), func(t *testing.T) {
			account, err := deriveAccountKey(seed, tc.net)
			if err != nil {
				t.Fatalf("deriveAccountKey: %v", err)
			}
			xpub, err := neuterToXpub(account)
			if err != nil {
				t.Fatalf("neuterToXpub: %v", err)
			}
			account.Zero()
			got, err := addressFromAccountXpub(xpub, tc.net, domain.BranchReceive, 0)
			if err != nil {
				t.Fatalf("addressFromAccountXpub: %v", err)
			}
			if got != tc.want {
				t.Fatalf("%s 0/0 = %q, want %q", tc.net, got, tc.want)
			}
		})
	}
}

// TestNetworkAddressPrefixes confirms each network derives an address with the
// expected human-readable bech32 prefix (sanity that the chaincfg mapping is
// wired correctly).
func TestNetworkAddressPrefixes(t *testing.T) {
	seed := bip39.NewSeed(canonicalMnemonic, "")
	cases := []struct {
		net    domain.Network
		prefix string
	}{
		{domain.NetworkMainnet, "bc1"},
		{domain.NetworkTestnet, "tb1"},
		{domain.NetworkTestnet4, "tb1"},
		{domain.NetworkSignet, "tb1"},
		{domain.NetworkRegtest, "bcrt1"},
	}
	for _, tc := range cases {
		t.Run(string(tc.net), func(t *testing.T) {
			account, err := deriveAccountKey(seed, tc.net)
			if err != nil {
				t.Fatalf("deriveAccountKey: %v", err)
			}
			xpub, err := neuterToXpub(account)
			if err != nil {
				t.Fatalf("neuterToXpub: %v", err)
			}
			account.Zero()
			addr, err := addressFromAccountXpub(xpub, tc.net, domain.BranchReceive, 0)
			if err != nil {
				t.Fatalf("addressFromAccountXpub: %v", err)
			}
			if len(addr) < len(tc.prefix) || addr[:len(tc.prefix)] != tc.prefix {
				t.Fatalf("network %s: address %q does not start with %q", tc.net, addr, tc.prefix)
			}
		})
	}
}
