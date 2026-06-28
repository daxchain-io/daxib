package keys

import (
	"context"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"

	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/secret"
)

// pubkey_test.go proves PubKeyAt's compressed pubkey hashes to the SAME P2WPKH
// address ScanAddresses/AddressAt derive (so the PSBT BIP-32 hint + the ownership
// label are consistent with the wallet's actual scripts), and that it is
// passphrase-free + stable.
func TestPubKeyAtMatchesDerivedAddress(t *testing.T) {
	s := openLight(t)
	ctx := context.Background()
	if _, err := s.ImportWallet(ctx, "vec", domain.NetworkMainnet, false,
		secret.NewString(canonicalMnemonic), nil, pass("pw"), pass("pw")); err != nil {
		t.Fatalf("ImportWallet: %v", err)
	}

	for _, tc := range []struct {
		branch domain.Branch
		index  uint32
	}{
		{domain.BranchReceive, 0},
		{domain.BranchReceive, 3},
		{domain.BranchChange, 0},
		{domain.BranchChange, 7},
	} {
		// PubKeyAt is passphrase-free.
		pk, err := s.PubKeyAt(ctx, "vec", domain.NetworkMainnet, tc.branch, tc.index)
		if err != nil {
			t.Fatalf("PubKeyAt(%d,%d): %v", tc.branch, tc.index, err)
		}
		if len(pk.PubKey) != 33 {
			t.Fatalf("pubkey length = %d, want 33 (compressed)", len(pk.PubKey))
		}
		// hash160(pubkey) -> P2WPKH address.
		h160 := btcutil.Hash160(pk.PubKey)
		wa, err := btcutil.NewAddressWitnessPubKeyHash(h160, &chaincfg.MainNetParams)
		if err != nil {
			t.Fatalf("address from pubkey: %v", err)
		}
		// The authoritative address ScanAddresses derives.
		want, err := s.AddressAt(ctx, "vec", domain.NetworkMainnet, tc.branch, tc.index)
		if err != nil {
			t.Fatalf("AddressAt: %v", err)
		}
		if wa.EncodeAddress() != want.Address {
			t.Fatalf("branch %d index %d: PubKeyAt-derived address %q != AddressAt %q",
				tc.branch, tc.index, wa.EncodeAddress(), want.Address)
		}
		// The path is the BIP-84 leaf path.
		if pk.Path != fullPath(domain.NetworkMainnet, tc.branch, tc.index) {
			t.Fatalf("path = %q, want %q", pk.Path, fullPath(domain.NetworkMainnet, tc.branch, tc.index))
		}
		if len(pk.PathIndices) != 5 {
			t.Fatalf("path indices length = %d, want 5", len(pk.PathIndices))
		}
		// Fingerprint is stable across calls.
		pk2, _ := s.PubKeyAt(ctx, "vec", domain.NetworkMainnet, tc.branch, tc.index)
		if pk.Fingerprint != pk2.Fingerprint {
			t.Fatalf("fingerprint not stable: %d != %d", pk.Fingerprint, pk2.Fingerprint)
		}
	}
}
