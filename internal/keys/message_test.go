package keys

import (
	"context"
	"testing"

	"github.com/daxchain-io/daxib/internal/bip322"
	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/secret"
)

// message_test.go proves the keystore's BIP-322 signing seam: SignMessage unlocks
// the address's key under the passphrase, produces a witness, and bip322.Verify
// accepts it — and a wrong passphrase / unknown address fail closed.

// TestSignMessageRoundtrip imports the canonical wallet, signs a message for its
// receive-0 address, and verifies the signature passphrase-free.
func TestSignMessageRoundtrip(t *testing.T) {
	s := openLight(t)
	ctx := context.Background()
	res, err := s.ImportWallet(ctx, "vec", domain.NetworkMainnet,
		secret.NewString(canonicalMnemonic), nil, pass("pw"), pass("pw"))
	if err != nil {
		t.Fatalf("ImportWallet: %v", err)
	}
	addr := res.Receive0Address

	msg := []byte("daxib signs this")
	sm, err := s.SignMessage(ctx, "vec", addr, msg, pass("pw"))
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}
	if sm.Address != addr {
		t.Errorf("signed address = %q, want %q", sm.Address, addr)
	}
	ok, verr := bip322.Verify(addr, msg, sm.Signature, domain.NetworkMainnet)
	if verr != nil {
		t.Fatalf("bip322.Verify error: %v", verr)
	}
	if !ok {
		t.Fatal("bip322.Verify rejected a keystore-produced signature")
	}
	// A tampered message must not verify.
	if ok, _ := bip322.Verify(addr, []byte("tampered"), sm.Signature, domain.NetworkMainnet); ok {
		t.Error("a tampered message verified")
	}
}

// TestSignMessageWrongPassphrase proves a wrong passphrase fails closed (exit 4)
// before any signing.
func TestSignMessageWrongPassphrase(t *testing.T) {
	s := openLight(t)
	ctx := context.Background()
	res, err := s.ImportWallet(ctx, "vec", domain.NetworkMainnet,
		secret.NewString(canonicalMnemonic), nil, pass("pw"), pass("pw"))
	if err != nil {
		t.Fatalf("ImportWallet: %v", err)
	}
	_, serr := s.SignMessage(ctx, "vec", res.Receive0Address, []byte("m"), pass("WRONG"))
	if code := codeOf(t, serr); code != CodeKeystoreBadPassphrase {
		t.Fatalf("wrong-passphrase code=%s, want %s", code, CodeKeystoreBadPassphrase)
	}
}

// TestSignMessageUnknownAddress proves an address no wallet owns is wallet.not_found.
func TestSignMessageUnknownAddress(t *testing.T) {
	s := openLight(t)
	ctx := context.Background()
	if _, err := s.ImportWallet(ctx, "vec", domain.NetworkMainnet,
		secret.NewString(canonicalMnemonic), nil, pass("pw"), pass("pw")); err != nil {
		t.Fatalf("ImportWallet: %v", err)
	}
	const foreign = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080" // not derivable by this wallet
	_, serr := s.SignMessage(ctx, "", foreign, []byte("m"), pass("pw"))
	if code := codeOf(t, serr); code != CodeWalletNotFound {
		t.Fatalf("unknown-address code=%s, want %s", code, CodeWalletNotFound)
	}
}

// TestSignMessageGapWindowAddress proves SignMessage finds an address that the
// wallet can derive but has NOT materialized in meta (a gap-window address), via
// the slow re-derivation path.
func TestSignMessageGapWindowAddress(t *testing.T) {
	s := openLight(t)
	ctx := context.Background()
	if _, err := s.ImportWallet(ctx, "vec", domain.NetworkMainnet,
		secret.NewString(canonicalMnemonic), nil, pass("pw"), pass("pw")); err != nil {
		t.Fatalf("ImportWallet: %v", err)
	}
	// receive index 5 is NOT materialized (only 0/0 is at import), but the wallet
	// can derive it. AddressAt gives us the address; SignMessage must still find it.
	d, err := s.AddressAt(ctx, "vec", domain.BranchReceive, 5)
	if err != nil {
		t.Fatalf("AddressAt: %v", err)
	}
	sm, err := s.SignMessage(ctx, "vec", d.Address, []byte("gap window"), pass("pw"))
	if err != nil {
		t.Fatalf("SignMessage gap-window: %v", err)
	}
	if sm.Index != 5 || sm.Branch != domain.BranchReceive {
		t.Errorf("resolved (branch,index) = (%d,%d), want (0,5)", sm.Branch, sm.Index)
	}
	ok, _ := bip322.Verify(d.Address, []byte("gap window"), sm.Signature, domain.NetworkMainnet)
	if !ok {
		t.Fatal("gap-window signature did not verify")
	}
}
