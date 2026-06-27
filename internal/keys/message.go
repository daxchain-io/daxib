package keys

import (
	"context"

	bip39 "github.com/tyler-smith/go-bip39"

	"github.com/daxchain-io/daxib/internal/bip322"
	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/secret"
)

// message.go is the keystore's BIP-322 message-signing seam. Like sign.go (the tx
// signing path) it is one of the few places a wallet's private key is materialized
// from the unlocked seed — and the ONLY one for message signing. The pure BIP-322
// virtual-tx construction lives in internal/bip322; this file resolves the address
// to its derivation coordinates, derives the leaf key under the keystore
// passphrase, hands the key to bip322.Sign, and zeroes every secret.
//
// Verification is NOT here: it needs no key and no keystore, so the service calls
// bip322.Verify directly (passphrase-free).

// SignMessageResult is the outcome of SignMessage: the address signed for and the
// raw BIP-322 witness bytes (the service base64-encodes them).
type SignMessageResult struct {
	Wallet    string
	Address   string
	Network   domain.Network
	Branch    domain.Branch
	Index     uint32
	Signature []byte // serialized BIP-322 "simple" witness
}

// addressMatch is a resolved (wallet, branch, index) for an address.
type addressMatch struct {
	walletID   string
	walletName string
	network    domain.Network
	branch     domain.Branch
	index      uint32
}

// SignMessage signs message with the key behind address using BIP-322 "simple".
// address must be a materialized address of some wallet in this keystore (so the
// keystore can derive its key); an address not owned by any wallet is
// wallet.not_found (exit 10). The keystore passphrase is verified first; a wrong
// passphrase is keystore.bad_passphrase (exit 4). Every secret (seed, derived
// keys) is zeroed before return.
//
// walletHint, when non-empty, scopes the address lookup to that wallet (so an
// address materialized in two wallets is disambiguated); empty searches all
// wallets.
func (s *Store) SignMessage(ctx context.Context, walletHint, address string, message []byte, pass *secret.Bytes) (SignMessageResult, error) {
	if verr := s.VerifyPassphrase(pass); verr != nil {
		return SignMessageResult{}, verr
	}

	match, err := s.findAddress(walletHint, address)
	if err != nil {
		return SignMessageResult{}, err
	}

	wb, err := s.loadWalletBlob(match.walletID)
	if err != nil {
		return SignMessageResult{}, err
	}
	mnemonic, bip39pass, oerr := s.openMnemonic(wb, pass.Reveal())
	if oerr != nil {
		return SignMessageResult{}, oerr
	}
	defer zeroBytes(mnemonic)
	defer zeroBytes(bip39pass)

	seed := bip39.NewSeed(string(mnemonic), string(bip39pass))
	defer zeroBytes(seed)

	account, err := deriveAccountKey(seed, match.network)
	if err != nil {
		return SignMessageResult{}, err
	}
	defer account.Zero()

	priv, derr := deriveLeafPrivKey(account, match.branch, match.index)
	if derr != nil {
		return SignMessageResult{}, derr
	}
	defer priv.Zero()

	sig, serr := bip322.Sign(address, message, priv, match.network)
	if serr != nil {
		return SignMessageResult{}, errWrap(CodeStateCorrupt, "signing the BIP-322 message", serr)
	}

	return SignMessageResult{
		Wallet:    match.walletName,
		Address:   address,
		Network:   match.network,
		Branch:    match.branch,
		Index:     match.index,
		Signature: sig,
	}, nil
}

// findAddress resolves a bech32 address to the (wallet, branch, index) that derives
// it. It first checks the materialized meta.json addresses (the fast path), then
// — to cover an address that was derived for a balance scan but not yet recorded —
// re-derives a gap window per wallet and matches. walletHint scopes the search
// when non-empty. No match is wallet.not_found.
func (s *Store) findAddress(walletHint, address string) (addressMatch, error) {
	meta, err := s.loadMeta()
	if err != nil {
		return addressMatch{}, err
	}

	for id, w := range meta.Wallets {
		if walletHint != "" && w.Name != walletHint {
			continue
		}
		network := domain.Network(w.Network)
		// Fast path: a materialized address recorded in meta.
		for key, a := range w.Addresses {
			if a.Address != address {
				continue
			}
			branch, idx, ok := parseAddressKey(key)
			if !ok {
				return addressMatch{}, errKeysf(CodeStateCorrupt, "wallet %q has a malformed address key %q", w.Name, key)
			}
			return addressMatch{walletID: id, walletName: w.Name, network: network, branch: branch, index: idx}, nil
		}
	}

	// Slow path: re-derive a gap window per (matching) wallet and match. This finds
	// an address that the wallet can derive but has not materialized in meta.
	const scanGap = 100
	for id, w := range meta.Wallets {
		if walletHint != "" && w.Name != walletHint {
			continue
		}
		network := domain.Network(w.Network)
		for _, b := range []struct {
			branch domain.Branch
			count  uint32
		}{
			{domain.BranchReceive, w.NextReceive + scanGap},
			{domain.BranchChange, w.NextChange + scanGap},
		} {
			for i := uint32(0); i < b.count; i++ {
				derived, derr := addressFromAccountXpub(w.AccountXpub, network, b.branch, i)
				if derr != nil {
					return addressMatch{}, derr
				}
				if derived == address {
					return addressMatch{walletID: id, walletName: w.Name, network: network, branch: b.branch, index: i}, nil
				}
			}
		}
	}

	if walletHint != "" {
		return addressMatch{}, errKeysf(CodeWalletNotFound, "address %q is not derivable by wallet %q", address, walletHint)
	}
	return addressMatch{}, errKeysf(CodeWalletNotFound, "address %q is not owned by any wallet in this keystore", address)
}
