package keys

import (
	"context"
	"sort"

	"github.com/daxchain-io/daxib/internal/domain"
)

// DerivedAddress is a single derived address, returned by DeriveNext.
type DerivedAddress struct {
	Wallet  string
	Network domain.Network
	Branch  domain.Branch
	Index   uint32
	Address string
	Path    string
}

// AddressInfo is one row of ListAddresses.
type AddressInfo struct {
	Branch    domain.Branch
	Index     uint32
	Address   string
	CreatedAt string
}

// DeriveNext allocates the next unused index on the requested branch (receive or
// change), derives the address from the wallet's stored neutered xpub (NO
// passphrase needed, §3.5), records it in meta, advances the watermark, and
// returns it. Runs under the exclusive lock.
func (s *Store) DeriveNext(ctx context.Context, walletName string, branch domain.Branch) (DerivedAddress, error) {
	var out DerivedAddress
	werr := s.withLock(ctx, func() error {
		meta, err := s.loadMeta()
		if err != nil {
			return err
		}
		_, w, ok := meta.findWalletByName(walletName)
		if !ok {
			return errKeysf(CodeWalletNotFound, "no wallet named %q", walletName)
		}
		network := domain.Network(w.Network)

		var index uint32
		if branch == domain.BranchChange {
			index = w.NextChange
		} else {
			index = w.NextReceive
		}

		addr, err := addressFromAccountXpub(w.AccountXpub, network, branch, index)
		if err != nil {
			return err
		}

		now := s.now()
		if w.Addresses == nil {
			w.Addresses = map[string]*metaAddress{}
		}
		w.Addresses[domain.AddressKey(branch, index)] = &metaAddress{Address: addr, CreatedAt: now}
		if branch == domain.BranchChange {
			w.NextChange = index + 1
		} else {
			w.NextReceive = index + 1
		}
		if err := s.saveMeta(meta); err != nil {
			return err
		}

		out = DerivedAddress{
			Wallet:  walletName,
			Network: network,
			Branch:  branch,
			Index:   index,
			Address: addr,
			Path:    fullPath(network, branch, index),
		}
		return nil
	})
	if werr != nil {
		return DerivedAddress{}, werr
	}
	return out, nil
}

// ListAddresses returns every materialized address for a wallet, sorted by
// (branch, index). Lock-free read; no passphrase.
func (s *Store) ListAddresses(ctx context.Context, walletName string) (domain.Network, []AddressInfo, error) {
	meta, err := s.loadMeta()
	if err != nil {
		return "", nil, err
	}
	_, w, ok := meta.findWalletByName(walletName)
	if !ok {
		return "", nil, errKeysf(CodeWalletNotFound, "no wallet named %q", walletName)
	}
	network := domain.Network(w.Network)
	out := make([]AddressInfo, 0, len(w.Addresses))
	for key, a := range w.Addresses {
		branch, idx, ok := parseAddressKey(key)
		if !ok {
			return "", nil, errKeysf(CodeStateCorrupt, "wallet %q has a malformed address key %q", walletName, key)
		}
		out = append(out, AddressInfo{Branch: branch, Index: idx, Address: a.Address, CreatedAt: a.CreatedAt})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Branch != out[j].Branch {
			return out[i].Branch < out[j].Branch
		}
		return out[i].Index < out[j].Index
	})
	return network, out, nil
}

// ScanAddress is one address in a wallet's gap-window scan set, returned by
// ScanAddresses for the balance/utxo backend query.
type ScanAddress struct {
	Branch  domain.Branch
	Index   uint32
	Address string
}

// ScanAddresses derives the set of addresses to query for a balance/utxo scan: on
// each branch, indices [0, next_<branch> + gap) derived from the wallet's stored
// neutered xpub (NO passphrase, §3.5). This covers every already-handed-out
// address plus a forward gap window so a balance still finds coins on addresses
// the wallet generated but has not yet "used" via `address new`. It is a lock-free
// read. A gap < 1 is clamped to 1.
func (s *Store) ScanAddresses(ctx context.Context, walletName string, gap uint32) (domain.Network, []ScanAddress, error) {
	if gap < 1 {
		gap = 1
	}
	meta, err := s.loadMeta()
	if err != nil {
		return "", nil, err
	}
	_, w, ok := meta.findWalletByName(walletName)
	if !ok {
		return "", nil, errKeysf(CodeWalletNotFound, "no wallet named %q", walletName)
	}
	network := domain.Network(w.Network)

	out := make([]ScanAddress, 0, w.NextReceive+w.NextChange+2*gap)
	for _, b := range []struct {
		branch domain.Branch
		count  uint32
	}{
		{domain.BranchReceive, w.NextReceive + gap},
		{domain.BranchChange, w.NextChange + gap},
	} {
		for i := uint32(0); i < b.count; i++ {
			addr, derr := addressFromAccountXpub(w.AccountXpub, network, b.branch, i)
			if derr != nil {
				return "", nil, derr
			}
			out = append(out, ScanAddress{Branch: b.branch, Index: i, Address: addr})
		}
	}
	return network, out, nil
}

// DefaultWallet returns the keystore's default wallet name (meta default_wallet),
// or "" when none is set.
func (s *Store) DefaultWallet(ctx context.Context) (string, bool) {
	meta, err := s.loadMeta()
	if err != nil || meta.DefaultWallet == "" {
		return "", false
	}
	return meta.DefaultWallet, true
}
