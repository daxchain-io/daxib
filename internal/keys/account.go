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

// walletChain resolves the derivation chain for (wallet, net): the active
// network's coin_type family. For an agnostic wallet both chains exist; for a
// bound wallet the service's network guard guarantees net == the bound network
// before any derivation, so its single chain is always present. A missing chain
// is wallet.not_found (the caller addressed a coin_type the wallet does not hold
// — an off-network bound wallet that slipped past the guard); the guard, not this
// path, is what surfaces the usage.network_mismatch.
func (m *metaFile) walletChain(walletName string, net domain.Network) (string, *metaWallet, *metaChain, error) {
	id, w, ok := m.findWalletByName(walletName)
	if !ok {
		return "", nil, nil, errKeysf(CodeWalletNotFound, "no wallet named %q", walletName)
	}
	c, ok := w.chain(net)
	if !ok {
		return "", nil, nil, errKeysf(CodeWalletNotFound,
			"wallet %q has no derivation chain for network %q (coin_type %d)", walletName, net, net.CoinType())
	}
	return id, w, c, nil
}

// DeriveNext allocates the next unused index on the requested branch (receive or
// change), derives the address for the ACTIVE network from the active coin_type
// chain's neutered xpub (NO passphrase needed, §3.5), records it (in the chain's
// canonical HRP) in meta, advances the chain's watermark (HRP-agnostic), and
// returns the address encoded for net. Runs under the exclusive lock.
func (s *Store) DeriveNext(ctx context.Context, walletName string, net domain.Network, branch domain.Branch) (DerivedAddress, error) {
	var out DerivedAddress
	werr := s.withLock(ctx, func() error {
		meta, err := s.loadMeta()
		if err != nil {
			return err
		}
		_, _, chain, cerr := meta.walletChain(walletName, net)
		if cerr != nil {
			return cerr
		}

		var index uint32
		if branch == domain.BranchChange {
			index = chain.NextChange
		} else {
			index = chain.NextReceive
		}

		// The address returned to the caller is encoded for the ACTIVE network.
		addr, err := addressFromAccountXpub(chain.AccountXpub, net, branch, index)
		if err != nil {
			return err
		}
		// The cached string is recorded in the chain's CANONICAL HRP so list/scan can
		// re-encode it for any active network deterministically.
		cached, err := addressFromAccountXpub(chain.AccountXpub, canonicalNet(net), branch, index)
		if err != nil {
			return err
		}

		now := s.now()
		if chain.Addresses == nil {
			chain.Addresses = map[string]*metaAddress{}
		}
		chain.Addresses[domain.AddressKey(branch, index)] = &metaAddress{Address: cached, CreatedAt: now}
		if branch == domain.BranchChange {
			chain.NextChange = index + 1
		} else {
			chain.NextReceive = index + 1
		}
		if err := s.saveMeta(meta); err != nil {
			return err
		}

		out = DerivedAddress{
			Wallet:  walletName,
			Network: net,
			Branch:  branch,
			Index:   index,
			Address: addr,
			Path:    fullPath(net, branch, index),
		}
		return nil
	})
	if werr != nil {
		return DerivedAddress{}, werr
	}
	return out, nil
}

// PeekNext derives the address at the next unused index on the requested branch
// for the ACTIVE network WITHOUT recording it or advancing the watermark (a
// read-only preview, §3.5). Used by `tx send --dry-run`.
func (s *Store) PeekNext(ctx context.Context, walletName string, net domain.Network, branch domain.Branch) (DerivedAddress, error) {
	meta, err := s.loadMeta()
	if err != nil {
		return DerivedAddress{}, err
	}
	_, _, chain, cerr := meta.walletChain(walletName, net)
	if cerr != nil {
		return DerivedAddress{}, cerr
	}

	var index uint32
	if branch == domain.BranchChange {
		index = chain.NextChange
	} else {
		index = chain.NextReceive
	}
	addr, err := addressFromAccountXpub(chain.AccountXpub, net, branch, index)
	if err != nil {
		return DerivedAddress{}, err
	}
	return DerivedAddress{
		Wallet:  walletName,
		Network: net,
		Branch:  branch,
		Index:   index,
		Address: addr,
		Path:    fullPath(net, branch, index),
	}, nil
}

// ListAddresses returns every materialized address for a wallet, RE-ENCODED for
// the ACTIVE network from the active coin_type chain (so an agnostic wallet shows
// tb1 on testnet/signet, bcrt1 on regtest, from the SAME ct1 watermark), sorted by
// (branch, index). Lock-free read; no passphrase. It never echoes the cached
// canonical-HRP string verbatim for a different active HRP.
func (s *Store) ListAddresses(ctx context.Context, walletName string, net domain.Network) (domain.Network, []AddressInfo, error) {
	meta, err := s.loadMeta()
	if err != nil {
		return "", nil, err
	}
	_, _, chain, cerr := meta.walletChain(walletName, net)
	if cerr != nil {
		return "", nil, cerr
	}
	out := make([]AddressInfo, 0, len(chain.Addresses))
	for key, a := range chain.Addresses {
		branch, idx, ok := parseAddressKey(key)
		if !ok {
			return "", nil, errKeysf(CodeStateCorrupt, "wallet %q has a malformed address key %q", walletName, key)
		}
		addr, derr := addressFromAccountXpub(chain.AccountXpub, net, branch, idx)
		if derr != nil {
			return "", nil, derr
		}
		out = append(out, AddressInfo{Branch: branch, Index: idx, Address: addr, CreatedAt: a.CreatedAt})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Branch != out[j].Branch {
			return out[i].Branch < out[j].Branch
		}
		return out[i].Index < out[j].Index
	})
	return net, out, nil
}

// ScanAddress is one address in a wallet's gap-window scan set, returned by
// ScanAddresses for the balance/utxo backend query.
type ScanAddress struct {
	Branch  domain.Branch
	Index   uint32
	Address string
}

// ScanAddresses derives the set of addresses to query for a balance/utxo scan on
// the ACTIVE network: on each branch, indices [0, next_<branch> + gap) derived from
// the active coin_type chain's neutered xpub (NO passphrase, §3.5), encoded for
// net. A gap < 1 is clamped to 1.
func (s *Store) ScanAddresses(ctx context.Context, walletName string, net domain.Network, gap uint32) (domain.Network, []ScanAddress, error) {
	if gap < 1 {
		gap = 1
	}
	meta, err := s.loadMeta()
	if err != nil {
		return "", nil, err
	}
	_, _, chain, cerr := meta.walletChain(walletName, net)
	if cerr != nil {
		return "", nil, cerr
	}

	out := make([]ScanAddress, 0, chain.NextReceive+chain.NextChange+2*gap)
	for _, b := range []struct {
		branch domain.Branch
		count  uint32
	}{
		{domain.BranchReceive, chain.NextReceive + gap},
		{domain.BranchChange, chain.NextChange + gap},
	} {
		for i := uint32(0); i < b.count; i++ {
			addr, derr := addressFromAccountXpub(chain.AccountXpub, net, b.branch, i)
			if derr != nil {
				return "", nil, derr
			}
			out = append(out, ScanAddress{Branch: b.branch, Index: i, Address: addr})
		}
	}
	return net, out, nil
}

// AddressAt derives (read-only, no passphrase) the P2WPKH address at
// (wallet, branch, index) for the ACTIVE network from the active coin_type chain's
// neutered xpub. It does NOT materialize the address or advance any watermark — it
// is a pure lookup used to resolve a "<wallet>/<branch>/<index>" ref (e.g. for
// message signing). An unknown wallet is wallet.not_found.
func (s *Store) AddressAt(ctx context.Context, walletName string, net domain.Network, branch domain.Branch, index uint32) (DerivedAddress, error) {
	meta, err := s.loadMeta()
	if err != nil {
		return DerivedAddress{}, err
	}
	_, _, chain, cerr := meta.walletChain(walletName, net)
	if cerr != nil {
		return DerivedAddress{}, cerr
	}
	addr, err := addressFromAccountXpub(chain.AccountXpub, net, branch, index)
	if err != nil {
		return DerivedAddress{}, err
	}
	return DerivedAddress{
		Wallet:  walletName,
		Network: net,
		Branch:  branch,
		Index:   index,
		Address: addr,
		Path:    fullPath(net, branch, index),
	}, nil
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

// canonicalNet maps a network to the representative network whose HRP is the
// chain's CANONICAL cached form: mainnet for ct0, testnet (tb) for ct1.
func canonicalNet(n domain.Network) domain.Network {
	if n.CoinType() == 0 {
		return domain.NetworkMainnet
	}
	return domain.NetworkTestnet
}
