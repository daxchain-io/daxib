package service

import (
	"context"

	"github.com/daxchain-io/daxib/internal/domain"
)

// AddressNew allocates the next receive (or change) index for a wallet, derives +
// records the address (no passphrase needed — derivation is from the stored
// neutered xpub), and returns it. The active --network must match the wallet's
// network (§3.5).
func (s *Service) AddressNew(ctx context.Context, req domain.AddressNewRequest) (domain.AddressNewResult, error) {
	wallet, err := s.resolveWallet(ctx, req.Wallet)
	if err != nil {
		return domain.AddressNewResult{}, err
	}
	if err := s.assertWalletNetwork(ctx, wallet); err != nil {
		return domain.AddressNewResult{}, err
	}

	branch := domain.BranchReceive
	if req.Change {
		branch = domain.BranchChange
	}
	d, err := s.keys.DeriveNext(ctx, wallet, s.net, branch)
	if err != nil {
		return domain.AddressNewResult{}, err
	}
	return domain.AddressNewResult{
		Wallet:  wallet,
		Ref:     wallet + "/" + d.Branch.String() + "/" + domain.IndexString(d.Index),
		Branch:  uint32(d.Branch),
		Index:   d.Index,
		Address: d.Address,
		Path:    d.Path,
	}, nil
}

// AddressList lists a wallet's materialized addresses. The active --network must
// match the wallet's network.
func (s *Service) AddressList(ctx context.Context, req domain.AddressListRequest) (domain.AddressListResult, error) {
	wallet, err := s.resolveWallet(ctx, req.Wallet)
	if err != nil {
		return domain.AddressListResult{}, err
	}
	if err := s.assertWalletNetwork(ctx, wallet); err != nil {
		return domain.AddressListResult{}, err
	}

	network, addrs, err := s.keys.ListAddresses(ctx, wallet, s.net)
	if err != nil {
		return domain.AddressListResult{}, err
	}
	out := domain.AddressListResult{
		Wallet:    wallet,
		Network:   network,
		Addresses: make([]domain.AddressSummary, 0, len(addrs)),
	}
	for _, a := range addrs {
		out.Addresses = append(out.Addresses, domain.AddressSummary{
			Ref:       wallet + "/" + a.Branch.String() + "/" + domain.IndexString(a.Index),
			Branch:    uint32(a.Branch),
			Index:     a.Index,
			Address:   a.Address,
			CreatedAt: a.CreatedAt,
		})
	}
	return out, nil
}

// assertWalletNetwork enforces the scope guard: a BOUND wallet is locked to one
// network and refuses ops on any other active network (usage.network_mismatch,
// exit 2); an AGNOSTIC wallet works on every network, so the guard is a no-op for
// it. The check loads the wallet meta against the active network — for a bound
// wallet ShowWallet renders the bound network into Network, so a mismatch is
// w.Network != s.net.
func (s *Service) assertWalletNetwork(ctx context.Context, wallet string) error {
	// A wallet op is rendered/derived against the active network; with none resolved
	// fail with usage.network_required before loading the wallet meta against "". This
	// is the shared gate for address new/list, balance, and utxo list.
	if err := s.requireNetwork(); err != nil {
		return err
	}
	w, err := s.keys.ShowWallet(ctx, wallet, s.net)
	if err != nil {
		return err
	}
	if w.Scope == "bound" && w.Network != s.net {
		return domain.Newf("usage.network_mismatch",
			"wallet %q is bound to network %q but the active network is %q; pass --network %s",
			wallet, w.Network, s.net, w.Network)
	}
	return nil
}
