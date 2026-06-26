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
	d, err := s.keys.DeriveNext(ctx, wallet, branch)
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

	network, addrs, err := s.keys.ListAddresses(ctx, wallet)
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

// assertWalletNetwork enforces the §3.5 simplification: a wallet is bound to a
// network at creation, and address ops require the active --network to match it.
// A mismatch is a clear usage error rather than silently deriving a wrong-network
// address.
func (s *Service) assertWalletNetwork(ctx context.Context, wallet string) error {
	w, err := s.keys.ShowWallet(ctx, wallet)
	if err != nil {
		return err
	}
	if w.Network != s.net {
		return domain.Newf("usage.network_mismatch",
			"wallet %q is bound to network %q but the active network is %q; pass --network %s",
			wallet, w.Network, s.net, w.Network)
	}
	return nil
}
