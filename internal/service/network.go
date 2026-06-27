package service

import (
	"context"
	"strings"

	"github.com/daxchain-io/daxib/internal/domain"
)

// network.go is the service-side bridge for the `daxib network use|show|list`
// noun (GAP-3). It owns the PERSISTED active-network default (config
// defaults.network — the third rung of the resolution ladder, below --network and
// DAXIB_NETWORK) and reports the resolved active network + its source for
// introspection. The cli/mcp frontends never import internal/config directly (the
// arch matrix forbids frontend→config); these methods are the sanctioned bridge.
//
// `network show`/`list` are network-INDEPENDENT (they answer "what IS the active
// network", so they must work even when none is selected) — they do NOT call
// requireNetwork. `network use` only WRITES a persisted default; it likewise does
// not require a currently-resolved network.

// supportedNetworks is the canonical, ordered set the `network list` noun
// enumerates — daxib's five well-known networks (mirrors config.listNetworks and
// the domain constants).
var supportedNetworks = []domain.Network{
	domain.NetworkMainnet,
	domain.NetworkTestnet,
	domain.NetworkTestnet4,
	domain.NetworkSignet,
	domain.NetworkRegtest,
}

// NetworkUse persists (or clears) the active-network default in config
// defaults.network — the same value `config set defaults.network` writes. A
// non-empty net must be one of the five well-known networks (validated by the
// config store); an empty net CLEARS the persisted default (back to unresolved).
// Requires a config dir (backend.not_configured otherwise).
func (s *Service) NetworkUse(ctx context.Context, net string) (domain.NetworkUseResult, error) {
	store, err := s.requireConfig()
	if err != nil {
		return domain.NetworkUseResult{}, err
	}
	net = strings.TrimSpace(net)
	if err := store.SetKey(ctx, "defaults.network", net); err != nil {
		return domain.NetworkUseResult{}, err
	}
	return domain.NetworkUseResult{Network: net, Cleared: net == ""}, nil
}

// NetworkShow reports the resolved active network and WHERE it was resolved from
// (flag/env/config/unset). It is read-only and network-independent: when nothing
// is selected it returns Resolved=false with Source="unset" (a network-requiring
// op would then fail with usage.network_required). It also surfaces the persisted
// config defaults.network value (if any) so an operator can see the standing
// default even when a flag/env override is in effect.
func (s *Service) NetworkShow(_ context.Context) (domain.NetworkShowResult, error) {
	out := domain.NetworkShowResult{
		Network:  string(s.net),
		Source:   s.netSource,
		Resolved: s.net != "",
	}
	if out.Source == "" {
		out.Source = "unset"
	}
	// Best-effort: surface the standing persisted default for visibility. A missing
	// config dir simply yields no persisted value.
	if s.cfg != nil {
		if p, perr := s.cfg.DefaultNetwork(); perr == nil {
			out.Persisted = p
		}
	}
	return out, nil
}

// NetworkList returns the five well-known networks in canonical order, marking the
// current active one (if any). Network-independent (read-only introspection).
func (s *Service) NetworkList(_ context.Context) (domain.NetworkListResult, error) {
	out := domain.NetworkListResult{Networks: make([]domain.NetworkListEntry, 0, len(supportedNetworks))}
	for _, n := range supportedNetworks {
		out.Networks = append(out.Networks, domain.NetworkListEntry{
			Network:  string(n),
			CoinType: n.CoinType(),
			Active:   s.net != "" && s.net == n,
		})
	}
	return out, nil
}
