package service

import (
	"context"

	"github.com/daxchain-io/daxib/internal/domain"
)

// config.go is the service-side bridge for the `daxib config get|set|list` noun.
// The cli never touches internal/config directly (the arch matrix forbids
// frontend→config), so these thin methods are the sanctioned bridge AND the
// re-export point for the one config shape the frontend renders (ConfigEntry).
//
// All config.* error codes (config.read_only exit 10, ref.not_found exit 10,
// usage.* exit 2 for a rejected policy.*/unknown key) originate in internal/config
// and flow back unchanged through the cli render registry. A missing --config /
// DAXIB_CONFIG path is backend.not_configured (exit 10) via requireConfig.

// ConfigList returns every operator-visible config key with its effective value
// and source. The named-endpoint objects and the policy.* subtree are excluded by
// internal/config.
func (s *Service) ConfigList(ctx context.Context, p domain.Principal) (domain.ConfigListResult, error) {
	_ = ctx
	store, err := s.requireConfig()
	if err != nil {
		return domain.ConfigListResult{}, err
	}
	kvs, err := store.ListKeys()
	if err != nil {
		return domain.ConfigListResult{}, err
	}
	out := domain.ConfigListResult{Entries: make([]domain.ConfigEntry, len(kvs))}
	for i, kv := range kvs {
		out.Entries[i] = domain.ConfigEntry{Key: kv.Key, Value: kv.Value, Source: kv.Source}
	}
	return out, nil
}

// ConfigGet returns one key's effective value, or ref.not_found (exit 10) for an
// unknown key / usage.policy_key (exit 2) for a policy.* key.
func (s *Service) ConfigGet(ctx context.Context, p domain.Principal, req domain.ConfigGetRequest) (domain.ConfigGetResult, error) {
	_ = ctx
	store, err := s.requireConfig()
	if err != nil {
		return domain.ConfigGetResult{}, err
	}
	val, err := store.GetKey(req.Key)
	if err != nil {
		return domain.ConfigGetResult{}, err
	}
	return domain.ConfigGetResult{Key: req.Key, Value: val}, nil
}

// ConfigSet writes one operator key into config.toml via the store's atomic,
// locked rewrite. It rejects any policy.* key (usage.policy_key, exit 2) and maps a
// read-only mount to config.read_only (exit 10).
func (s *Service) ConfigSet(ctx context.Context, p domain.Principal, req domain.ConfigSetRequest) (domain.ConfigSetResult, error) {
	store, err := s.requireConfig()
	if err != nil {
		return domain.ConfigSetResult{}, err
	}
	if err := store.SetKey(ctx, req.Key, req.Value); err != nil {
		return domain.ConfigSetResult{}, err
	}
	return domain.ConfigSetResult(req), nil
}
