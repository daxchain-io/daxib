package config

import (
	"context"
	"sort"
	"strings"

	"github.com/daxchain-io/daxib/internal/domain"
)

// getset.go is the generic get/set/list surface over the config-class settings
// daxib actually has (the Bitcoin sibling of daxie's `config` noun, scoped to
// daxib's far smaller schema). daxib's only operator-tunable config today is the
// per-network DEFAULT BACKEND — the same selection `backend use` makes, exposed
// here as a dotted key so an agent can read/script it uniformly. The named
// [backend.<name>] endpoint objects are managed by the `backend` noun (add/list/
// use/remove), not listed as scalar keys; the policy.* subtree is REJECTED (it
// lives in the sealed anchor, set only via `daxib policy` — the anchor carve-out).
//
// The dotted key grammar:
//
//   defaults.network                     → the PERSISTED active-network default, the
//                                          third rung of the resolution ladder
//                                          (--network > DAXIB_NETWORK > this > error).
//                                          One of the five well-known networks; ""
//                                          clears it (back to unresolved). Written by
//                                          `daxib network use <net>`.
//   networks.<network>.default-backend   → the endpoint name dialed for <network>
//                                          when no --backend/DAXIB_BACKEND override
//                                          is given ("" = none configured).
//
// <network> is one of daxib's five well-known networks. Get on an unknown key is
// ref.not_found (exit 10); Set of a policy.* key is usage.policy_key (exit 2); a
// read-only mount on Set is config.read_only (exit 10).

// KV is one operator-visible config key with its effective value and the layer the
// value came from (here always "default" when unset or "file" when present).
type KV struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Source string `json:"source"` // "default" | "file"
}

// listNetworks is the canonical, ordered network set whose default-backend keys
// `config list` enumerates. It mirrors domain's five well-known networks.
var listNetworks = []string{"mainnet", "testnet", "testnet4", "signet", "regtest"}

// defaultsNetworkKey is the dotted key for the PERSISTED active-network default —
// the third rung of the network-resolution ladder. Its value is validated by
// domain.ParseNetwork (one of the five well-known networks); an empty value clears
// it (back to unresolved).
const defaultsNetworkKey = "defaults.network"

// defaultBackendKey is the dotted key for a network's default backend.
func defaultBackendKey(network string) string {
	return "networks." + network + ".default-backend"
}

// ListKeys returns the operator-visible config keys with their effective values,
// in a stable order. The five named-endpoint objects ([backend.<name>]) and the
// policy.* subtree are deliberately ABSENT (managed elsewhere). A missing config
// file lists every key with an empty value (source "default").
func (s *Store) ListKeys() ([]KV, error) {
	f, err := s.load()
	if err != nil {
		return nil, err
	}
	out := make([]KV, 0, len(listNetworks)+1)
	// The operator-wide persisted active-network default (the third rung of the
	// network-resolution ladder).
	{
		val := f.Defaults.Network
		src := "default"
		if val != "" {
			src = "file"
		}
		out = append(out, KV{Key: defaultsNetworkKey, Value: val, Source: src})
	}
	for _, net := range listNetworks {
		val := f.Networks[net].DefaultBackend
		src := "default"
		if val != "" {
			src = "file"
		}
		out = append(out, KV{Key: defaultBackendKey(net), Value: val, Source: src})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// GetKey returns one key's effective value, or ref.not_found for an unknown key. A
// policy.* key is rejected with usage.policy_key (it is never readable here — the
// anchor carve-out).
func (s *Store) GetKey(key string) (string, error) {
	if isPolicyKey(key) {
		return "", domain.Newf(domain.CodeUsage+".policy_key",
			"%q is a policy key — inspect it with `daxib policy show`, not `config get`", key)
	}
	if key == defaultsNetworkKey {
		f, err := s.load()
		if err != nil {
			return "", err
		}
		return f.Defaults.Network, nil
	}
	network, ok := parseDefaultBackendKey(key)
	if !ok {
		return "", domain.Newf(domain.CodeRefNotFound, "unknown config key %q", key)
	}
	// Validate the network the same way SetKey does so get and set agree: a
	// well-shaped key naming a non-existent network is ref.not_found (exit 10), not a
	// silent empty value with exit 0 (CFG-GET-1). parseDefaultBackendKey already
	// rejects an empty mid, so ParseNetwork's empty-is-unresolved case cannot reach
	// here (a non-empty unknown name is the usage.network error we project below).
	if _, perr := domain.ParseNetwork(network); perr != nil {
		return "", domain.Newf(domain.CodeRefNotFound, "unknown config key %q", key)
	}
	f, err := s.load()
	if err != nil {
		return "", err
	}
	return f.Networks[network].DefaultBackend, nil
}

// SetKey writes one key into config.toml via the store's atomic, locked rewrite. It
// rejects a policy.* key (usage.policy_key, exit 2) and an unknown key
// (usage.bad_key, exit 2). Setting networks.<net>.default-backend to a non-empty
// value requires that the endpoint EXISTS and is bound to <net> (the same guard
// `backend use` enforces); an empty value clears the default. A read-only mount is
// config.read_only (exit 10).
func (s *Store) SetKey(ctx context.Context, key, value string) error {
	if isPolicyKey(key) {
		return domain.Newf(domain.CodeUsage+".policy_key",
			"%q is a policy key — set it with `daxib policy`, not `config set` (the sealed anchor carve-out)", key)
	}
	if key == defaultsNetworkKey {
		// The persisted active-network default. A non-empty value must be one of the
		// five well-known networks (validated by ParseNetwork); an empty value CLEARS
		// it (back to the unresolved sentinel). ParseNetwork("") returns "" with no
		// error, so the clear path and the explicit "" both land as "".
		val := strings.TrimSpace(value)
		if val != "" {
			if _, perr := domain.ParseNetwork(val); perr != nil {
				return domain.Newf(domain.CodeUsage+".bad_value",
					"cannot set %s = %q: %s", key, val, perr.(*domain.Error).Msg)
			}
		}
		return s.mutate(ctx, func(f *File) error {
			f.Defaults.Network = val
			return nil
		})
	}
	network, ok := parseDefaultBackendKey(key)
	if !ok {
		return domain.Newf(domain.CodeUsage+".bad_key",
			"unknown config key %q (settable keys: networks.<network>.default-backend)", key)
	}
	if _, perr := domain.ParseNetwork(network); perr != nil {
		return domain.Newf(domain.CodeUsage+".bad_key", "config key %q names an unknown network %q", key, network)
	}
	return s.mutate(ctx, func(f *File) error {
		val := strings.TrimSpace(value)
		if val != "" {
			ep, exists := f.Backends[val]
			if !exists {
				return domain.Newf(domain.CodeBackendNotFound,
					"cannot set %s = %q: no backend named %q (add it with `daxib backend add`)", key, val, val)
			}
			if ep.Network != network {
				return domain.Newf(domain.CodeUsage+".bad_value",
					"cannot set %s = %q: backend %q is bound to network %q, not %q", key, val, val, ep.Network, network)
			}
		}
		nc := f.Networks[network]
		nc.DefaultBackend = val
		f.Networks[network] = nc
		return nil
	})
}

// parseDefaultBackendKey parses a "networks.<net>.default-backend" key, returning
// the network and whether the key matched the shape. It does NOT validate that the
// network is one of the five (the caller does, with a precise error).
func parseDefaultBackendKey(key string) (network string, ok bool) {
	const prefix = "networks."
	const suffix = ".default-backend"
	if !strings.HasPrefix(key, prefix) || !strings.HasSuffix(key, suffix) {
		return "", false
	}
	mid := key[len(prefix) : len(key)-len(suffix)]
	if mid == "" || strings.Contains(mid, ".") {
		return "", false
	}
	return mid, true
}

// isPolicyKey reports whether a key is in the policy.* subtree (never settable or
// gettable via `config` — the sealed anchor carve-out).
func isPolicyKey(key string) bool {
	return key == "policy" || strings.HasPrefix(key, "policy.")
}
