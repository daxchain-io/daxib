// Package config owns daxib's on-disk config store for backend endpoints
// (docs/PLAN.md §6): named bitcoind-RPC / Esplora connections bound to a network,
// one default per network, stored in TOML with ${env:}/${file:} secret references
// kept RAW (resolved transiently in service at dial time, never persisted, §7.5).
//
// config is a provider leaf: it imports domain (the error taxonomy + value types)
// and fsx (atomic write, lock, perms) — never service, a frontend, or the backend
// provider. The Endpoint→backend.Options assembly (secret-reference resolution,
// default-per-network selection) lives in service, the one place that legally
// imports both config and backend. config NEVER resolves a secret reference and
// NEVER dials.
//
// M3 keeps this deliberately small (a focused [backend.<name>] store, no Viper):
// the daxie config is far larger, but daxib v1's only config surface is the
// backend endpoint set, so this mirrors daxie's RPC-endpoint idioms (named object,
// network binding, default-per-network, secret refs, masked views) without the
// full schema machinery.
package config

import (
	"github.com/daxchain-io/daxib/internal/domain"
)

// Endpoint is a named backend connection bound to a network. URLRef and the auth
// fields keep the RAW value with any ${env:}/${file:} references still embedded —
// config NEVER resolves them (§7.5). Type is "core" | "esplora".
type Endpoint struct {
	Network    string `toml:"network"`
	Type       string `toml:"type"`
	URLRef     string `toml:"url"`
	RPCUserRef string `toml:"rpcuser,omitempty"`
	RPCPassRef string `toml:"rpcpassword,omitempty"`
	CookieFile string `toml:"cookie-file,omitempty"` // path to a .cookie file
}

// NetworkConfig holds a network's per-network selections. DefaultBackend names
// the endpoint dialed when no --backend / DAXIB_BACKEND override is given.
type NetworkConfig struct {
	DefaultBackend string `toml:"default-backend,omitempty"`
}

// Defaults holds operator-wide (not per-network) defaults. Network is the
// PERSISTED active-network default — the third rung of the resolution ladder
// (--network > DAXIB_NETWORK > defaults.network > unresolved), written by
// `daxib network use <net>` / `config set defaults.network`. Empty means no
// persisted default (the unresolved sentinel; a network-requiring op then fails
// with usage.network_required).
type Defaults struct {
	Network string `toml:"network,omitempty"`
}

// File is the whole config.toml document. Backends are keyed by name; Networks by
// network name. Both maps tolerate absence (a fresh install has neither). Defaults
// holds operator-wide scalars (the persisted active-network default).
type File struct {
	Schema   int                      `toml:"schema"`
	Defaults Defaults                 `toml:"defaults"`
	Backends map[string]Endpoint      `toml:"backend"`
	Networks map[string]NetworkConfig `toml:"networks"`
}

// SchemaVersion is the config-file schema this build writes.
const SchemaVersion = 1

// EndpointView is the masked render shape for one endpoint (URL already masked).
// service re-maps it into domain.BackendSummary so the cli never imports config.
type EndpointView struct {
	Name    string
	Network string
	Type    string
	URL     string // MASKED
	Default bool
}

// validName reuses the wallet-name grammar for endpoint names (1..64 chars,
// [a-z0-9] then [a-z0-9_-]) so a backend name is filename/flag-safe.
func validName(s string) bool { return domain.ValidWalletName(s) }
