package domain

// config_requests.go is the wire contract for the `daxib config get|set|list`
// noun — the generic operator-config surface over config.toml (the per-network
// default-backend selection). The policy.* subtree is rejected by the config
// provider (the sealed-anchor carve-out); these types carry only the non-policy
// keys. Single string values cross the boundary (no float).

// ConfigEntry is one listed config key with its effective value and source. It
// mirrors config.KV so the cli renders `config list` without importing the config
// provider (the arch matrix forbids frontend→config); the service re-exports it.
type ConfigEntry struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Source string `json:"source"` // "default" | "file"
}

// ConfigListResult is the full key set with effective values.
type ConfigListResult struct {
	Entries []ConfigEntry `json:"entries"`
}

// ConfigGetRequest reads one key's effective value.
type ConfigGetRequest struct {
	Key string `json:"key" jsonschema:"the config key, e.g. networks.mainnet.default-backend"`
}

// ConfigGetResult is one key/value (no Source — a direct get).
type ConfigGetResult struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// ConfigSetRequest writes one key. policy.* keys are rejected (exit 2).
type ConfigSetRequest struct {
	Key   string `json:"key" jsonschema:"the config key to set"`
	Value string `json:"value" jsonschema:"the new value (empty clears a default-backend)"`
}

// ConfigSetResult echoes the written key/value.
type ConfigSetResult struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
