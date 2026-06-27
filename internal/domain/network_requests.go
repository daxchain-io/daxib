package domain

// network_requests.go is the wire contract for the `daxib network` noun — the
// surface that selects + introspects the ACTIVE network without silently
// defaulting. `network use <net>` persists the default (config defaults.network);
// `network show` reports the resolved network and WHERE it came from; `network
// list` enumerates the five well-known networks. Single string values cross the
// boundary (no float).

// NetworkUseResult echoes the persisted active-network default after a
// `network use <net>` (empty Network clears it back to unresolved).
type NetworkUseResult struct {
	Network string `json:"network"`
	Cleared bool   `json:"cleared"` // true when the persisted default was cleared (empty arg)
}

// NetworkShowResult reports the resolved active network and its SOURCE. Source is
// one of "flag", "env", "config", or "unset"; when Resolved is false (Source ==
// "unset") Network is empty and a network-requiring op would fail with
// usage.network_required.
type NetworkShowResult struct {
	Network   string `json:"network"`             // the resolved network, "" when unset
	Source    string `json:"source"`              // flag | env | config | unset
	Resolved  bool   `json:"resolved"`            // false ⇒ no network selected
	Persisted string `json:"persisted,omitempty"` // the config defaults.network value, if any
}

// NetworkListEntry is one supported network with whether it is the current active
// network.
type NetworkListEntry struct {
	Network  string `json:"network"`
	CoinType uint32 `json:"coin_type"`
	Active   bool   `json:"active"`
}

// NetworkListResult is the five well-known networks, in canonical order.
type NetworkListResult struct {
	Networks []NetworkListEntry `json:"networks"`
}
