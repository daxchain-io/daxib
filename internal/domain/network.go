package domain

// Bitcoin has four well-known networks (docs/PLAN.md §2.2 — "simpler than
// chain-id"). The domain layer owns the canonical names + validation; the keys
// provider maps each to its btcd chaincfg.Params (domain imports nothing
// internal and must not pull in btcd).

// Network is one of Bitcoin's four well-known networks.
type Network string

const (
	// NetworkMainnet is Bitcoin mainnet (bc1 addresses, coin type 0).
	NetworkMainnet Network = "mainnet"
	// NetworkTestnet is testnet3 (tb1 addresses, coin type 1).
	NetworkTestnet Network = "testnet"
	// NetworkSignet is the default signet (tb1 addresses, coin type 1).
	NetworkSignet Network = "signet"
	// NetworkRegtest is a local regression-test network (bcrt1 addresses, coin
	// type 1).
	NetworkRegtest Network = "regtest"
)

// DefaultNetwork is the network used when none is selected by flag/env.
const DefaultNetwork = NetworkMainnet

// ParseNetwork validates a network name and returns the canonical Network. An
// empty string maps to DefaultNetwork (mainnet). An unknown name is a usage error.
func ParseNetwork(s string) (Network, error) {
	switch s {
	case "":
		return DefaultNetwork, nil
	case string(NetworkMainnet):
		return NetworkMainnet, nil
	case string(NetworkTestnet):
		return NetworkTestnet, nil
	case string(NetworkSignet):
		return NetworkSignet, nil
	case string(NetworkRegtest):
		return NetworkRegtest, nil
	default:
		return "", Newf(CodeUsage+".network",
			"unknown network %q: want one of mainnet, testnet, signet, regtest", s)
	}
}

// CoinType returns the BIP-44 coin_type for the network's derivation path: 0 for
// mainnet, 1 for every test network (BIP-44 registered coin types).
func (n Network) CoinType() uint32 {
	if n == NetworkMainnet {
		return 0
	}
	return 1
}
