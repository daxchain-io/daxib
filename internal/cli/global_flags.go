package cli

import (
	"github.com/daxchain-io/daxib/internal/cli/render"
)

// FlagValues holds the global persistent flags bound on the root command. It is
// the cli frontend's own struct. The path/network subset is destined for
// service.Options (the only thing service.Open consumes) once the core lands;
// the output flags (--json/--quiet/--yes) are frontend-only and never cross into
// the core.
type FlagValues struct {
	JSON     bool   // --json: machine output
	Quiet    bool   // --quiet: suppress non-essential human lines
	Network  string // --network: active-network override (mainnet/testnet/testnet4/signet/regtest)
	Backend  string // --backend: per-invocation backend-endpoint override (bitcoind RPC / Esplora)
	Config   string // --config: config file or dir
	Keystore string // --keystore: keystore dir
	StateDir string // --state-dir: mutable state dir
	Yes      bool   // --yes: skip the interactive y/N confirmation prompt for money-moving ops (required for those ops non-interactively)

	// Wallet is the active-wallet override (--wallet). M1 binds no command-level
	// --wallet yet (its first consumer is balance/tx); the default-wallet
	// precedence (flag>env>meta.json) gets wired when the keys provider lands.
	Wallet string
}

// Mode projects the output-style subset the render package threads.
func (f FlagValues) Mode() render.Mode {
	return render.Mode{JSON: f.JSON, Quiet: f.Quiet}
}
