package service

import (
	"context"
	"io"
	"time"

	"github.com/daxchain-io/daxib/internal/backend"
)

// Options is what service.Open consumes. The cli frontend builds it from
// flags/env (and injects the host secret primitives via SecretIO); the core never
// reaches for os.Stdin / time.Now directly.
type Options struct {
	// Keystore is the keystore directory ($DAXIB_KEYSTORE / --keystore).
	Keystore string
	// Config is the config DIRECTORY ($DAXIB_CONFIG / --config), the config state
	// class — the store reads/writes <Config>/config.toml inside it (and, on the
	// forward path, the sealed policy anchor). Empty disables config-backed backend
	// selection.
	Config string
	// State is the mutable state DIRECTORY ($DAXIB_STATE_DIR / --state-dir), the
	// state class that holds the tx journal (<State>/journal/<network>.jsonl) and
	// the send/journal locks (<State>/locks). Empty defaults to <data-dir>/state via
	// stateDir(); the journal opens lazily (no dirs until the first send).
	State string
	// Network is the active network name (mainnet/testnet/signet/regtest); ""
	// defaults to mainnet.
	Network string
	// Wallet is the active-wallet override (--wallet > DAXIB_WALLET).
	Wallet string
	// Backend is the active-backend override (--backend > DAXIB_BACKEND); ""
	// falls back to the network's configured default.
	Backend string
	// KDFLight forces the test scrypt cost on FIRST INIT only (DAXIB_KDF_LIGHT=1).
	KDFLight bool

	// Clock is the injected wall clock (defaults to time.Now).
	Clock func() time.Time
	// Secret carries the host primitives the §3.6 resolver needs (stdin, env
	// lookup, TTY detection, the terminal prompt).
	Secret SecretIO

	// Dial overrides the backend dialer (tests inject a fake; production leaves it
	// nil to use backend.Dial). It receives the fully-resolved backend.Options.
	Dial func(ctx context.Context, o backend.Options) (backend.Client, error)
}

// SecretIO bundles the host primitives the secret resolver needs. The cli
// frontend fills these from os + x/term; tests inject stubs. The core stays free
// of a real TTY/stdin/env dependency.
type SecretIO struct {
	// Stdin is the stdin reader (os.Stdin in production).
	Stdin io.Reader
	// LookupEnv resolves env vars (os.LookupEnv in production).
	LookupEnv func(string) (string, bool)
	// IsTTY reports whether interactive prompting is possible.
	IsTTY func() bool
	// Prompt reads one secret interactively with the given label.
	Prompt func(label string) ([]byte, error)
}
