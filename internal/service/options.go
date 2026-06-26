package service

import (
	"io"
	"time"
)

// Options is what service.Open consumes. The cli frontend builds it from
// flags/env (and injects the host secret primitives via SecretIO); the core never
// reaches for os.Stdin / time.Now directly.
type Options struct {
	// Keystore is the keystore directory ($DAXIB_KEYSTORE / --keystore).
	Keystore string
	// Network is the active network name (mainnet/testnet/signet/regtest); ""
	// defaults to mainnet.
	Network string
	// Wallet is the active-wallet override (--wallet > DAXIB_WALLET).
	Wallet string
	// KDFLight forces the test scrypt cost on FIRST INIT only (DAXIB_KDF_LIGHT=1).
	KDFLight bool

	// Clock is the injected wall clock (defaults to time.Now).
	Clock func() time.Time
	// Secret carries the host primitives the §3.6 resolver needs (stdin, env
	// lookup, TTY detection, the terminal prompt).
	Secret SecretIO
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
