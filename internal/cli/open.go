package cli

import (
	"context"
	"os"
	"time"

	"golang.org/x/term"

	"github.com/daxchain-io/daxib/internal/service"
)

// openService opens the core service lazily for one command, wiring the host
// secret primitives (stdin, env lookup, TTY detection, terminal prompt) into the
// service's SecretIO. The cli frontend may not import the secret provider (the
// arch matrix forbids frontend→secret), so it builds an equivalent terminal
// reader from os + x/term here. The returned closeFn must be deferred.
func openService(ctx context.Context, rs *rootState) (*service.Service, func(), error) {
	opts := buildServiceOptions(rs)
	svc, err := service.Open(ctx, opts)
	if err != nil {
		return nil, func() {}, err
	}
	return svc, func() { _ = svc.Close() }, nil
}

// buildServiceOptions assembles service.Options from the global flags + env, with
// the documented precedence: --keystore > DAXIB_KEYSTORE > ~/.daxib/keystore;
// --network > DAXIB_NETWORK; --wallet > DAXIB_WALLET.
func buildServiceOptions(rs *rootState) service.Options {
	keystore := rs.flags.Keystore
	if keystore == "" {
		if v, ok := os.LookupEnv("DAXIB_KEYSTORE"); ok && v != "" {
			keystore = v
		} else {
			keystore = defaultKeystoreDir()
		}
	}

	// Network resolution rungs 1+2 (flag > env). The persisted default (config
	// defaults.network) is rung 3, resolved in the service (it owns the config
	// store, which the cli may not import). When neither flag nor env is set, network
	// stays "" and netSource "" — the service then tries the persisted default and,
	// failing that, leaves the network UNRESOLVED so network-requiring ops fail with
	// usage.network_required. NO silent default to mainnet.
	network := rs.flags.Network
	netSource := ""
	if network != "" {
		netSource = "flag"
	} else if v, ok := os.LookupEnv("DAXIB_NETWORK"); ok && v != "" {
		network = v
		netSource = "env"
	}

	wallet := rs.flags.Wallet
	if wallet == "" {
		if v, ok := os.LookupEnv("DAXIB_WALLET"); ok && v != "" {
			wallet = v
		}
	}

	// --config / DAXIB_CONFIG denote the config DIRECTORY (the config state class),
	// not a file — the service joins config.toml inside it. This mirrors daxie's
	// DAXIE_CONFIG ConfigDir contract (the var is semver-protected).
	configDir := rs.flags.Config
	if configDir == "" {
		if v, ok := os.LookupEnv("DAXIB_CONFIG"); ok && v != "" {
			configDir = v
		} else {
			configDir = defaultConfigDir()
		}
	}

	bk := rs.flags.Backend
	if bk == "" {
		if v, ok := os.LookupEnv("DAXIB_BACKEND"); ok && v != "" {
			bk = v
		}
	}

	// --state-dir > DAXIB_STATE_DIR > ~/.daxib/state. The state dir holds the tx
	// journal + send locks.
	stateDir := rs.flags.StateDir
	if stateDir == "" {
		if v, ok := os.LookupEnv("DAXIB_STATE_DIR"); ok && v != "" {
			stateDir = v
		} else {
			stateDir = defaultStateDir()
		}
	}

	_, light := os.LookupEnv("DAXIB_KDF_LIGHT")

	return service.Options{
		Keystore:      keystore,
		Config:        configDir,
		State:         stateDir,
		Network:       network,
		NetworkSource: netSource,
		Wallet:        wallet,
		Backend:       bk,
		KDFLight:      light,
		Clock:         time.Now,
		Secret: service.SecretIO{
			Stdin:     os.Stdin,
			LookupEnv: os.LookupEnv,
			IsTTY:     func() bool { return term.IsTerminal(int(os.Stdin.Fd())) },
			Prompt:    ttyPrompt,
		},
	}
}

// ttyPrompt reads a secret from the terminal with echo disabled, printing the
// label to stderr (so stdout stays clean for piping).
func ttyPrompt(label string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	_, _ = os.Stderr.WriteString(label)
	pw, err := term.ReadPassword(fd)
	_, _ = os.Stderr.WriteString("\n")
	if err != nil {
		return nil, err
	}
	return pw, nil
}
