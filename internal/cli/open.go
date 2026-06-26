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
// the documented precedence: --keystore > DAXIB_KEYSTORE > platform default;
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

	network := rs.flags.Network
	if network == "" {
		if v, ok := os.LookupEnv("DAXIB_NETWORK"); ok && v != "" {
			network = v
		}
	}

	wallet := rs.flags.Wallet
	if wallet == "" {
		if v, ok := os.LookupEnv("DAXIB_WALLET"); ok && v != "" {
			wallet = v
		}
	}

	_, light := os.LookupEnv("DAXIB_KDF_LIGHT")

	return service.Options{
		Keystore: keystore,
		Network:  network,
		Wallet:   wallet,
		KDFLight: light,
		Clock:    time.Now,
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
