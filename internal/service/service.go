package service

import (
	"context"
	"time"

	"github.com/daxchain-io/daxib/internal/backend"
	"github.com/daxchain-io/daxib/internal/config"
	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/keys"
)

// Service is THE daxib core composition root. The cli and mcpserver frontends are
// thin adapters over it. In M2 it owns the keystore (keys.Store) and the secret
// acquisition wiring; later milestones add the backend provider, coin selection,
// the tx/PSBT pipeline, and the sealed-policy engine (docs/PLAN.md §8).
type Service struct {
	opts    Options
	keys    *keys.Store
	cfg     *config.Store // backend endpoint config store (nil when no --config path)
	clock   func() time.Time
	secret  SecretIO
	wallet  string         // active-wallet override (--wallet > DAXIB_WALLET)
	backend string         // active-backend override (--backend > DAXIB_BACKEND)
	net     domain.Network // active network (validated)
	dial    func(ctx context.Context, o backend.Options) (backend.Client, error)
}

// Open builds a Service from Options. The keystore is opened eagerly (keys.Open
// runs the derivation-watermark tripwire under the index.lock). A missing
// keystore directory is a fresh install, not an error. Open is lazy about
// everything else (no backend dial in M2 — none exists yet).
func Open(ctx context.Context, opts Options) (*Service, error) {
	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}
	net, err := domain.ParseNetwork(opts.Network)
	if err != nil {
		return nil, err
	}

	ks, err := keys.Open(ctx, keys.Options{
		Dir:   opts.Keystore,
		Clock: clock,
		Light: opts.KDFLight,
	})
	if err != nil {
		return nil, err
	}

	// The config store is optional: a missing --config path simply means no
	// config-backed backend selection (backend/balance then report
	// backend.not_configured). A non-empty path opens lazily (the file need not
	// exist yet).
	var cfg *config.Store
	if opts.Config != "" {
		cfg, err = config.Open(opts.Config)
		if err != nil {
			return nil, err
		}
	}

	dial := opts.Dial
	if dial == nil {
		dial = backend.Dial
	}

	return &Service{
		opts:    opts,
		keys:    ks,
		cfg:     cfg,
		clock:   clock,
		secret:  opts.Secret,
		wallet:  opts.Wallet,
		backend: opts.Backend,
		net:     net,
		dial:    dial,
	}, nil
}

// Close releases the keystore.
func (s *Service) Close() error {
	if s.keys != nil {
		return s.keys.Close()
	}
	return nil
}

// Now returns the service's wall time (through the injected clock).
func (s *Service) Now() time.Time { return s.clock() }

// resolveWallet applies the default-wallet precedence: an explicit name (the
// command's --wallet) > the Service's active wallet (--wallet flag > DAXIB_WALLET)
// > meta.json default_wallet. Returns wallet.not_found when none resolves.
func (s *Service) resolveWallet(ctx context.Context, explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if s.wallet != "" {
		return s.wallet, nil
	}
	if d, ok := s.keys.DefaultWallet(ctx); ok {
		return d, nil
	}
	return "", domain.New("wallet.not_found", "no wallet specified and no default wallet is set; pass --wallet <name> or create one")
}
