package service

import (
	"context"
	"path/filepath"
	"time"

	"github.com/daxchain-io/daxib/internal/backend"
	"github.com/daxchain-io/daxib/internal/config"
	"github.com/daxchain-io/daxib/internal/contacts"
	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/journal"
	"github.com/daxchain-io/daxib/internal/keys"
)

// Service is THE daxib core composition root. The cli and mcpserver frontends are
// thin adapters over it. In M2 it owns the keystore (keys.Store) and the secret
// acquisition wiring; later milestones add the backend provider, coin selection,
// the tx/PSBT pipeline, and the sealed-policy engine (docs/ARCHITECTURE.md §8).
type Service struct {
	opts    Options
	keys    *keys.Store
	cfg     *config.Store // backend endpoint config store (nil when no --config path)
	clock   func() time.Time
	secret  SecretIO
	wallet  string         // active-wallet override (--wallet > DAXIB_WALLET)
	backend string         // active-backend override (--backend > DAXIB_BACKEND)
	net     domain.Network // active network (validated); "" when UNRESOLVED (no silent default)
	// netSource records WHERE net was resolved from, for `network show`. One of
	// "flag", "env", "config", or "unset" (when net == ""). The flag/env split comes
	// from Options.NetworkSource (the cli/mcp host already knows which it used);
	// "config" / "unset" are decided here at Open.
	netSource string
	dial      func(ctx context.Context, o backend.Options) (backend.Client, error)

	journal  *journal.Store  // the tx journal (state class); nil only if Open failed to bind it
	contacts *contacts.Store // the local address book (state class); name->address resolution
	stateDir string          // resolved mutable state directory (<data>/state by default)
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
	// netSource: the host (cli/mcp) tells us flag vs env via Options.NetworkSource
	// when it supplied a non-empty Options.Network. When it did NOT (net == ""), we
	// consult the persisted default (config defaults.network) as the THIRD rung of
	// the ladder; if that is empty too, net stays "" (UNRESOLVED) and any
	// network-requiring op fails with usage.network_required. No silent default to
	// mainnet (or any net) ever happens.
	netSource := opts.NetworkSource
	if net == "" {
		netSource = "unset"
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

	// Third rung of the network-resolution ladder: when no flag/env network was
	// supplied, consult the PERSISTED default (config defaults.network, written by
	// `daxib network use`). A bad persisted value is a usage error (it should never
	// be malformed — `network use` / `config set` validate on write — but a
	// hand-edited config.toml could carry garbage, and failing closed beats trusting
	// it). Still empty ⇒ net stays "" (UNRESOLVED); no silent fallback.
	if net == "" && cfg != nil {
		if persisted, derr := cfg.DefaultNetwork(); derr != nil {
			return nil, derr
		} else if persisted != "" {
			net, err = domain.ParseNetwork(persisted)
			if err != nil {
				return nil, err
			}
			netSource = "config"
		}
	}

	dial := opts.Dial
	if dial == nil {
		dial = backend.Dial
	}

	// The tx journal (state class) opens lazily: it creates no dirs until the first
	// send, so a read-only/uninitialized state dir is fine for non-send commands. A
	// resolved state dir is always available (defaults to <data>/state).
	sd := stateDir(opts)
	j, err := journal.Open(sd, clock)
	if err != nil {
		return nil, err
	}

	// The contacts address book (state class) opens lazily: it creates no dirs
	// until the first `contacts add`, so a read-only/uninitialized state dir is fine
	// for non-mutating commands. It shares the resolved state dir with the journal.
	contactStore, err := contacts.Open(sd)
	if err != nil {
		return nil, err
	}

	svc := &Service{
		opts:      opts,
		keys:      ks,
		cfg:       cfg,
		clock:     clock,
		secret:    opts.Secret,
		wallet:    opts.Wallet,
		backend:   opts.Backend,
		net:       net,
		netSource: netSource,
		dial:      dial,
		journal:   j,
		contacts:  contactStore,
		stateDir:  sd,
	}

	// Best-effort reconcile at open (never fails Open): leaves `signed` records for
	// lazy rebroadcast under the next send-lock / tx wait, and may opportunistically
	// promote a `broadcast` record to confirmed. It performs NO destructive action
	// offline.
	svc.reconcileAtOpen(ctx)

	return svc, nil
}

// stateDir resolves the mutable state directory: an explicit Options.State, else
// <keystore-parent>/state (so a daxib install keeps keystore/config/state as
// siblings under one data root). When even the keystore dir is empty it falls back
// to "./.daxib/state".
func stateDir(opts Options) string {
	if opts.State != "" {
		return opts.State
	}
	if opts.Keystore != "" {
		return filepath.Join(filepath.Dir(opts.Keystore), "state")
	}
	return filepath.Join(".daxib", "state")
}

// Close releases the keystore (and the journal, a no-op flush kept for symmetry).
func (s *Service) Close() error {
	if s.journal != nil {
		_ = s.journal.Close()
	}
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

// requireNetwork is the chokepoint guard for every network-specific op. When no
// network resolved (--network > DAXIB_NETWORK > config defaults.network all empty),
// s.net == "" and this returns a typed usage.network_required (exit 2) instead of
// letting the op proceed against a silently-defaulted network. The OWNER decision
// is NO silent default anywhere: an unqualified network-requiring command MUST
// fail, telling the operator how to select one. Network-INDEPENDENT commands
// (version, convert, completion, keystore info/change-passphrase, contacts,
// agnostic `wallet create`) never call this.
func (s *Service) requireNetwork() error {
	if s.net == "" {
		return domain.New(domain.CodeNetworkRequired,
			"no network selected; pass --network <net>, set DAXIB_NETWORK, or run `daxib network use <net>`")
	}
	return nil
}
