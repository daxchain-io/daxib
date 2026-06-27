// Package keys is daxib's local key-management provider: BIP-39 mnemonics,
// BIP-84 HD derivation, and an encrypted keystore on disk. It is a provider (a
// leaf): it imports domain (error types + value types), secret (zeroable
// passphrase buffers), and fsx (atomic writes, flock, permission checks) — never
// service or a frontend.
//
// On-disk layout under the keystore dir (§3.4):
//
//	keystore.json        manifest: format, kdf defaults, verifier envelope
//	meta.json            sidecar: default wallet, per-uuid wallet metadata
//	index.lock           advisory flock sibling (empty)
//	wallets/<uuid>.json  AES-256-GCM-sealed mnemonic blob
//
// Mutations take the exclusive index.lock; POSIX reads are lock-free (Windows
// readers take a shared lock — see rlock_windows.go). The encryption envelope
// deliberately diverges from daxie's geth-v3 to a stdlib AES-256-GCM AEAD — see
// codec.go for the rationale.
package keys

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/daxchain-io/daxib/internal/fsx"
)

// lockTimeout bounds index.lock acquisition. A longer-held lock surfaces as
// state.lock_timeout (exit 11).
const lockTimeout = 15 * time.Second

// Options configures a keystore Store.
type Options struct {
	Dir   string           // keystore directory ($DAXIB_KEYSTORE)
	Clock func() time.Time // injected wall clock (defaults to time.Now)
	// Light forces the test scrypt cost on FIRST INIT only. After init the
	// manifest's light flag is authoritative; this option is ignored. The cli
	// frontend sets it from DAXIB_KDF_LIGHT.
	Light bool
}

// Store is an open keystore at a directory. A nil-safe, per-operation locking
// model: mutations take the exclusive index.lock; reads are lock-free on POSIX.
type Store struct {
	dir   string
	clock func() time.Time
	light bool

	exclMu   sync.Mutex
	exclHeld bool
}

// Open opens (does not necessarily create) a keystore at opts.Dir. A missing
// directory is a fresh install (Initialized()==false); the dirs are created lazily
// on first init. Open runs the derivation-watermark tripwire (§3.4) under the
// exclusive lock when a meta.json already exists, failing closed
// (keystore.derivation_watermark) on an inconsistent restore.
func Open(ctx context.Context, opts Options) (*Store, error) {
	if opts.Dir == "" {
		return nil, errKeys(CodeKeystoreNotFound, "no keystore directory configured")
	}
	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}
	light := opts.Light
	s := &Store{dir: opts.Dir, clock: clock, light: light}

	// If a manifest exists, adopt its light flag (the downgrade guard) and run the
	// watermark check. A fresh keystore has nothing to check.
	m, err := s.loadManifest()
	if err != nil {
		return nil, err
	}
	if m != nil {
		s.light = m.Light
	}

	// A manifest existing means the keystore is initialized, so a crashed
	// change-passphrase rotation may have left staged artifacts (§3.8). Heal them
	// (roll forward if the commit marker is present, else roll back the orphaned
	// .new files) under the exclusive lock BEFORE the watermark tripwire, so both
	// run against a single-passphrase, consistent on-disk state.
	if m != nil {
		if werr := s.withLock(ctx, func() error {
			if rerr := recoverRotation(s.dir); rerr != nil {
				return rerr
			}
			if _, statErr := os.Stat(s.metaPath()); statErr == nil {
				meta, lerr := s.loadMeta()
				if lerr != nil {
					return lerr
				}
				return meta.checkWatermark()
			}
			return nil
		}); werr != nil {
			return nil, werr
		}
	}
	return s, nil
}

// Close releases any held resources. The per-operation lock is released by each
// mutation, so Close is currently a no-op kept for symmetry with daxie.
func (s *Store) Close() error { return nil }

// Initialized reports whether the keystore has a manifest (a verifier exists).
func (s *Store) Initialized() bool {
	_, err := os.Stat(s.manifestPath())
	return err == nil
}

// now renders the current wall time as an RFC3339 UTC string.
func (s *Store) now() string { return s.clock().UTC().Format(time.RFC3339) }

// ── paths ────────────────────────────────────────────────────────────────────

func (s *Store) manifestPath() string { return filepath.Join(s.dir, "keystore.json") }
func (s *Store) metaPath() string     { return filepath.Join(s.dir, "meta.json") }

// lockPath is the lock BASE; fsx.Lock/RLock append ".lock", so the on-disk
// advisory flock sibling is the documented "index.lock" (§3.4 layout).
func (s *Store) lockPath() string   { return filepath.Join(s.dir, "index") }
func (s *Store) walletsDir() string { return filepath.Join(s.dir, "wallets") }
func (s *Store) walletPath(id string) string {
	return filepath.Join(s.walletsDir(), id+".json")
}

// ── locking ──────────────────────────────────────────────────────────────────

// withLock runs fn while holding the exclusive index.lock. The keystore dir must
// exist (callers that may init first call ensureDirs inside fn or before).
func (s *Store) withLock(ctx context.Context, fn func() error) error {
	// Ensure the directory exists so the sibling .lock can be created.
	if err := s.ensureDirs(); err != nil {
		return err
	}
	lctx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()

	unlock, err := fsx.Lock(lctx, s.lockPath())
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return errKeys(CodeStateLockTimeout, "timed out acquiring the keystore lock; another daxib process may be holding it")
		}
		return errWrap(CodeStateCorrupt, "acquiring keystore lock", err)
	}
	defer unlock()

	s.exclMu.Lock()
	s.exclHeld = true
	s.exclMu.Unlock()
	defer func() {
		s.exclMu.Lock()
		s.exclHeld = false
		s.exclMu.Unlock()
	}()

	return fn()
}

// holdingExclusive reports whether this Store currently holds the exclusive lock
// (consulted by the Windows reader path to avoid a self-deadlock). It is used only
// by rlock_windows.go, so the non-windows build sees it as unused.
//
//nolint:unused // used by rlock_windows.go on the windows build
func (s *Store) holdingExclusive() bool {
	s.exclMu.Lock()
	defer s.exclMu.Unlock()
	return s.exclHeld
}

// ── fs helpers ─────────────────────────────────────────────────────────────────

// ensureDirs creates the keystore dir + wallets/ subdir at 0700 (owner-only),
// re-tightening a pre-existing dir.
func (s *Store) ensureDirs() error {
	if err := fsx.MkdirAll(s.walletsDir(), 0o700); err != nil {
		if fsx.IsReadOnly(err) {
			return errKeys(CodeKeystoreReadOnly, "keystore directory is read-only")
		}
		return errWrap(CodeStateCorrupt, "creating keystore directory", err)
	}
	// Re-tighten in case the dirs pre-existed with looser bits (umask/out-of-band).
	_ = chmodOwnerOnlyDir(s.dir)
	_ = chmodOwnerOnlyDir(s.walletsDir())
	return nil
}

// writeFile atomically writes a keystore data file at 0600, mapping a read-only
// target to keystore.read_only.
func (s *Store) writeFile(path string, data []byte) error {
	if err := fsx.WriteAtomic(path, data, 0o600); err != nil {
		if fsx.IsReadOnly(err) {
			return errKeys(CodeKeystoreReadOnly, "keystore is read-only")
		}
		return errWrap(CodeStateCorrupt, "writing keystore file", err)
	}
	return nil
}

// checkPerms enforces the §7.9 secure-perms rule on a keystore file, mapping a
// missing file to nil (callers handle not-exist separately) and surfacing
// insecure perms as keystore.perms_insecure.
func (s *Store) checkPerms(path string) error {
	err := fsx.CheckPerms(path)
	if err == nil {
		return nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
