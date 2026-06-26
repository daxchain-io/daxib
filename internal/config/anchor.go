package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/fsx"
)

// anchorFileName is the sealed policy trust root inside the config DIRECTORY. It is
// CONFIG class (like config.toml) but is NOT TOML and is NOT reachable through any
// DAXIB_* env var or flag: it is read DIRECTLY here by file path so a compromised
// agent cannot inject a verify key from its own environment and "outvote" the admin
// passphrase. The agent could otherwise pair a self-forged policy.json with a
// self-generated key and sign anything.
const anchorFileName = "policy-anchor.json"

// anchorLockTimeout bounds policy-anchor.lock acquisition (maps to
// state.lock_timeout, exit 11).
const anchorLockTimeout = 15 * time.Second

// AnchorReader reads/writes the policy anchor rooted at a config DIRECTORY. It is
// deliberately a tiny standalone type (not the backend Store) so the anchor path is
// derived ONLY from the resolved config dir — there is no TOML key, no env var, and
// no flag that names the anchor file. The service constructs it from the same
// config dir as the backend store.
type AnchorReader struct {
	dir  string
	path string
}

// OpenAnchor returns an AnchorReader rooted at the config DIRECTORY dir. dir need
// not exist (a fresh, pre-bootstrap install); the anchor file is created lazily by
// WriteAnchor on the first `policy set`.
func OpenAnchor(dir string) (*AnchorReader, error) {
	if dir == "" {
		return nil, domain.New("config.not_found", "no config directory configured for the policy anchor")
	}
	return &AnchorReader{dir: dir, path: filepath.Join(dir, anchorFileName)}, nil
}

// Path is the resolved anchor file path (<configDir>/policy-anchor.json). It is a
// pure join of the config dir and the fixed file name — NO env/flag can change it.
func (a *AnchorReader) Path() string { return a.path }

// ReadAnchor reads the raw anchor bytes under a shared lock.
//
//   - (bytes, true, nil)  — the anchor exists and was read.
//   - (nil, false, nil)   — no anchor yet (the opt-in / pre-bootstrap case; NOT an
//     error: with no anchor AND no policy.json the engine is permissive).
//   - (nil, false, err)   — a genuine read/lock failure (fail closed).
func (a *AnchorReader) ReadAnchor(ctx context.Context) (raw []byte, found bool, err error) {
	if _, statErr := os.Stat(a.path); statErr != nil {
		if errors.Is(statErr, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, domain.Wrap("config.read_only", "stat policy anchor "+a.path+": "+statErr.Error(), statErr)
	}
	lockCtx, cancel := context.WithTimeout(ctx, anchorLockTimeout)
	defer cancel()
	unlock, lerr := fsx.RLock(lockCtx, a.path)
	if lerr != nil {
		return nil, false, domain.Wrap("state.lock_timeout", "acquiring policy-anchor read lock: "+lerr.Error(), lerr)
	}
	defer unlock()

	b, rerr := os.ReadFile(a.path) // #nosec G304 -- the anchor path is a fixed join of the operator-configured config dir
	if rerr != nil {
		if errors.Is(rerr, os.ErrNotExist) {
			// Raced with a delete between Stat and ReadFile — treat as not-found.
			return nil, false, nil
		}
		return nil, false, domain.Wrap("config.read_only", "reading policy anchor "+a.path+": "+rerr.Error(), rerr)
	}
	return b, true, nil
}

// WriteAnchor writes raw atomically under an exclusive lock, creating the config
// directory (0700) lazily. A read-only mount (the K8s ConfigMap case) returns
// config.read_only so the caller can fall back to emitting the anchor JSON to
// stdout / --anchor-out for an out-of-band land.
func (a *AnchorReader) WriteAnchor(ctx context.Context, raw []byte) error {
	if err := fsx.MkdirAll(a.dir, configDirMode); err != nil {
		if fsx.IsReadOnly(err) {
			return domain.Wrap("config.read_only", "config dir "+a.dir+" is on a read-only mount", err)
		}
		return domain.Wrap("config.invalid", "creating config dir "+a.dir+": "+err.Error(), err)
	}
	lockCtx, cancel := context.WithTimeout(ctx, anchorLockTimeout)
	defer cancel()
	unlock, lerr := fsx.Lock(lockCtx, a.path)
	if lerr != nil {
		return domain.Wrap("state.lock_timeout", "acquiring policy-anchor write lock: "+lerr.Error(), lerr)
	}
	defer unlock()

	if err := fsx.WriteAtomic(a.path, raw, configMode); err != nil {
		if fsx.IsReadOnly(err) {
			return domain.Wrap("config.read_only", "policy anchor "+a.path+" is on a read-only mount", err)
		}
		return domain.Wrap("config.invalid", "writing policy anchor "+a.path+": "+err.Error(), err)
	}
	return nil
}

// AnchorIsReadOnly reports whether err is the read-only-mount class, so a caller can
// branch to the --anchor-out fallback instead of failing the mutation.
func AnchorIsReadOnly(err error) bool {
	if err == nil {
		return false
	}
	return domain.AsError(err).Code == "config.read_only"
}
