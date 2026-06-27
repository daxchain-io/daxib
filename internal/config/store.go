package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/fsx"
)

// configMode is the permission for a freshly written config file. The file holds
// only ${env:}/${file:} REFERENCES (never resolved secrets), but is owner-only by
// default per the §7.9 posture.
const configMode os.FileMode = 0o600

// configDirMode is the permission for the lazily-created config DIRECTORY (the
// config STATE CLASS, mirroring daxie's ConfigDir): owner-only by default (§7.9).
const configDirMode os.FileMode = 0o700

// configFileName is the file inside the config DIR that holds the backend store.
// The config dir is a state class (like daxie's): it holds config.toml today and,
// on the forward path, the sealed policy-anchor.json — so DAXIB_CONFIG / --config
// denote the DIRECTORY, not this file.
const configFileName = "config.toml"

// lockTimeout bounds config.lock acquisition.
const lockTimeout = 15 * time.Second

// Store is an open config store rooted at a config DIRECTORY (the config state
// class). Reads load <dir>/config.toml lazily; mutations create the dir (0700) if
// needed, take the config.lock sidecar, and rewrite atomically.
type Store struct {
	dir  string
	path string // <dir>/config.toml
}

// Open returns a Store rooted at the config DIRECTORY dir. dir need not exist (a
// fresh install); it (and config.toml inside it) are created lazily on the first
// mutation. This mirrors daxie's ConfigDir state class — the directory holds
// config.toml today and the sealed policy anchor on the forward path.
func Open(dir string) (*Store, error) {
	if dir == "" {
		return nil, domain.New("config.not_found", "no config directory configured")
	}
	return &Store{dir: dir, path: filepath.Join(dir, configFileName)}, nil
}

// load reads + parses the config file, returning an empty File when it does not
// exist (the fresh-install case).
func (s *Store) load() (*File, error) {
	b, err := os.ReadFile(s.path) // #nosec G304 -- operator-configured config path
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &File{Schema: SchemaVersion, Backends: map[string]Endpoint{}, Networks: map[string]NetworkConfig{}}, nil
		}
		return nil, domain.Wrap("config.read_only", "reading config "+s.path+": "+err.Error(), err)
	}
	if perr := fsx.CheckPerms(s.path); perr != nil {
		return nil, perr
	}
	var f File
	if uerr := toml.Unmarshal(b, &f); uerr != nil {
		return nil, domain.Wrap("config.invalid", "config "+s.path+" is malformed TOML: "+uerr.Error(), uerr)
	}
	if f.Backends == nil {
		f.Backends = map[string]Endpoint{}
	}
	if f.Networks == nil {
		f.Networks = map[string]NetworkConfig{}
	}
	return &f, nil
}

// save atomically writes config.toml under the config.lock sidecar. The config
// DIRECTORY is provisioned by mutate (before the lock) so the sibling .lock file
// has a parent dir; save only writes the data file.
func (s *Store) save(f *File) error {
	f.Schema = SchemaVersion
	data, err := toml.Marshal(f)
	if err != nil {
		return domain.Wrap("config.invalid", "encoding config: "+err.Error(), err)
	}
	if err := fsx.WriteAtomic(s.path, data, configMode); err != nil {
		if fsx.IsReadOnly(err) {
			return domain.Wrap("config.read_only", "config "+s.path+" is on a read-only mount", err)
		}
		return domain.Wrap("config.invalid", "writing "+s.path+": "+err.Error(), err)
	}
	return nil
}

// mutate runs a read-modify-write transaction under the config.lock sidecar. It
// lazily creates the config DIRECTORY (0700) FIRST — both so the sibling .lock
// file has a parent dir (fsx.Lock requires it) and so the dir is provisioned on
// the first write, mirroring the keystore dir handling.
func (s *Store) mutate(ctx context.Context, fn func(*File) error) error {
	if mkErr := fsx.MkdirAll(s.dir, configDirMode); mkErr != nil {
		if fsx.IsReadOnly(mkErr) {
			return domain.Wrap("config.read_only", "config dir "+s.dir+" is on a read-only mount", mkErr)
		}
		return domain.Wrap("config.invalid", "creating config dir "+s.dir+": "+mkErr.Error(), mkErr)
	}
	lockCtx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()
	unlock, err := fsx.Lock(lockCtx, s.path)
	if err != nil {
		return domain.Wrap("state.lock_timeout", "acquiring config lock: "+err.Error(), err)
	}
	defer unlock()

	f, err := s.load()
	if err != nil {
		return err
	}
	if err := fn(f); err != nil {
		return err
	}
	return s.save(f)
}

// AddEndpoint adds a named endpoint bound to a network. It rejects an invalid
// name, a duplicate, an empty url/network/type, and runs the literal-secret
// heuristic (a warning unless strict). The url + auth values are stored RAW.
func (s *Store) AddEndpoint(ctx context.Context, name string, e Endpoint, strictSecrets bool) (warnings []string, err error) {
	if !validName(name) {
		return nil, domain.Newf(domain.CodeUsage+".invalid_name",
			"invalid backend name %q: use 1-64 chars [a-z0-9_-], starting with a letter or digit", name)
	}
	if e.Network == "" {
		return nil, domain.Newf(domain.CodeUsage+".bad_value", "backend %q requires --network", name)
	}
	if e.Type == "" {
		return nil, domain.Newf(domain.CodeUsage+".bad_value", "backend %q requires --type (core|esplora)", name)
	}
	if e.URLRef == "" {
		return nil, domain.Newf(domain.CodeUsage+".bad_value", "backend %q requires --url", name)
	}

	if hits := detectLiteralSecret(e); len(hits) > 0 {
		if strictSecrets {
			return nil, domain.WithData(
				domain.Newf(domain.CodeUsage+".literal_secret",
					"backend %q appears to embed a literal secret (%s); use a ${env:}/${file:} reference, or drop --strict-secrets",
					name, joinComma(hits)),
				map[string]any{"locations": hits})
		}
		for _, h := range hits {
			warnings = append(warnings, "backend "+name+": "+h+
				" looks like a literal secret; it will be stored in config plaintext — prefer a ${env:}/${file:} reference")
		}
	}

	merr := s.mutate(ctx, func(f *File) error {
		if _, exists := f.Backends[name]; exists {
			return domain.Newf(domain.CodeBackendExists, "backend %q already exists", name)
		}
		f.Backends[name] = e
		return nil
	})
	if merr != nil {
		return nil, merr
	}
	return warnings, nil
}

// ListEndpoints returns every endpoint (masked), optionally filtered to one
// network, sorted by name, with the default marker set.
func (s *Store) ListEndpoints(network string) ([]EndpointView, error) {
	f, err := s.load()
	if err != nil {
		return nil, err
	}
	out := make([]EndpointView, 0, len(f.Backends))
	for name, e := range f.Backends {
		if network != "" && e.Network != network {
			continue
		}
		out = append(out, f.view(name, e))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// GetEndpoint returns one endpoint by name (RAW refs intact, for the service to
// resolve at dial time). backend.not_found when unknown.
func (s *Store) GetEndpoint(name string) (Endpoint, error) {
	f, err := s.load()
	if err != nil {
		return Endpoint{}, err
	}
	e, ok := f.Backends[name]
	if !ok {
		return Endpoint{}, domain.Newf(domain.CodeBackendNotFound, "no backend named %q", name)
	}
	return e, nil
}

// DefaultNetwork returns the PERSISTED active-network default (defaults.network),
// or "" when none is set. This is the third rung of the network-resolution ladder
// (--network > DAXIB_NETWORK > defaults.network > unresolved); the service reads it
// at Open when no flag/env network was supplied. A missing config file is "".
func (s *Store) DefaultNetwork() (string, error) {
	f, err := s.load()
	if err != nil {
		return "", err
	}
	return f.Defaults.Network, nil
}

// DefaultForNetwork returns the name of the network's default backend, or "" when
// none is set.
func (s *Store) DefaultForNetwork(network string) (string, error) {
	f, err := s.load()
	if err != nil {
		return "", err
	}
	return f.Networks[network].DefaultBackend, nil
}

// UseEndpoint makes an endpoint the default for ITS network. backend.not_found
// when unknown.
func (s *Store) UseEndpoint(ctx context.Context, name string) (network string, err error) {
	merr := s.mutate(ctx, func(f *File) error {
		e, ok := f.Backends[name]
		if !ok {
			return domain.Newf(domain.CodeBackendNotFound, "no backend named %q", name)
		}
		network = e.Network
		nc := f.Networks[e.Network]
		nc.DefaultBackend = name
		f.Networks[e.Network] = nc
		return nil
	})
	if merr != nil {
		return "", merr
	}
	return network, nil
}

// RemoveEndpoint removes an endpoint and clears any network default pointing at
// it. Returns the network whose default it cleared (if any).
func (s *Store) RemoveEndpoint(ctx context.Context, name string) (clearedFor string, err error) {
	merr := s.mutate(ctx, func(f *File) error {
		if _, ok := f.Backends[name]; !ok {
			return domain.Newf(domain.CodeBackendNotFound, "no backend named %q", name)
		}
		delete(f.Backends, name)
		for netName, nc := range f.Networks {
			if nc.DefaultBackend == name {
				nc.DefaultBackend = ""
				f.Networks[netName] = nc
				clearedFor = netName
			}
		}
		return nil
	})
	if merr != nil {
		return "", merr
	}
	return clearedFor, nil
}

// view builds the masked render shape for one endpoint.
func (f *File) view(name string, e Endpoint) EndpointView {
	v := EndpointView{
		Name:    name,
		Network: e.Network,
		Type:    e.Type,
		URL:     MaskSecretRefs(e.URLRef),
	}
	if f.Networks[e.Network].DefaultBackend == name {
		v.Default = true
	}
	return v
}

// joinComma joins hits with ", " (a tiny strings.Join to keep the dependency set
// flat in the message path).
func joinComma(hits []string) string {
	out := ""
	for i, h := range hits {
		if i > 0 {
			out += ", "
		}
		out += h
	}
	return out
}
