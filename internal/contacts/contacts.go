// Package contacts is daxib's local address book (a state-class provider leaf):
// a name→{address,label,network} registry the cli/mcp surfaces resolve a `tx send
// --to <name>` / `policy allow <name>` against (the Bitcoin sibling of daxie's
// internal/registry contacts). It is the simplest possible store — one JSON file
// in the state dir, owner-only, rewritten atomically under a flock — and validates
// only the within-book NAME grammar + duplicate rule. The ADDRESS is validated
// (bech32, for-network) by the service before Add is called, because the contacts
// leaf may not import btcutil-class network logic that lives above it; the service
// is the one place that legally knows the active network's chain params.
//
// contacts is a provider leaf: it imports domain (the error taxonomy) and fsx
// (atomic write, lock, perms) — never service, a frontend, or another provider. It
// holds no long-lived fd: every operation opens, (for mutations) locks, reads,
// writes, releases, so concurrent daxib processes serialize on the registry flock.
package contacts

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/fsx"
)

// schemaVersion is the on-disk schema version. A file with a higher version is
// refused (a newer binary wrote it) — fail closed rather than silently drop a
// field a future schema added.
const schemaVersion = 1

// fileMode / dirMode are the owner-only perms for the contacts file + its parent
// (a state-class registry, §7.9 posture). The book holds no secrets, but the
// state class is owner-only by default like the keystore/config.
const (
	fileMode os.FileMode = 0o600
	dirMode  os.FileMode = 0o700
)

// fileName is the contacts file inside the registry dir.
const fileName = "contacts.json"

// lockTimeout bounds the registry-lock acquisition for a mutation.
const lockTimeout = 15 * time.Second

// Contact is one address-book entry. Name follows the wallet-name grammar
// (lowercased, matched case-insensitively); Address is a raw, already-validated
// Bitcoin address; Network records the network it is valid for (a contact is
// network-specific — a bc1 mainnet address is meaningless on testnet); Label is an
// optional operator note; CreatedAt is the RFC3339 add time.
type Contact struct {
	Name      string `json:"name"`
	Address   string `json:"address"`
	Network   string `json:"network,omitempty"`
	Label     string `json:"label,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
}

// contactsFile is the on-disk envelope: {"v":1,"contacts":[…]}.
type contactsFile struct {
	V        int       `json:"v"`
	Contacts []Contact `json:"contacts"`
}

// Store is the contacts registry rooted at a registry DIRECTORY (the state class).
// It binds no fd: every op opens the file, (for mutations) takes the flock,
// read-modify-writes, releases.
type Store struct {
	dir  string
	path string
}

// Open binds to <dir>/contacts.json. Lazy: it creates nothing on disk; a missing
// file reads as empty (a fresh install). dir is the resolved state directory.
func Open(dir string) (*Store, error) {
	if dir == "" {
		return nil, domain.New("state.corrupt", "no state directory configured for contacts")
	}
	return &Store{dir: dir, path: filepath.Join(dir, fileName)}, nil
}

// Add writes a name→address entry under the registry lock via fsx.WriteAtomic. It
// canonicalizes + validates the NAME grammar (usage.* exit 2 on a bad name); a
// duplicate name (case-insensitive) is usage.duplicate (exit 2); a read-only mount
// maps to config.read_only's state-class sibling (exit 10). The ADDRESS is assumed
// already-validated by the caller (the service, which owns the network params).
func (s *Store) Add(ctx context.Context, c Contact) (Contact, error) {
	canon, err := canonicalName(c.Name)
	if err != nil {
		return Contact{}, err
	}
	c.Name = canon
	var added Contact
	werr := s.mutate(ctx, func(f *contactsFile) error {
		for _, existing := range f.Contacts {
			if existing.Name == canon {
				return domain.Newf(domain.CodeUsage+".duplicate",
					"a contact named %q already exists; remove it first or choose another name", canon)
			}
		}
		f.Contacts = append(f.Contacts, c)
		added = c
		return nil
	})
	if werr != nil {
		return Contact{}, werr
	}
	return added, nil
}

// List returns all contacts, name-sorted. A missing file is an empty list.
func (s *Store) List(ctx context.Context) ([]Contact, error) {
	_ = ctx
	f, err := s.load()
	if err != nil {
		return nil, err
	}
	out := append([]Contact(nil), f.Contacts...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Show returns one contact by name (case-insensitive), or ref.not_found (exit 10).
func (s *Store) Show(ctx context.Context, name string) (Contact, error) {
	_ = ctx
	canon, err := canonicalName(name)
	if err != nil {
		return Contact{}, err
	}
	f, err := s.load()
	if err != nil {
		return Contact{}, err
	}
	for _, ct := range f.Contacts {
		if ct.Name == canon {
			return ct, nil
		}
	}
	return Contact{}, notFound(canon)
}

// Remove deletes a contact by name (case-insensitive) under the registry lock, or
// ref.not_found (exit 10).
func (s *Store) Remove(ctx context.Context, name string) (Contact, error) {
	canon, err := canonicalName(name)
	if err != nil {
		return Contact{}, err
	}
	var removed Contact
	werr := s.mutate(ctx, func(f *contactsFile) error {
		idx := -1
		for i, ct := range f.Contacts {
			if ct.Name == canon {
				idx = i
				removed = ct
				break
			}
		}
		if idx < 0 {
			return notFound(canon)
		}
		f.Contacts = append(f.Contacts[:idx], f.Contacts[idx+1:]...)
		return nil
	})
	if werr != nil {
		return Contact{}, werr
	}
	return removed, nil
}

// Resolve maps a name to its contact (case-insensitive), reporting found. A
// not-found here is NOT an error (found=false, nil): the caller (the service's
// destination resolver) falls through to treat the input as a raw address. A name
// that fails the grammar also resolves as not-found (a raw address that was never a
// contact name still falls through cleanly).
func (s *Store) Resolve(ctx context.Context, name string) (Contact, bool, error) {
	_ = ctx
	canon, err := canonicalName(name)
	if err != nil {
		return Contact{}, false, nil //nolint:nilerr // a bad name is simply "not a contact"; fall through
	}
	f, lerr := s.load()
	if lerr != nil {
		return Contact{}, false, lerr
	}
	for _, ct := range f.Contacts {
		if ct.Name == canon {
			return ct, true, nil
		}
	}
	return Contact{}, false, nil
}

// mutate runs a read-modify-write under the registry flock, lazily creating the
// registry dir (0700) first so the sibling .lock file has a parent.
func (s *Store) mutate(ctx context.Context, fn func(*contactsFile) error) error {
	if err := fsx.MkdirAll(s.dir, dirMode); err != nil {
		if fsx.IsReadOnly(err) {
			return errReadOnly()
		}
		return domain.Wrap("state.corrupt", "cannot create the contacts directory", err)
	}
	lockCtx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()
	unlock, err := fsx.Lock(lockCtx, s.path)
	if err != nil {
		return domain.Wrap("state.lock_timeout", "acquiring the contacts lock: "+err.Error(), err)
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

// load reads and parses contacts.json. A missing file is an empty,
// current-version envelope. A higher on-disk version is refused (fail closed). A
// corrupt file is state.corrupt (exit 11).
func (s *Store) load() (*contactsFile, error) {
	b, err := os.ReadFile(s.path) // #nosec G304 -- operator-configured state path
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &contactsFile{V: schemaVersion}, nil
		}
		return nil, domain.Wrap("state.corrupt", "cannot read the contacts file", err)
	}
	var f contactsFile
	if jerr := json.Unmarshal(b, &f); jerr != nil {
		return nil, domain.Wrap("state.corrupt", "the contacts file is corrupt (not valid JSON)", jerr)
	}
	if f.V > schemaVersion {
		return nil, domain.Newf("state.corrupt",
			"the contacts file is schema version %d, newer than this binary supports (%d); upgrade daxib",
			f.V, schemaVersion)
	}
	return &f, nil
}

// save atomically writes contacts.json (0600). A read-only mount maps to the
// state-class read-only sibling (exit 10). The caller holds the lock.
func (s *Store) save(f *contactsFile) error {
	f.V = schemaVersion
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return domain.Wrap("state.corrupt", "cannot encode the contacts file", err)
	}
	if werr := fsx.WriteAtomic(s.path, b, fileMode); werr != nil {
		if fsx.IsReadOnly(werr) {
			return errReadOnly()
		}
		return domain.Wrap("state.corrupt", "cannot write the contacts file", werr)
	}
	return nil
}

// errReadOnly is the state-class read-only mount error (exit 10, the config.read_only
// sibling).
func errReadOnly() error {
	return domain.New("config.read_only", "the state directory is on a read-only mount")
}

// notFound is the ref.not_found error for a missing contact (exit 10).
func notFound(name string) error {
	return domain.Newf(domain.CodeRefNotFound, "no contact named %q", name)
}

// canonicalName lowercases and validates a contact name. It reuses daxib's
// wallet-name grammar (1..64 chars, [a-z0-9] then [a-z0-9_-]) so a contact name is
// filename/flag-safe and never collides with the address shape (a bech32 address
// contains no uppercase-only requirement, but its length + the reserved '/'-free
// grammar keep names and addresses distinct in a --to position). Stored lowercase,
// matched case-insensitively. Returns a usage.* error (exit 2) for a bad name.
func canonicalName(name string) (string, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "", domain.New(domain.CodeUsage+".empty_name", "contact name is empty")
	}
	lower := strings.ToLower(trimmed)
	if !domain.ValidWalletName(lower) {
		return "", domain.Newf(domain.CodeUsage+".bad_name",
			"invalid contact name %q: use 1-64 chars [a-z0-9_-], starting with a letter or digit", name)
	}
	return lower, nil
}
