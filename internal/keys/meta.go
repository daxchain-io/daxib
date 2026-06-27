package keys

import (
	"encoding/json"
	"errors"
	"os"
	"strings"

	"github.com/daxchain-io/daxib/internal/domain"
)

const metaFormatVersion = 2

// scope values for a wallet's derivation reach.
const (
	scopeAgnostic = "agnostic" // works on every network (both coin_type chains stored)
	scopeBound    = "bound"    // locked to one network (single coin_type chain stored)
)

// metaAddress is one materialized derived address (cached plaintext so address
// list/show need no passphrase). The cached string is in the chain's CANONICAL
// HRP (bc for ct0, tb for ct1); list/scan RE-ENCODE per active network.
type metaAddress struct {
	Address   string `json:"address"`
	CreatedAt string `json:"created_at"`
}

// metaChain is one coin_type derivation family. account_xpub is the neutered
// account-level (m/84'/coin'/0') xpub; child receive/change addresses derive from
// it WITHOUT the passphrase. next_receive / next_change are the DeriveNext
// watermarks (HRP-agnostic — they advance the same regardless of active network).
// addresses is keyed by "<branch>/<index>" (e.g. "0/0"); the stored string is in
// the chain's CANONICAL HRP (bc for ct0, tb for ct1).
type metaChain struct {
	AccountXpub string                  `json:"account_xpub"`
	NextReceive uint32                  `json:"next_receive"`
	NextChange  uint32                  `json:"next_change"`
	Addresses   map[string]*metaAddress `json:"addresses"`
}

// metaWallet is one wallet's metadata sidecar entry. Scope is "agnostic" (works on
// every network: two chains keyed "0"/"1") or "bound" (locked to Network: one
// chain). Network is set ONLY for a bound wallet (the locked network); it is ""
// for an agnostic wallet. Chains is keyed by decimal coin_type ("0" mainnet, "1"
// all test nets). path_prefix is NOT stored — recompute via accountPathPrefix(net).
type metaWallet struct {
	Name      string                `json:"name"`
	CreatedAt string                `json:"created_at"`
	Scope     string                `json:"scope"`
	Network   string                `json:"network,omitempty"` // bound: the locked network; "" for agnostic
	Chains    map[string]*metaChain `json:"chains"`
}

// metaFile is meta.json: the format version, the default wallet name, and the
// per-uuid wallet map.
type metaFile struct {
	Format        int                    `json:"daxib_meta"`
	DefaultWallet string                 `json:"default_wallet,omitempty"`
	Wallets       map[string]*metaWallet `json:"wallets"`
}

// newMetaFile returns an empty meta with the wallet map initialized.
func newMetaFile() *metaFile {
	return &metaFile{Format: metaFormatVersion, Wallets: map[string]*metaWallet{}}
}

// coinKey maps a coin_type to its decimal chain key. Only 0 (mainnet) and 1 (all
// test nets) are valid; anything else is state.corrupt (meta carries an
// unrepresentable coin_type).
func coinKey(ct uint32) (string, error) {
	switch ct {
	case 0:
		return "0", nil
	case 1:
		return "1", nil
	default:
		return "", errKeysf(CodeStateCorrupt, "unsupported coin_type %d in meta.json", ct)
	}
}

// chain returns the wallet's derivation chain for the network's coin_type. ok is
// false when no chain is stored for that coin_type (a bound wallet off its
// network, or an unmigrated/legacy gap).
func (w *metaWallet) chain(n domain.Network) (*metaChain, bool) {
	key, err := coinKey(n.CoinType())
	if err != nil {
		return nil, false
	}
	c, ok := w.Chains[key]
	return c, ok && c != nil
}

// isBound reports whether the wallet is locked to a single network.
func (w *metaWallet) isBound() bool { return w.Scope == scopeBound }

// loadMeta reads + parses meta.json. Returns a fresh empty meta when the file
// does not exist. A v1 file is migrated IN MEMORY to v2 (bound scope) on read
// (persisted on the next saveMeta); a future (>2) format is state.corrupt.
func (s *Store) loadMeta() (*metaFile, error) {
	b, err := s.readKeystoreFile(s.metaPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return newMetaFile(), nil
		}
		return nil, err
	}
	if perr := s.checkPerms(s.metaPath()); perr != nil {
		return nil, perr
	}

	// Sniff the format first so a v1 file unmarshals into the legacy shape.
	var probe struct {
		Format int `json:"daxib_meta"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return nil, errWrap(CodeStateCorrupt, "meta.json is corrupt", err)
	}

	switch probe.Format {
	case metaFormatVersion:
		var m metaFile
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, errWrap(CodeStateCorrupt, "meta.json is corrupt", err)
		}
		if m.Wallets == nil {
			m.Wallets = map[string]*metaWallet{}
		}
		return &m, nil
	case 1:
		m, merr := migrateV1(b)
		if merr != nil {
			return nil, merr
		}
		return m, nil
	default:
		return nil, errKeysf(CodeStateCorrupt, "unsupported meta format version %d (want %d)", probe.Format, metaFormatVersion)
	}
}

// metaWalletV1 is the legacy (format 1) flat per-wallet entry: network-bound, one
// account_xpub, scalar watermarks + addresses.
type metaWalletV1 struct {
	Name        string                  `json:"name"`
	Network     string                  `json:"network"`
	CreatedAt   string                  `json:"created_at"`
	AccountXpub string                  `json:"account_xpub"`
	NextReceive uint32                  `json:"next_receive"`
	NextChange  uint32                  `json:"next_change"`
	Addresses   map[string]*metaAddress `json:"addresses"`
}

// metaFileV1 is the legacy meta.json wrapper.
type metaFileV1 struct {
	Format        int                      `json:"daxib_meta"`
	DefaultWallet string                   `json:"default_wallet,omitempty"`
	Wallets       map[string]*metaWalletV1 `json:"wallets"`
}

// migrateV1 converts a format-1 meta.json to v2 IN MEMORY. A v1 wallet was
// network-bound, so it becomes a BOUND v2 wallet: its single chain lands under its
// network's coin_type, the other coin_type chain stays ABSENT (a bound wallet
// never needs it). Lossless + passphrase-free. The result is persisted on the next
// saveMeta; the on-read migration applies on every load until then.
func migrateV1(b []byte) (*metaFile, error) {
	var v1 metaFileV1
	if err := json.Unmarshal(b, &v1); err != nil {
		return nil, errWrap(CodeStateCorrupt, "meta.json (v1) is corrupt", err)
	}
	out := &metaFile{
		Format:        metaFormatVersion,
		DefaultWallet: v1.DefaultWallet,
		Wallets:       map[string]*metaWallet{},
	}
	for id, w := range v1.Wallets {
		if w == nil {
			continue
		}
		net, perr := domain.ParseNetwork(w.Network)
		if perr != nil {
			return nil, errKeysf(CodeStateCorrupt, "wallet %q has an unknown network %q in meta.json", w.Name, w.Network)
		}
		key, kerr := coinKey(net.CoinType())
		if kerr != nil {
			return nil, kerr
		}
		out.Wallets[id] = &metaWallet{
			Name:      w.Name,
			CreatedAt: w.CreatedAt,
			Scope:     scopeBound,
			Network:   w.Network,
			Chains: map[string]*metaChain{
				key: {
					AccountXpub: w.AccountXpub,
					NextReceive: w.NextReceive,
					NextChange:  w.NextChange,
					Addresses:   w.Addresses,
				},
			},
		}
	}
	return out, nil
}

// saveMeta atomically writes meta.json (0600).
func (s *Store) saveMeta(m *metaFile) error {
	m.Format = metaFormatVersion
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return errWrap(CodeStateCorrupt, "encoding meta.json", err)
	}
	return s.writeFile(s.metaPath(), b)
}

// findWalletByName returns the uuid + entry for a wallet by name (case-sensitive
// match on the stored lowercase name). ok=false when not found.
func (m *metaFile) findWalletByName(name string) (string, *metaWallet, bool) {
	for id, w := range m.Wallets {
		if w.Name == name {
			return id, w, true
		}
	}
	return "", nil, false
}

// checkWatermark is the restore-coupling tripwire (§3.4): if any materialized
// address index is >= the chain's next_<branch> watermark, meta.json is
// inconsistent with the mnemonic's derivation and the keystore is fail-closed
// (keystore.derivation_watermark). Called on every Open; it iterates every
// coin_type chain of every wallet.
func (m *metaFile) checkWatermark() error {
	for id, w := range m.Wallets {
		for _, c := range w.Chains {
			if c == nil {
				continue
			}
			for key := range c.Addresses {
				branch, idx, ok := parseAddressKey(key)
				if !ok {
					return errKeysf(CodeStateCorrupt, "wallet %q has a non-canonical address key %q in meta.json", w.Name, key)
				}
				next := c.NextReceive
				if branch == domain.BranchChange {
					next = c.NextChange
				}
				if idx >= next {
					return errKeysf(CodeKeystoreDerivationWatermark,
						"keystore meta.json is inconsistent: wallet %q (%s) has a materialized %s index %d but next_%s is %d; "+
							"this keystore may have been restored without its derivation watermark — refusing to risk reusing a derivation index",
						w.Name, id, branchName(branch), idx, branchName(branch), next)
				}
			}
		}
	}
	return nil
}

func branchName(b domain.Branch) string {
	if b == domain.BranchChange {
		return "change"
	}
	return "receive"
}

// parseAddressKey parses a canonical "<branch>/<index>" address key.
func parseAddressKey(key string) (domain.Branch, uint32, bool) {
	i := strings.IndexByte(key, '/')
	if i <= 0 || i == len(key)-1 {
		return 0, 0, false
	}
	b, ok := parseUint32(key[:i])
	if !ok || (b != 0 && b != 1) {
		return 0, 0, false
	}
	idx, ok := parseUint32(key[i+1:])
	if !ok {
		return 0, 0, false
	}
	return domain.Branch(b), idx, true
}

// parseUint32 parses an unsigned decimal with no leading zeros (beyond "0").
func parseUint32(s string) (uint32, bool) {
	if s == "" {
		return 0, false
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, false
	}
	var v uint64
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		v = v*10 + uint64(s[i]-'0')
		if v > 0xFFFFFFFF {
			return 0, false
		}
	}
	return uint32(v), true
}
