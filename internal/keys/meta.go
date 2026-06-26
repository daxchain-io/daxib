package keys

import (
	"encoding/json"
	"errors"
	"os"
	"strings"

	"github.com/daxchain-io/daxib/internal/domain"
)

const metaFormatVersion = 1

// metaAddress is one materialized derived address (cached plaintext so address
// list/show need no passphrase).
type metaAddress struct {
	Address   string `json:"address"`
	CreatedAt string `json:"created_at"`
}

// metaWallet is one wallet's metadata sidecar entry. account_xpub is the neutered
// account-level (m/84'/coin'/0') xpub: child receive/change addresses derive from
// it WITHOUT the passphrase. next_receive / next_change are the DeriveNext
// watermarks. addresses is keyed by "<branch>/<index>" (e.g. "0/0").
type metaWallet struct {
	Name        string                  `json:"name"`
	Network     string                  `json:"network"`
	CreatedAt   string                  `json:"created_at"`
	PathPrefix  string                  `json:"path_prefix"`  // "m/84'/coin'/0'"
	AccountXpub string                  `json:"account_xpub"` // neutered account-level xpub
	NextReceive uint32                  `json:"next_receive"`
	NextChange  uint32                  `json:"next_change"`
	Addresses   map[string]*metaAddress `json:"addresses"`
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

// loadMeta reads + parses meta.json. Returns a fresh empty meta when the file
// does not exist.
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
	var m metaFile
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, errWrap(CodeStateCorrupt, "meta.json is corrupt", err)
	}
	if m.Format != metaFormatVersion {
		return nil, errKeysf(CodeStateCorrupt, "unsupported meta format version %d (want %d)", m.Format, metaFormatVersion)
	}
	if m.Wallets == nil {
		m.Wallets = map[string]*metaWallet{}
	}
	return &m, nil
}

// saveMeta atomically writes meta.json (0600).
func (s *Store) saveMeta(m *metaFile) error {
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
// address index is >= the wallet's next_<branch> watermark, meta.json is
// inconsistent with the mnemonic's derivation and the keystore is fail-closed
// (keystore.derivation_watermark). Called on every Open.
func (m *metaFile) checkWatermark() error {
	for id, w := range m.Wallets {
		for key := range w.Addresses {
			branch, idx, ok := parseAddressKey(key)
			if !ok {
				return errKeysf(CodeStateCorrupt, "wallet %q has a non-canonical address key %q in meta.json", w.Name, key)
			}
			next := w.NextReceive
			if branch == domain.BranchChange {
				next = w.NextChange
			}
			if idx >= next {
				return errKeysf(CodeKeystoreDerivationWatermark,
					"keystore meta.json is inconsistent: wallet %q (%s) has a materialized %s index %d but next_%s is %d; "+
						"this keystore may have been restored without its derivation watermark — refusing to risk reusing a derivation index",
					w.Name, id, branchName(branch), idx, branchName(branch), next)
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
