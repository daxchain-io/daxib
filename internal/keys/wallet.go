package keys

import (
	"context"
	"sort"

	"github.com/google/uuid"
	bip39 "github.com/tyler-smith/go-bip39"
	"golang.org/x/text/unicode/norm"

	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/secret"
)

// CreateResult is the outcome of CreateWallet/ImportWallet. The Mnemonic /
// BIP39Pass are owning *secret.Bytes the caller MUST zero (CreateWallet returns
// the freshly generated mnemonic so the service can display it once).
type CreateResult struct {
	WalletID        string
	Network         domain.Network
	PathPrefix      string
	AccountXpub     string
	Receive0Address string
	Mnemonic        *secret.Bytes // nil for import
	BIP39Pass       *secret.Bytes // nil/empty when no passphrase
}

// WalletInfo is the read-only summary surfaced by list/show.
type WalletInfo struct {
	ID          string
	Name        string
	Network     domain.Network
	PathPrefix  string
	AccountXpub string
	NextReceive uint32
	NextChange  uint32
	Addresses   int
	Default     bool
	CreatedAt   string
}

// CreateWallet generates a fresh BIP-39 mnemonic (128 bits for 12 words, 256 for
// 24), encrypts it under pass, derives + records the first receive address (0/0),
// and stores the neutered account xpub. It verifies/initializes the keystore
// passphrase first (one-passphrase-per-keystore). The returned Mnemonic is the
// caller's to zero (display once).
func (s *Store) CreateWallet(ctx context.Context, name string, words int, network domain.Network, pass, confirm *secret.Bytes) (CreateResult, error) {
	if !domain.ValidWalletName(name) {
		return CreateResult{}, errKeysf(CodeUsageInvalidName, "invalid wallet name %q: use 1-64 chars [a-z0-9_-], starting with a letter or digit", name)
	}
	entropyBits, err := entropyForWords(words)
	if err != nil {
		return CreateResult{}, err
	}

	var res CreateResult
	werr := s.withLock(ctx, func() error {
		if err := s.ensureInitialized(pass, confirm); err != nil {
			return err
		}
		meta, err := s.loadMeta()
		if err != nil {
			return err
		}
		if _, _, ok := meta.findWalletByName(name); ok {
			return errKeysf(CodeWalletExists, "a wallet named %q already exists", name)
		}

		entropy, err := bip39.NewEntropy(entropyBits)
		if err != nil {
			return errWrap(CodeStateCorrupt, "generating entropy", err)
		}
		defer zeroBytes(entropy)
		mnemonicStr, err := bip39.NewMnemonic(entropy)
		if err != nil {
			return errWrap(CodeStateCorrupt, "generating mnemonic", err)
		}
		// NFKD-normalize the sentence (BIP-39 §wordlist normalization).
		mnemonicStr = norm.NFKD.String(mnemonicStr)

		r, err := s.materializeWallet(meta, name, network, []byte(mnemonicStr), nil, pass.Reveal())
		if err != nil {
			return err
		}
		r.Mnemonic = secret.NewString(mnemonicStr)
		res = r
		return nil
	})
	if werr != nil {
		return CreateResult{}, werr
	}
	return res, nil
}

// ImportWallet ingests an existing BIP-39 mnemonic (NFKD-normalized, checksum-
// validated — a bad checksum is mnemonic.invalid, exit 2). bip39 is the optional
// 25th-word passphrase (may be nil/empty). mnemonic/bip39 are the caller's to
// zero. It verifies/initializes the keystore passphrase first.
func (s *Store) ImportWallet(ctx context.Context, name string, network domain.Network, mnemonic, bip39pass, pass, confirm *secret.Bytes) (CreateResult, error) {
	if !domain.ValidWalletName(name) {
		return CreateResult{}, errKeysf(CodeUsageInvalidName, "invalid wallet name %q: use 1-64 chars [a-z0-9_-], starting with a letter or digit", name)
	}

	// NFKD-normalize and checksum-validate before touching the keystore.
	normalized := norm.NFKD.String(string(mnemonic.Reveal()))
	if !bip39.IsMnemonicValid(normalized) {
		return CreateResult{}, errKeys(CodeMnemonicInvalid, "the mnemonic failed BIP-39 checksum/wordlist validation")
	}

	var bipBytes []byte
	if bip39pass != nil {
		bipBytes = bip39pass.Reveal()
	}

	var res CreateResult
	werr := s.withLock(ctx, func() error {
		if err := s.ensureInitialized(pass, confirm); err != nil {
			return err
		}
		meta, err := s.loadMeta()
		if err != nil {
			return err
		}
		if _, _, ok := meta.findWalletByName(name); ok {
			return errKeysf(CodeWalletExists, "a wallet named %q already exists", name)
		}
		r, err := s.materializeWallet(meta, name, network, []byte(normalized), bipBytes, pass.Reveal())
		if err != nil {
			return err
		}
		res = r
		return nil
	})
	if werr != nil {
		return CreateResult{}, werr
	}
	return res, nil
}

// materializeWallet is the shared create/import core: derive the account key +
// neutered xpub, seal the mnemonic blob, derive the first receive address, and
// write meta. Called under the exclusive lock with a verified passphrase. mnemonic
// / bip39 are the caller's to zero (it copies them into the sealed blob). The seed
// and derived keys are zeroed here.
func (s *Store) materializeWallet(meta *metaFile, name string, network domain.Network, mnemonic, bip39pass, pass []byte) (CreateResult, error) {
	// Derive the BIP-32 seed from the mnemonic + optional passphrase.
	seed := bip39.NewSeed(string(mnemonic), string(bip39pass))
	defer zeroBytes(seed)

	account, err := deriveAccountKey(seed, network)
	if err != nil {
		return CreateResult{}, err
	}
	defer account.Zero()

	xpub, err := neuterToXpub(account)
	if err != nil {
		return CreateResult{}, err
	}

	// First receive address (0/0).
	addr0, err := addressFromAccountXpub(xpub, network, domain.BranchReceive, 0)
	if err != nil {
		return CreateResult{}, err
	}

	id := uuid.NewString()
	wb, err := s.sealMnemonic(id, mnemonic, bip39pass, pass)
	if err != nil {
		return CreateResult{}, err
	}
	if err := s.saveWalletBlob(wb); err != nil {
		return CreateResult{}, err
	}

	now := s.now()
	mw := &metaWallet{
		Name:        name,
		Network:     string(network),
		CreatedAt:   now,
		PathPrefix:  accountPathPrefix(network),
		AccountXpub: xpub,
		NextReceive: 1, // 0/0 is materialized below
		NextChange:  0,
		Addresses: map[string]*metaAddress{
			domain.AddressKey(domain.BranchReceive, 0): {Address: addr0, CreatedAt: now},
		},
	}
	meta.Wallets[id] = mw
	if meta.DefaultWallet == "" {
		meta.DefaultWallet = name
	}
	if err := s.saveMeta(meta); err != nil {
		return CreateResult{}, err
	}

	var bipOut *secret.Bytes
	if len(bip39pass) > 0 {
		bipOut = secret.NewString(string(bip39pass))
	}
	return CreateResult{
		WalletID:        id,
		Network:         network,
		PathPrefix:      mw.PathPrefix,
		AccountXpub:     xpub,
		Receive0Address: addr0,
		BIP39Pass:       bipOut,
	}, nil
}

// ListWallets returns every wallet's read-only summary, sorted by name.
func (s *Store) ListWallets(ctx context.Context) ([]WalletInfo, error) {
	meta, err := s.loadMeta()
	if err != nil {
		return nil, err
	}
	out := make([]WalletInfo, 0, len(meta.Wallets))
	for id, w := range meta.Wallets {
		out = append(out, walletInfo(id, w, meta.DefaultWallet))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ShowWallet returns one wallet's summary by name.
func (s *Store) ShowWallet(ctx context.Context, name string) (WalletInfo, error) {
	meta, err := s.loadMeta()
	if err != nil {
		return WalletInfo{}, err
	}
	id, w, ok := meta.findWalletByName(name)
	if !ok {
		return WalletInfo{}, errKeysf(CodeWalletNotFound, "no wallet named %q", name)
	}
	return walletInfo(id, w, meta.DefaultWallet), nil
}

// ExportWallet decrypts and returns a wallet's mnemonic + bip39 passphrase as
// owning *secret.Bytes (the caller MUST zero them). It verifies pass freshly
// (operator-only export).
func (s *Store) ExportWallet(ctx context.Context, name string, pass *secret.Bytes) (id string, mnemonic, bip39out *secret.Bytes, err error) {
	if verr := s.VerifyPassphrase(pass); verr != nil {
		return "", nil, nil, verr
	}
	meta, err := s.loadMeta()
	if err != nil {
		return "", nil, nil, err
	}
	wid, _, ok := meta.findWalletByName(name)
	if !ok {
		return "", nil, nil, errKeysf(CodeWalletNotFound, "no wallet named %q", name)
	}
	wb, err := s.loadWalletBlob(wid)
	if err != nil {
		return "", nil, nil, err
	}
	mn, bp, oerr := s.openMnemonic(wb, pass.Reveal())
	if oerr != nil {
		return "", nil, nil, oerr
	}
	return wid, secret.New(mn), secret.New(bp), nil
}

// walletInfo projects a metaWallet to a read-only WalletInfo.
func walletInfo(id string, w *metaWallet, defaultName string) WalletInfo {
	return WalletInfo{
		ID:          id,
		Name:        w.Name,
		Network:     domain.Network(w.Network),
		PathPrefix:  w.PathPrefix,
		AccountXpub: w.AccountXpub,
		NextReceive: w.NextReceive,
		NextChange:  w.NextChange,
		Addresses:   len(w.Addresses),
		Default:     w.Name == defaultName,
		CreatedAt:   w.CreatedAt,
	}
}

// entropyForWords maps a --words value to BIP-39 entropy bits (12 -> 128, 24 ->
// 256). 0 defaults to 12. Anything else is usage.words.
func entropyForWords(words int) (int, error) {
	switch words {
	case 0, 12:
		return 128, nil
	case 24:
		return 256, nil
	default:
		return 0, errKeysf(CodeUsageWords, "--words must be 12 or 24, got %d", words)
	}
}
