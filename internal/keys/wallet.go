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
// the freshly generated mnemonic so the service can display it once). Network /
// PathPrefix / AccountXpub / Receive0Address are for the DISPLAYED coin_type (the
// resolved active/hint network for an agnostic wallet, the bound network for a
// bound one). Scope is "agnostic" or "bound".
type CreateResult struct {
	WalletID        string
	Scope           string
	Network         domain.Network
	PathPrefix      string
	AccountXpub     string
	Receive0Address string
	Mnemonic        *secret.Bytes // nil for import
	BIP39Pass       *secret.Bytes // nil/empty when no passphrase
}

// WalletInfo is the read-only summary surfaced by list/show, rendered against an
// EFFECTIVE network: the bound network for a bound wallet, else the active network
// passed in. Network/PathPrefix/AccountXpub/watermarks/Addresses reflect the
// chain in view; CoinType is that chain's coin_type.
type WalletInfo struct {
	ID          string
	Name        string
	Scope       string
	Network     domain.Network
	CoinType    uint32
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
// and stores the neutered account xpub(s). bind selects the scope: false (default)
// yields an AGNOSTIC wallet (both coin_type chains stored, works on every network);
// true yields a BOUND wallet locked to network. It verifies/initializes the
// keystore passphrase first (one-passphrase-per-keystore). The returned Mnemonic
// is the caller's to zero (display once).
func (s *Store) CreateWallet(ctx context.Context, name string, words int, network domain.Network, bind bool, pass, confirm *secret.Bytes) (CreateResult, error) {
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

		r, err := s.materializeWallet(meta, name, network, bind, []byte(mnemonicStr), nil, pass.Reveal())
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
// 25th-word passphrase (may be nil/empty). bind selects the scope (see
// CreateWallet). mnemonic/bip39 are the caller's to zero. It verifies/initializes
// the keystore passphrase first.
func (s *Store) ImportWallet(ctx context.Context, name string, network domain.Network, bind bool, mnemonic, bip39pass, pass, confirm *secret.Bytes) (CreateResult, error) {
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
		r, err := s.materializeWallet(meta, name, network, bind, []byte(normalized), bipBytes, pass.Reveal())
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

// agnosticNetworks are the two representative networks whose coin_types an
// agnostic wallet stores: mainnet (ct0) and testnet (ct1, shared by every test
// net). Deriving both under the single unlock makes the wallet network-agnostic.
var agnosticNetworks = []domain.Network{domain.NetworkMainnet, domain.NetworkTestnet}

// materializeWallet is the shared create/import core: derive the account key(s) +
// neutered xpub(s), seal the mnemonic blob, materialize the first receive address
// per chain, and write meta. Called under the exclusive lock with a verified
// passphrase. For a BOUND wallet it derives ONLY network's coin_type chain; for an
// AGNOSTIC wallet it derives BOTH coin_type chains. mnemonic / bip39 are the
// caller's to zero (it copies them into the sealed blob). The seed and derived
// keys are zeroed here.
func (s *Store) materializeWallet(meta *metaFile, name string, network domain.Network, bind bool, mnemonic, bip39pass, pass []byte) (CreateResult, error) {
	// Derive the BIP-32 seed from the mnemonic + optional passphrase.
	seed := bip39.NewSeed(string(mnemonic), string(bip39pass))
	defer zeroBytes(seed)

	now := s.now()

	// The networks whose coin_type chains we materialize: one for bound, both for
	// agnostic.
	derivNets := agnosticNetworks
	scope := scopeAgnostic
	if bind {
		derivNets = []domain.Network{network}
		scope = scopeBound
	}

	chains := map[string]*metaChain{}
	for _, dn := range derivNets {
		account, err := deriveAccountKey(seed, dn)
		if err != nil {
			return CreateResult{}, err
		}
		xpub, nerr := neuterToXpub(account)
		account.Zero()
		if nerr != nil {
			return CreateResult{}, nerr
		}
		// First receive address (0/0), encoded in the chain's CANONICAL HRP (dn).
		addr0, aerr := addressFromAccountXpub(xpub, dn, domain.BranchReceive, 0)
		if aerr != nil {
			return CreateResult{}, aerr
		}
		key, kerr := coinKey(dn.CoinType())
		if kerr != nil {
			return CreateResult{}, kerr
		}
		chains[key] = &metaChain{
			AccountXpub: xpub,
			NextReceive: 1, // 0/0 is materialized
			NextChange:  0,
			Addresses: map[string]*metaAddress{
				domain.AddressKey(domain.BranchReceive, 0): {Address: addr0, CreatedAt: now},
			},
		}
	}

	id := uuid.NewString()
	wb, err := s.sealMnemonic(id, mnemonic, bip39pass, pass)
	if err != nil {
		return CreateResult{}, err
	}
	if err := s.saveWalletBlob(wb); err != nil {
		return CreateResult{}, err
	}

	mw := &metaWallet{
		Name:      name,
		CreatedAt: now,
		Scope:     scope,
		Chains:    chains,
	}
	if bind {
		mw.Network = string(network)
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

	// The DISPLAYED coin_type: the bound network for bound; the requested
	// (active/hint) network for agnostic. An AGNOSTIC create with NO resolved network
	// (network == "") has no per-network display: the wallet is fully created (both
	// coin_type chains materialized), but we render no sample address / path / xpub —
	// daxib never silently picks a network just to print one. (Bound create always
	// has a network: the service guards usage.network_required before --bind.)
	if network == "" {
		return CreateResult{
			WalletID:  id,
			Scope:     scope,
			BIP39Pass: bipOut,
		}, nil
	}

	dispNet := network
	dispChain, ok := mw.chain(dispNet)
	if !ok {
		return CreateResult{}, errKeysf(CodeStateCorrupt, "internal: no chain for display network %q", dispNet)
	}
	dispAddr0, derr := addressFromAccountXpub(dispChain.AccountXpub, dispNet, domain.BranchReceive, 0)
	if derr != nil {
		return CreateResult{}, derr
	}

	return CreateResult{
		WalletID:        id,
		Scope:           scope,
		Network:         dispNet,
		PathPrefix:      accountPathPrefix(dispNet),
		AccountXpub:     dispChain.AccountXpub,
		Receive0Address: dispAddr0,
		BIP39Pass:       bipOut,
	}, nil
}

// WalletUpgrade promotes a BOUND (or migrated-legacy) wallet to AGNOSTIC: it
// unlocks once under pass, derives the MISSING coin_type account xpub from the
// seed, adds it as a second chain, sets Scope="agnostic", clears the bound
// Network, and saves. An already-agnostic wallet is a usage error. One-time
// passphrase.
func (s *Store) WalletUpgrade(ctx context.Context, name string, net domain.Network, pass *secret.Bytes) (WalletInfo, error) {
	if verr := s.VerifyPassphrase(pass); verr != nil {
		return WalletInfo{}, verr
	}
	var out WalletInfo
	werr := s.withLock(ctx, func() error {
		meta, err := s.loadMeta()
		if err != nil {
			return err
		}
		wid, w, ok := meta.findWalletByName(name)
		if !ok {
			return errKeysf(CodeWalletNotFound, "no wallet named %q", name)
		}
		if !w.isBound() {
			return errKeysf("usage.already_agnostic", "wallet %q is already network-agnostic", name)
		}

		wb, err := s.loadWalletBlob(wid)
		if err != nil {
			return err
		}
		mnemonic, bip39pass, oerr := s.openMnemonic(wb, pass.Reveal())
		if oerr != nil {
			return oerr
		}
		defer zeroBytes(mnemonic)
		defer zeroBytes(bip39pass)

		seed := bip39.NewSeed(string(mnemonic), string(bip39pass))
		defer zeroBytes(seed)

		now := s.now()
		for _, dn := range agnosticNetworks {
			key, kerr := coinKey(dn.CoinType())
			if kerr != nil {
				return kerr
			}
			if _, present := w.Chains[key]; present {
				continue
			}
			account, derr := deriveAccountKey(seed, dn)
			if derr != nil {
				return derr
			}
			xpub, nerr := neuterToXpub(account)
			account.Zero()
			if nerr != nil {
				return nerr
			}
			addr0, aerr := addressFromAccountXpub(xpub, dn, domain.BranchReceive, 0)
			if aerr != nil {
				return aerr
			}
			w.Chains[key] = &metaChain{
				AccountXpub: xpub,
				NextReceive: 1,
				NextChange:  0,
				Addresses: map[string]*metaAddress{
					domain.AddressKey(domain.BranchReceive, 0): {Address: addr0, CreatedAt: now},
				},
			}
		}
		w.Scope = scopeAgnostic
		w.Network = ""
		if err := s.saveMeta(meta); err != nil {
			return err
		}
		out = walletInfo(wid, w, meta.DefaultWallet, net)
		return nil
	})
	if werr != nil {
		return WalletInfo{}, werr
	}
	return out, nil
}

// ListWallets returns every wallet's read-only summary, sorted by name, rendered
// against the effective network (bound network for a bound wallet, else net).
func (s *Store) ListWallets(ctx context.Context, net domain.Network) ([]WalletInfo, error) {
	meta, err := s.loadMeta()
	if err != nil {
		return nil, err
	}
	out := make([]WalletInfo, 0, len(meta.Wallets))
	for id, w := range meta.Wallets {
		out = append(out, walletInfo(id, w, meta.DefaultWallet, net))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ShowWallet returns one wallet's summary by name, rendered against the effective
// network (bound network for a bound wallet, else net).
func (s *Store) ShowWallet(ctx context.Context, name string, net domain.Network) (WalletInfo, error) {
	meta, err := s.loadMeta()
	if err != nil {
		return WalletInfo{}, err
	}
	id, w, ok := meta.findWalletByName(name)
	if !ok {
		return WalletInfo{}, errKeysf(CodeWalletNotFound, "no wallet named %q", name)
	}
	return walletInfo(id, w, meta.DefaultWallet, net), nil
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

// effectiveNetwork is the network a wallet renders/derives against: the bound
// network for a bound wallet (always its lock target), else the active net.
func (w *metaWallet) effectiveNetwork(net domain.Network) domain.Network {
	if w.isBound() {
		if bn, err := domain.ParseNetwork(w.Network); err == nil {
			return bn
		}
	}
	return net
}

// walletInfo projects a metaWallet to a read-only WalletInfo against the effective
// network. When the effective network's chain is absent (a bound wallet viewed off
// its network should not happen, but be defensive), the chain-derived fields stay
// zero.
func walletInfo(id string, w *metaWallet, defaultName string, net domain.Network) WalletInfo {
	eff := w.effectiveNetwork(net)
	info := WalletInfo{
		ID:         id,
		Name:       w.Name,
		Scope:      w.Scope,
		Network:    eff,
		CoinType:   eff.CoinType(),
		PathPrefix: accountPathPrefix(eff),
		Default:    w.Name == defaultName,
		CreatedAt:  w.CreatedAt,
	}
	if c, ok := w.chain(eff); ok {
		info.AccountXpub = c.AccountXpub
		info.NextReceive = c.NextReceive
		info.NextChange = c.NextChange
		info.Addresses = len(c.Addresses)
	}
	return info
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
