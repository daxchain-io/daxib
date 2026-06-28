package keys

import (
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"

	"github.com/daxchain-io/daxib/internal/domain"
)

// BIP-84 derivation (the daxib choice, docs/ARCHITECTURE.md §3.5). Path:
//
//	m / 84' / coin' / 0' / branch / index
//
// coin = 0 for mainnet, 1 for testnet/signet/regtest; branch 0 = receive,
// 1 = change. Addresses are native-SegWit P2WPKH (bech32). The structure here is
// deliberately split so a later BIP-86 (Taproot) milestone can add a second
// address type without reworking the path machinery: deriveAccountKey produces
// the account-level node, neuterToXpub strips it to a watch-only xpub, and
// addressFromAccountXpub turns (xpub, branch, index) into an address — only the
// last step is script-type-specific.

const (
	hdHardened   = hdkeychain.HardenedKeyStart // 0x80000000
	purposeBIP84 = 84
)

// chainParams maps a daxib network to its btcd chaincfg.Params.
func chainParams(n domain.Network) *chaincfg.Params {
	switch n {
	case domain.NetworkMainnet:
		return &chaincfg.MainNetParams
	case domain.NetworkTestnet:
		return &chaincfg.TestNet3Params
	case domain.NetworkTestnet4:
		return &chaincfg.TestNet4Params
	case domain.NetworkSignet:
		return &chaincfg.SigNetParams
	case domain.NetworkRegtest:
		return &chaincfg.RegressionNetParams
	default:
		return &chaincfg.MainNetParams
	}
}

// accountPathPrefix renders the account-level BIP-84 path for the network, e.g.
// "m/84'/0'/0'" on mainnet.
func accountPathPrefix(n domain.Network) string {
	return "m/84'/" + domain.IndexString(n.CoinType()) + "'/0'"
}

// fullPath renders the complete leaf path, e.g. "m/84'/0'/0'/0/5".
func fullPath(n domain.Network, branch domain.Branch, index uint32) string {
	return accountPathPrefix(n) + "/" + branch.String() + "/" + domain.IndexString(index)
}

// deriveAccountKey derives the BIP-84 account-level extended PRIVATE key
// (m/84'/coin'/0') from a BIP-39 seed for the given network. The returned key
// must be Zero()'d by the caller after neutering. The intermediate purpose/coin
// nodes are zeroed here.
func deriveAccountKey(seed []byte, n domain.Network) (*hdkeychain.ExtendedKey, error) {
	params := chainParams(n)
	master, err := hdkeychain.NewMaster(seed, params)
	if err != nil {
		return nil, errWrap(CodeStateCorrupt, "deriving master key", err)
	}
	defer master.Zero()

	purpose, err := master.Derive(hdHardened + purposeBIP84)
	if err != nil {
		return nil, errWrap(CodeStateCorrupt, "deriving purpose node", err)
	}
	defer purpose.Zero()

	coin, err := purpose.Derive(hdHardened + n.CoinType())
	if err != nil {
		return nil, errWrap(CodeStateCorrupt, "deriving coin node", err)
	}
	defer coin.Zero()

	account, err := coin.Derive(hdHardened + 0)
	if err != nil {
		return nil, errWrap(CodeStateCorrupt, "deriving account node", err)
	}
	return account, nil
}

// neuterToXpub strips an account-level extended private key to its neutered
// watch-only xpub string (the value stored in meta.account_xpub). The xpub lets
// address new/list derive child addresses without the passphrase.
func neuterToXpub(account *hdkeychain.ExtendedKey) (string, error) {
	pub, err := account.Neuter()
	if err != nil {
		return "", errWrap(CodeStateCorrupt, "neutering account key", err)
	}
	defer pub.Zero()
	return pub.String(), nil
}

// addressFromAccountXpub derives the P2WPKH bech32 address at
// (account_xpub)/branch/index for the network. It needs no private key — only the
// stored neutered xpub — so address new/list run without a passphrase (§3.5).
func addressFromAccountXpub(xpub string, n domain.Network, branch domain.Branch, index uint32) (string, error) {
	params := chainParams(n)
	acct, err := hdkeychain.NewKeyFromString(xpub)
	if err != nil {
		return "", errWrap(CodeStateCorrupt, "parsing account xpub", err)
	}
	defer acct.Zero()

	branchKey, err := acct.Derive(uint32(branch))
	if err != nil {
		return "", errWrap(CodeStateCorrupt, "deriving branch node", err)
	}
	defer branchKey.Zero()

	leaf, err := branchKey.Derive(index)
	if err != nil {
		return "", errWrap(CodeStateCorrupt, "deriving address node", err)
	}
	defer leaf.Zero()

	pubKey, err := leaf.ECPubKey()
	if err != nil {
		return "", errWrap(CodeStateCorrupt, "extracting public key", err)
	}
	// P2WPKH (BIP-84): hash160(compressed pubkey) -> witness-v0 program -> bech32.
	witnessProg := btcutil.Hash160(pubKey.SerializeCompressed())
	addr, err := btcutil.NewAddressWitnessPubKeyHash(witnessProg, params)
	if err != nil {
		return "", errWrap(CodeStateCorrupt, "building p2wpkh address", err)
	}
	return addr.EncodeAddress(), nil
}
