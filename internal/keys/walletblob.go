package keys

import (
	"encoding/json"
	"errors"
	"os"
)

const walletBlobVersion = 1

// walletBlob is the on-disk wallets/<uuid>.json: a small header plus the
// AES-256-GCM envelope sealing the mnemonic plaintext.
type walletBlob struct {
	DaxibWallet int      `json:"daxib_wallet"` // walletBlobVersion
	Type        string   `json:"type"`         // "mnemonic"
	ID          string   `json:"id"`           // wallet uuid
	Crypto      envelope `json:"crypto"`
}

// walletPlaintext is the JSON sealed inside the envelope: the NFKD-normalized
// mnemonic SENTENCE (not the seed) and the optional BIP-39 passphrase. Stored as
// the sentence so re-derivation is deterministic and the wallet is portable.
type walletPlaintext struct {
	V               int    `json:"v"`
	Mnemonic        string `json:"mnemonic"`
	BIP39Passphrase string `json:"bip39_passphrase"`
}

// loadWalletBlob reads + parses a wallet blob by uuid.
func (s *Store) loadWalletBlob(id string) (*walletBlob, error) {
	path := s.walletPath(id)
	b, err := s.readKeystoreFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errKeysf(CodeWalletNotFound, "wallet blob %q not found", id)
		}
		return nil, err
	}
	if perr := s.checkPerms(path); perr != nil {
		return nil, perr
	}
	var wb walletBlob
	if err := json.Unmarshal(b, &wb); err != nil {
		return nil, errWrap(CodeStateCorrupt, "wallet blob is corrupt", err)
	}
	return &wb, nil
}

// saveWalletBlob atomically writes a wallet blob (0600).
func (s *Store) saveWalletBlob(wb *walletBlob) error {
	b, err := json.MarshalIndent(wb, "", "  ")
	if err != nil {
		return errWrap(CodeStateCorrupt, "encoding wallet blob", err)
	}
	return s.writeFile(s.walletPath(wb.ID), b)
}

// sealMnemonic builds a wallet blob sealing the mnemonic + bip39 passphrase under
// pass. mnemonic / bip39 are the caller's to zero. The plaintext JSON is zeroed
// here after sealing.
func (s *Store) sealMnemonic(id string, mnemonic, bip39, pass []byte) (*walletBlob, error) {
	pt := walletPlaintext{V: walletBlobVersion, Mnemonic: string(mnemonic), BIP39Passphrase: string(bip39)}
	raw, err := json.Marshal(pt)
	if err != nil {
		return nil, errWrap(CodeStateCorrupt, "encoding wallet plaintext", err)
	}
	defer zeroBytes(raw)

	env, err := seal(raw, pass, s.scryptN())
	if err != nil {
		return nil, err
	}
	return &walletBlob{
		DaxibWallet: walletBlobVersion,
		Type:        "mnemonic",
		ID:          id,
		Crypto:      env,
	}, nil
}

// openMnemonic decrypts a wallet blob under pass, returning the mnemonic + bip39
// passphrase as fresh byte slices the caller MUST zero. The intermediate
// plaintext JSON is zeroed here.
func (s *Store) openMnemonic(wb *walletBlob, pass []byte) (mnemonic, bip39 []byte, err error) {
	raw, err := open(wb.Crypto, pass)
	if err != nil {
		return nil, nil, err
	}
	defer zeroBytes(raw)

	var pt walletPlaintext
	if err := json.Unmarshal(raw, &pt); err != nil {
		return nil, nil, errWrap(CodeStateCorrupt, "decoding wallet plaintext", err)
	}
	mnemonic = []byte(pt.Mnemonic)
	bip39 = []byte(pt.BIP39Passphrase)
	pt.Mnemonic = ""
	pt.BIP39Passphrase = ""
	return mnemonic, bip39, nil
}
