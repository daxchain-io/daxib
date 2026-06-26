package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"

	"golang.org/x/crypto/scrypt"
)

// ── DELIBERATE DIVERGENCE FROM daxie ─────────────────────────────────────────
//
// daxie encrypts its keystore secrets with the geth "Web3 Secret Storage v3"
// envelope (AES-128-CTR + a Keccak-256 MAC), because daxie already depends on
// go-ethereum for everything else and reuses its EncryptDataV3/DecryptDataV3.
//
// daxib does NOT depend on go-ethereum (it would drag the entire EVM stack and a
// cgo-flavored dependency tree into a pure-Bitcoin wallet). So daxib diverges,
// on purpose, to a standard-library AEAD composition:
//
//   scrypt(passphrase, salt) -> 32-byte key
//   aes.NewCipher(key)       -> AES-256 block cipher
//   cipher.NewGCM(block)     -> AES-256-GCM AEAD
//   gcm.Seal(nonce, ...)     -> ciphertext authenticated by GCM's tag
//
// This is NOT hand-rolled crypto: it is the textbook crypto/cipher AEAD pattern.
// AES-256-GCM authenticates the ciphertext via its built-in tag, so there is no
// separate MAC to get wrong (the v3 envelope needs an explicit Keccak MAC that a
// hand-port could easily mis-order). A wrong passphrase, a flipped bit, or a
// truncated file all fail Open with the same authentication error, which we map
// to keystore.bad_passphrase. The on-disk envelope shape is daxib's own (cipher:
// "aes-256-gcm"); it is intentionally not geth-v3-compatible.
//
// ─────────────────────────────────────────────────────────────────────────────

const (
	// scryptR / scryptDKLen are fixed by the design (32-byte derived key feeds
	// AES-256). scryptN/scryptP vary by light/standard (see kdf.go).
	scryptR     = 8
	scryptP     = 1
	scryptDKLen = 32
	saltLen     = 32 // 32-byte random salt per file (§3.4)
	nonceLen    = 12 // AES-GCM standard nonce
	cipherName  = "aes-256-gcm"
	kdfName     = "scrypt"
)

// kdfParams is the per-file scrypt parameter block, persisted in every envelope
// (all values hex where binary). N is the scrypt cost; salt is unique per file.
type kdfParams struct {
	N     int    `json:"n"`
	R     int    `json:"r"`
	P     int    `json:"p"`
	DKLen int    `json:"dklen"`
	Salt  string `json:"salt"` // hex, 32 bytes
}

// envelope is daxib's on-disk encrypted-secret shape (the divergence from geth
// v3). Every hex field is lowercase hex.
type envelope struct {
	KDF        string    `json:"kdf"` // "scrypt"
	KDFParams  kdfParams `json:"kdfparams"`
	Cipher     string    `json:"cipher"`     // "aes-256-gcm"
	Nonce      string    `json:"nonce"`      // hex, 12 bytes
	Ciphertext string    `json:"ciphertext"` // hex (plaintext+GCM tag)
}

// seal derives a key from pass via scrypt (cost n) and AES-256-GCM-seals plaintext
// into a fresh envelope with a random 32-byte salt and 12-byte nonce. plaintext is
// the caller's to zero; seal does not retain it.
func seal(plaintext, pass []byte, n int) (envelope, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return envelope{}, errWrap(CodeStateCorrupt, "generating keystore salt", err)
	}
	dk, err := scrypt.Key(pass, salt, n, scryptR, scryptP, scryptDKLen)
	if err != nil {
		return envelope{}, errWrap(CodeStateCorrupt, "scrypt key derivation", err)
	}
	defer zeroBytes(dk)

	block, err := aes.NewCipher(dk)
	if err != nil {
		return envelope{}, errWrap(CodeStateCorrupt, "aes cipher", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return envelope{}, errWrap(CodeStateCorrupt, "aes-gcm", err)
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return envelope{}, errWrap(CodeStateCorrupt, "generating gcm nonce", err)
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)

	return envelope{
		KDF: kdfName,
		KDFParams: kdfParams{
			N: n, R: scryptR, P: scryptP, DKLen: scryptDKLen,
			Salt: hex.EncodeToString(salt),
		},
		Cipher:     cipherName,
		Nonce:      hex.EncodeToString(nonce),
		Ciphertext: hex.EncodeToString(ct),
	}, nil
}

// open inverts seal: it re-derives the scrypt key from pass + the envelope's salt
// and AES-256-GCM-opens the ciphertext. A wrong passphrase (or any tamper) fails
// the GCM tag check and is returned as keystore.bad_passphrase. The returned
// plaintext is the caller's to zero.
func open(env envelope, pass []byte) ([]byte, error) {
	if env.Cipher != cipherName {
		return nil, errKeysf(CodeStateCorrupt, "unsupported cipher %q in keystore envelope", env.Cipher)
	}
	if env.KDF != kdfName {
		return nil, errKeysf(CodeStateCorrupt, "unsupported kdf %q in keystore envelope", env.KDF)
	}
	// Validate the KDF cost params against the fixed allowed set BEFORE deriving, so
	// a tampered/corrupt file presenting an attacker-chosen cost can never drive
	// scrypt with arbitrary (and possibly huge) work. r/p/dklen are constants;
	// N is only ever the standard or light cost. daxib is a deliberate divergence
	// from geth's uncapped DecryptDataV3 and is stricter here (fail cheap).
	if err := validateKDFParams(env.KDFParams); err != nil {
		return nil, err
	}
	salt, err := hex.DecodeString(env.KDFParams.Salt)
	if err != nil || len(salt) != saltLen {
		return nil, errKeys(CodeStateCorrupt, "keystore envelope has a malformed salt")
	}
	nonce, err := hex.DecodeString(env.Nonce)
	if err != nil || len(nonce) != nonceLen {
		return nil, errKeys(CodeStateCorrupt, "keystore envelope has a malformed nonce")
	}
	ct, err := hex.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, errKeys(CodeStateCorrupt, "keystore envelope has a malformed ciphertext")
	}
	dk, err := scrypt.Key(pass, salt, env.KDFParams.N, env.KDFParams.R, env.KDFParams.P, env.KDFParams.DKLen)
	if err != nil {
		return nil, errWrap(CodeStateCorrupt, "scrypt key derivation", err)
	}
	defer zeroBytes(dk)

	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, errWrap(CodeStateCorrupt, "aes cipher", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errWrap(CodeStateCorrupt, "aes-gcm", err)
	}
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		// A GCM authentication failure is, by construction, "the key derived from
		// this passphrase does not decrypt this file" — i.e. the wrong passphrase
		// (or tampered ciphertext). Both map to the same fail-fast auth error.
		return nil, errKeys(CodeKeystoreBadPassphrase, "wrong keystore passphrase")
	}
	return pt, nil
}

// validateKDFParams rejects an envelope whose scrypt cost parameters are not the
// fixed allowed set, BEFORE scrypt is invoked. r/p/dklen are constants; N must be
// the standard (2^18) or light (2^12) cost. Any other value is a corrupt/tampered
// envelope (a memory/CPU bomb if honored), reported as state.corrupt so scrypt is
// never run with attacker-chosen work. This is daxib's deliberate hardening over
// geth's uncapped DecryptDataV3.
func validateKDFParams(p kdfParams) error {
	if p.R != scryptR || p.P != scryptP || p.DKLen != scryptDKLen {
		return errKeysf(CodeStateCorrupt,
			"unexpected keystore KDF parameters (r=%d p=%d dklen=%d); the keystore envelope may be corrupt or tampered",
			p.R, p.P, p.DKLen)
	}
	if p.N != stdScryptN && p.N != lightScryptN {
		return errKeysf(CodeStateCorrupt,
			"unexpected keystore scrypt cost N=%d (want %d or %d); the keystore envelope may be corrupt or tampered",
			p.N, stdScryptN, lightScryptN)
	}
	return nil
}
