package policyseal

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"runtime"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/scrypt"
)

// The domain-separation constants. These are LOAD-BEARING: the seal subject is
// sealDomain||body, and the HKDF info string domain-separates the policy seal-seed
// from every other KDF in daxib (the keystore KDF lives in a different package with
// a different salt and parameters — §3.7 independence). Changing either string
// invalidates every existing seal, so they are versioned ("/v1").
const (
	// sealDomain is prepended (with its trailing newline) to the policy body before
	// signing/verifying, so a raw ed25519 verify of the bare body cannot pass.
	sealDomain = "daxib/policy/v1\n"
	// seedInfo domain-separates the HKDF expansion that turns K_master into the
	// ed25519 seed.
	seedInfo = "daxib/policy/sig-seed/v1"
	// scryptDKLen is the scrypt output length (also the HKDF PRK length).
	scryptDKLen = 32
	// SaltSize is the admin-KDF salt length (32 random bytes).
	SaltSize = 32
)

// Sentinel errors. DeriveSealKey refuses an empty passphrase (it would derive a
// world-known key) and invalid scrypt params; the wrapping is generic so a derive
// failure never leaks key material into a message.
var (
	errEmptyPassphrase = errors.New("policyseal: empty admin passphrase")
	errInvalidParams   = errors.New("policyseal: invalid scrypt params")
	errScrypt          = errors.New("policyseal: scrypt derivation failed")
	errHKDF            = errors.New("policyseal: hkdf expansion failed")
)

// ScryptParams is the admin-KDF cost record pinned in the anchor. N is the
// CPU/memory cost (a power of two ≥ 2), R the block size, P the parallelism. They
// are pinned (not inferred) so a binary verifies a file written by any other binary
// regardless of compile-time defaults.
type ScryptParams struct {
	N int `json:"n"`
	R int `json:"r"`
	P int `json:"p"`
}

// DefaultScryptParams returns the canonical admin-KDF cost: N=2^17, r=8, p=1
// (§3.4). Distinct from the keystore KDF cost — a compromised agent holding the
// keystore passphrase gains nothing toward forging a seal.
func DefaultScryptParams() ScryptParams { return ScryptParams{N: 1 << 17, R: 8, P: 1} }

// Valid reports whether p is a usable scrypt cost: N a power of two ≥ 2, R ≥ 1,
// P ≥ 1. The power-of-two check mirrors scrypt's own requirement (scrypt.Key
// errors otherwise), surfaced early as a typed param error.
func (p ScryptParams) Valid() bool {
	if p.N < 2 || p.R < 1 || p.P < 1 {
		return false
	}
	return p.N&(p.N-1) == 0 // power of two
}

// DeriveSealKey derives the Ed25519 seal key family from the admin passphrase and
// the anchor salt. It is the ONE place the admin secret is turned into a key. Both
// intermediate buffers (K_master, K_seed) are zeroed before return; the caller owns
// the returned private key and MUST zero it after signing.
//
// An empty passphrase or invalid params is a hard error (never a silent
// world-known key). The same (pass, salt, params) always yields the same (sk, pk)
// — that determinism is how an admin mutation re-derives the pinned key to
// authenticate, and how rotation re-derives the staged key to commit.
func DeriveSealKey(adminPass, salt []byte, p ScryptParams) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if len(adminPass) == 0 {
		return nil, nil, errEmptyPassphrase
	}
	if !p.Valid() {
		return nil, nil, errInvalidParams
	}

	kMaster, err := scrypt.Key(adminPass, salt, p.N, p.R, p.P, scryptDKLen)
	if err != nil {
		return nil, nil, errScrypt
	}
	defer zero(kMaster)

	seed := make([]byte, ed25519.SeedSize)
	r := hkdf.New(sha256.New, kMaster, nil, []byte(seedInfo))
	if _, err := io.ReadFull(r, seed); err != nil {
		zero(seed)
		return nil, nil, errHKDF
	}
	defer zero(seed)

	sk := ed25519.NewKeyFromSeed(seed)
	pk := sk.Public().(ed25519.PublicKey)
	return sk, pk, nil
}

// Sign returns the detached 64-byte Ed25519 signature over sealDomain||body. The
// caller has already produced the canonical body bytes (internal/policy's ordered
// writer); the seal covers those EXACT bytes, never a re-marshaled projection.
func Sign(body []byte, sk ed25519.PrivateKey) []byte {
	return ed25519.Sign(sk, subject(body))
}

// Verify reports whether sig is a valid detached signature over sealDomain||body
// under pk. It is length-safe (a wrong-length pk or sig returns false, never a
// panic), so a malformed anchor key or a corrupt seal fails closed. A wrong admin
// passphrase derives a DIFFERENT pk than the one pinned — that mismatch is caught
// by the engine BEFORE Verify (it compares derived pk to the pinned key); here, a
// bad sig under the correct pk is the tamper signal.
func Verify(body, sig []byte, pk ed25519.PublicKey) bool {
	if len(pk) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pk, subject(body), sig)
}

// subject builds the signed/verified message: the domain prefix followed by the
// exact body bytes.
func subject(body []byte) []byte {
	s := make([]byte, 0, len(sealDomain)+len(body))
	s = append(s, sealDomain...)
	s = append(s, body...)
	return s
}

// NewSalt returns 32 cryptographically random bytes for a fresh admin KDF salt
// (first `policy set` and each passphrase rotation).
func NewSalt() ([]byte, error) {
	b := make([]byte, SaltSize)
	if _, err := rand.Read(b); err != nil {
		return nil, errors.New("policyseal: cannot read random salt")
	}
	return b, nil
}

// zero overwrites b and keeps it alive past the wipe so the compiler cannot elide
// it (best-effort memory hygiene for a transient key buffer).
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
