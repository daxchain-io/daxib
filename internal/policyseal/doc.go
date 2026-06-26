// Package policyseal is the leaf crypto utility behind daxib's sealed policy file
// (the M5 spend-limit guardrails). It owns ONE asymmetric primitive: an admin
// passphrase, run through scrypt then HKDF, derives an Ed25519 key family; the
// secret key signs the policy body, and the public (verify) key is pinned in a
// machine-only anchor (internal/config reads that file). The agent host can VERIFY
// the seal (it holds the pinned verify key) but can never FORGE it (it never holds
// the admin secret) — the asymmetry IS the security spine. A symmetric MAC is
// rejected on purpose: any MAC key the agent can read to verify is a key a
// compromised agent could re-seal a tampered policy with.
//
// The crypto, exactly (daxib domain separation):
//
//	salt        = 32 random bytes (generated at first `policy set`)
//	K_master    = scrypt(adminPass, salt, N=2^17, r=8, p=1, dkLen=32)
//	K_seed      = HKDF-SHA256(K_master, info="daxib/policy/sig-seed/v1", L=32)
//	(sk, pk)    = ed25519.NewKeyFromSeed(K_seed)
//	sig         = ed25519.Sign(sk, []byte("daxib/policy/v1\n") || body)
//
// All pure-Go (golang.org/x/crypto/scrypt, golang.org/x/crypto/hkdf,
// crypto/ed25519); no cgo, builds for windows. This package holds NO policy
// schema, NO file I/O of the policy body, and NO engine state — internal/policy
// owns those and calls Sign/Verify/DeriveSealKey here. The anchor JSON shape lives
// here (it is the verify key + KDF params + nonce watermark, a pure crypto record)
// and is read/written by internal/config.
package policyseal
