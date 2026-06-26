package policyseal

import (
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
)

// Rotation sentinels.
var (
	// ErrRotationKeyMismatch is returned by CommitRotation when the new passphrase
	// re-derived under the staged salt does not produce the staged verify key (a
	// typo in the new passphrase, or a different key was promoted into the anchor).
	ErrRotationKeyMismatch = errors.New("policyseal: staged rotation key mismatch (new passphrase or promoted key differs from --stage)")
	// ErrNoStagedRotation is returned when --commit runs with no verify_key_next /
	// staged_salt pair to commit.
	ErrNoStagedRotation = errors.New("policyseal: no staged rotation to commit")
)

// RotatedFamily is the new key family produced by CommitRotation. The caller
// reseals the policy body under Private, promotes verify_key_next → verify_key,
// records Salt as the new anchor salt, and clears the staged fields — then MUST
// zero Private.
type RotatedFamily struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
	Salt    []byte
}

// StageRotation generates a fresh salt, derives the new key family under the new
// admin passphrase, and returns the encoded public key + raw salt for the caller to
// record as the anchor's verify_key_next + staged_salt. The new private key is
// zeroed immediately (staging records only the public key; policy keeps signing
// under the OLD key until --commit). For v1 the staged salt is carried in the
// anchor so --commit needs only the new passphrase.
func StageRotation(newAdminPass []byte, params ScryptParams) (newVerifyKey string, stagedSalt []byte, err error) {
	if len(newAdminPass) == 0 {
		return "", nil, errEmptyPassphrase
	}
	salt, err := NewSalt()
	if err != nil {
		return "", nil, err
	}
	sk, pk, err := DeriveSealKey(newAdminPass, salt, params)
	if err != nil {
		return "", nil, err
	}
	zero(sk)
	return EncodeKey(pk), salt, nil
}

// CommitRotation re-derives the key family from the anchor's staged salt under the
// new admin passphrase and constant-time-compares it to the pinned verify_key_next.
// On match it returns the rotated family (caller reseals + promotes); on mismatch it
// zeroes the derived key and returns ErrRotationKeyMismatch. A missing staged pair
// is ErrNoStagedRotation.
func CommitRotation(newAdminPass []byte, a Anchor, params ScryptParams) (RotatedFamily, error) {
	if len(newAdminPass) == 0 {
		return RotatedFamily{}, errEmptyPassphrase
	}
	stagedSalt, ok, err := a.StagedSaltBytes()
	if err != nil {
		return RotatedFamily{}, err
	}
	if !ok || a.VerifyKeyNext == "" {
		return RotatedFamily{}, ErrNoStagedRotation
	}
	wantPK, _, err := a.VerifyKeyNextBytes()
	if err != nil {
		return RotatedFamily{}, err
	}
	sk, pk, err := DeriveSealKey(newAdminPass, stagedSalt, params)
	if err != nil {
		return RotatedFamily{}, err
	}
	if subtle.ConstantTimeCompare(pk, wantPK) != 1 {
		zero(sk)
		return RotatedFamily{}, ErrRotationKeyMismatch
	}
	return RotatedFamily{Private: sk, Public: pk, Salt: stagedSalt}, nil
}
