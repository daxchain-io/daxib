package policyseal

import (
	"bytes"
	"testing"
)

// baseAnchorFor builds an anchor pinned to pass under fixedSalt/lightParams.
func baseAnchorFor(t *testing.T, pass []byte) Anchor {
	t.Helper()
	_, pk, err := DeriveSealKey(pass, fixedSalt(), lightParams)
	if err != nil {
		t.Fatal(err)
	}
	return Anchor{
		VerifyKey:      EncodeKey(pk),
		Salt:           EncodeSalt(fixedSalt()),
		Scrypt:         lightParams,
		NonceWatermark: 5,
	}
}

func TestStageThenCommit(t *testing.T) {
	a := baseAnchorFor(t, []byte("old-pass"))
	newPass := []byte("new-pass")

	nextKey, stagedSalt, err := StageRotation(newPass, lightParams)
	if err != nil {
		t.Fatal(err)
	}
	a.VerifyKeyNext = nextKey
	a.StagedSalt = EncodeSalt(stagedSalt)

	fam, err := CommitRotation(newPass, a, lightParams)
	if err != nil {
		t.Fatal(err)
	}
	if EncodeKey(fam.Public) != nextKey {
		t.Fatal("committed public key must equal the staged key")
	}
	if !bytes.Equal(fam.Salt, stagedSalt) {
		t.Fatal("committed salt must equal the staged salt")
	}
	// The new key signs verifiably.
	body := []byte(`{"nonce":6}`)
	sig := Sign(body, fam.Private)
	if !Verify(body, sig, fam.Public) {
		t.Fatal("new key family must sign+verify")
	}
	// And differs from the old key.
	if fam.Public.Equal(mustKey(t, a.VerifyKey)) {
		t.Fatal("rotated key must differ from the old pinned key")
	}
}

func TestCommitWrongNewPassphrase(t *testing.T) {
	a := baseAnchorFor(t, []byte("old-pass"))
	nextKey, stagedSalt, err := StageRotation([]byte("intended-new"), lightParams)
	if err != nil {
		t.Fatal(err)
	}
	a.VerifyKeyNext = nextKey
	a.StagedSalt = EncodeSalt(stagedSalt)

	if _, err := CommitRotation([]byte("typo-new"), a, lightParams); err != ErrRotationKeyMismatch {
		t.Fatalf("expected ErrRotationKeyMismatch, got %v", err)
	}
}

func TestCommitNoStaged(t *testing.T) {
	a := baseAnchorFor(t, []byte("old-pass"))
	if _, err := CommitRotation([]byte("new"), a, lightParams); err != ErrNoStagedRotation {
		t.Fatalf("no staged: want ErrNoStagedRotation, got %v", err)
	}
	// staged salt without next key.
	a.StagedSalt = EncodeSalt(fixedSalt())
	if _, err := CommitRotation([]byte("new"), a, lightParams); err != ErrNoStagedRotation {
		t.Fatalf("staged-salt only: want ErrNoStagedRotation, got %v", err)
	}
}

func TestCommitZeroesPrivateOnMismatch(t *testing.T) {
	a := baseAnchorFor(t, []byte("old-pass"))
	nextKey, stagedSalt, err := StageRotation([]byte("intended"), lightParams)
	if err != nil {
		t.Fatal(err)
	}
	a.VerifyKeyNext = nextKey
	a.StagedSalt = EncodeSalt(stagedSalt)
	fam, err := CommitRotation([]byte("wrong"), a, lightParams)
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	if fam.Private != nil || fam.Public != nil || fam.Salt != nil {
		t.Fatal("on mismatch the rotated family must be zero (no live key escapes)")
	}
}

func mustKey(t *testing.T, enc string) []byte {
	t.Helper()
	a := Anchor{VerifyKey: enc, Salt: EncodeSalt(fixedSalt()), Scrypt: lightParams}
	pk, err := a.VerifyKeyBytes()
	if err != nil {
		t.Fatal(err)
	}
	return pk
}
