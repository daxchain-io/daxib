package keys

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/daxchain-io/daxib/internal/domain"
)

// codec_test.go pins the hand-composed AES-256-GCM envelope (the deliberate
// divergence from daxie's geth-v3 envelope, see codec.go). These tests use the
// light scrypt cost so they stay fast.

// mustOpen is open() with a fatal on error.
func sealLight(t *testing.T, plaintext, pass []byte) envelope {
	t.Helper()
	env, err := seal(plaintext, pass, lightScryptN)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return env
}

func TestSealOpenRoundtrip(t *testing.T) {
	plaintext := []byte("the canonical mnemonic plaintext blob")
	pass := []byte("test-pass-12345678")
	env := sealLight(t, plaintext, pass)

	got, err := open(env, pass)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("roundtrip = %q, want %q", got, plaintext)
	}
}

func TestOpenWrongPassphrase(t *testing.T) {
	env := sealLight(t, []byte("secret"), []byte("right-pass"))
	_, err := open(env, []byte("wrong-pass"))
	assertCode(t, err, CodeKeystoreBadPassphrase)
}

// TestOpenTamperMatrix mutates each authenticated/derived field by one byte and
// asserts open fails the GCM tag check (keystore.bad_passphrase), confirming the
// envelope is authenticated end to end.
func TestOpenTamperMatrix(t *testing.T) {
	plaintext := []byte("authenticated plaintext")
	pass := []byte("test-pass-12345678")

	flipHexByte := func(s string, i int) string {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatalf("decode %q: %v", s, err)
		}
		b[i] ^= 0xff
		return hex.EncodeToString(b)
	}

	cases := []struct {
		name   string
		mutate func(e *envelope)
	}{
		{"ciphertext[0]", func(e *envelope) { e.Ciphertext = flipHexByte(e.Ciphertext, 0) }},
		{"last tag byte", func(e *envelope) {
			b, _ := hex.DecodeString(e.Ciphertext)
			e.Ciphertext = flipHexByte(e.Ciphertext, len(b)-1)
		}},
		{"nonce[0]", func(e *envelope) { e.Nonce = flipHexByte(e.Nonce, 0) }},
		{"salt[0]", func(e *envelope) { e.KDFParams.Salt = flipHexByte(e.KDFParams.Salt, 0) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := sealLight(t, plaintext, pass)
			tc.mutate(&env)
			_, err := open(env, pass)
			assertCode(t, err, CodeKeystoreBadPassphrase)
		})
	}
}

// TestSealUniqueSaltNonce seals the same plaintext+pass N times and asserts every
// salt and nonce is distinct with the fixed lengths.
func TestSealUniqueSaltNonce(t *testing.T) {
	const n = 8
	plaintext := []byte("same plaintext every time")
	pass := []byte("same-pass-12345678")
	salts := map[string]bool{}
	nonces := map[string]bool{}
	for i := 0; i < n; i++ {
		env := sealLight(t, plaintext, pass)
		salt, _ := hex.DecodeString(env.KDFParams.Salt)
		nonce, _ := hex.DecodeString(env.Nonce)
		if len(salt) != saltLen {
			t.Fatalf("salt len = %d, want %d", len(salt), saltLen)
		}
		if len(nonce) != nonceLen {
			t.Fatalf("nonce len = %d, want %d", len(nonce), nonceLen)
		}
		if salts[env.KDFParams.Salt] {
			t.Fatalf("duplicate salt at iteration %d", i)
		}
		if nonces[env.Nonce] {
			t.Fatalf("duplicate nonce at iteration %d", i)
		}
		salts[env.KDFParams.Salt] = true
		nonces[env.Nonce] = true
	}
}

// TestSealEnvelopeParams asserts the on-disk envelope carries the fixed scrypt
// params (r=8, p=1, dklen=32) and a power-of-two N from the allowed set.
func TestSealEnvelopeParams(t *testing.T) {
	env := sealLight(t, []byte("x"), []byte("pass-12345678"))
	if env.Cipher != cipherName {
		t.Errorf("cipher = %q, want %q", env.Cipher, cipherName)
	}
	if env.KDF != kdfName {
		t.Errorf("kdf = %q, want %q", env.KDF, kdfName)
	}
	p := env.KDFParams
	if p.R != scryptR || p.P != scryptP || p.DKLen != scryptDKLen {
		t.Errorf("kdf params r/p/dklen = %d/%d/%d, want %d/%d/%d", p.R, p.P, p.DKLen, scryptR, scryptP, scryptDKLen)
	}
	if p.N != lightScryptN {
		t.Errorf("N = %d, want lightScryptN %d", p.N, lightScryptN)
	}
}

// TestOpenRejectsHostileKDFParams is the regression guard for the
// unbounded-memory-DoS fix: open() must reject an envelope whose scrypt cost
// params are outside the allowed set BEFORE invoking scrypt (state.corrupt),
// so a tampered file presenting a huge N is not a memory bomb.
func TestOpenRejectsHostileKDFParams(t *testing.T) {
	pass := []byte("pass-12345678")
	cases := []struct {
		name   string
		mutate func(e *envelope)
	}{
		{"huge N (memory bomb)", func(e *envelope) { e.KDFParams.N = 1 << 28 }},
		{"N not in allowed set", func(e *envelope) { e.KDFParams.N = 1 << 16 }},
		{"r tampered", func(e *envelope) { e.KDFParams.R = 16 }},
		{"p tampered", func(e *envelope) { e.KDFParams.P = 4 }},
		{"dklen tampered", func(e *envelope) { e.KDFParams.DKLen = 64 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := sealLight(t, []byte("x"), pass)
			tc.mutate(&env)
			_, err := open(env, pass)
			assertCode(t, err, CodeStateCorrupt)
		})
	}
}

// TestOpenRejectsWrongLengthSalt is the regression guard for the salt-length fix:
// a salt whose decoded length != 32 is a corrupt envelope (state.corrupt), not a
// wrong passphrase.
func TestOpenRejectsWrongLengthSalt(t *testing.T) {
	pass := []byte("pass-12345678")
	env := sealLight(t, []byte("x"), pass)
	// 31-byte salt (one byte short of saltLen).
	env.KDFParams.Salt = hex.EncodeToString(make([]byte, saltLen-1))
	_, err := open(env, pass)
	assertCode(t, err, CodeStateCorrupt)
}

func TestValidateKDFParams(t *testing.T) {
	good := kdfParams{N: stdScryptN, R: scryptR, P: scryptP, DKLen: scryptDKLen}
	if err := validateKDFParams(good); err != nil {
		t.Errorf("std params rejected: %v", err)
	}
	light := kdfParams{N: lightScryptN, R: scryptR, P: scryptP, DKLen: scryptDKLen}
	if err := validateKDFParams(light); err != nil {
		t.Errorf("light params rejected: %v", err)
	}
	bad := kdfParams{N: 1 << 28, R: scryptR, P: scryptP, DKLen: scryptDKLen}
	if err := validateKDFParams(bad); err == nil {
		t.Errorf("hostile N accepted")
	}
}

// assertCode fails unless err is a *domain.Error with the given code.
func assertCode(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %q, got nil", want)
	}
	var de *domain.Error
	if !errors.As(err, &de) {
		t.Fatalf("error %v is not a *domain.Error", err)
	}
	if de.Code != want {
		t.Fatalf("code = %q, want %q", de.Code, want)
	}
}
