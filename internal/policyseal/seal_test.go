package policyseal

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

// lightParams is a cheap scrypt cost for tests (production is N=2^17). N must stay
// a power of two.
var lightParams = ScryptParams{N: 1 << 4, R: 8, P: 1}

func fixedSalt() []byte {
	s := make([]byte, SaltSize)
	for i := range s {
		s[i] = byte(i)
	}
	return s
}

func TestDefaultScryptParams(t *testing.T) {
	p := DefaultScryptParams()
	if p.N != 1<<17 || p.R != 8 || p.P != 1 {
		t.Fatalf("default params = %+v; want N=131072 r=8 p=1", p)
	}
	if !p.Valid() {
		t.Fatal("default params must be Valid")
	}
}

func TestScryptParamsValid(t *testing.T) {
	cases := []struct {
		p  ScryptParams
		ok bool
	}{
		{ScryptParams{N: 1 << 4, R: 8, P: 1}, true},
		{ScryptParams{N: 0, R: 8, P: 1}, false},
		{ScryptParams{N: 1, R: 8, P: 1}, false},
		{ScryptParams{N: 3, R: 8, P: 1}, false}, // not power of two
		{ScryptParams{N: 16, R: 0, P: 1}, false},
		{ScryptParams{N: 16, R: 8, P: 0}, false},
	}
	for _, c := range cases {
		if got := c.p.Valid(); got != c.ok {
			t.Errorf("Valid(%+v)=%v want %v", c.p, got, c.ok)
		}
	}
}

func TestDeriveDeterminism(t *testing.T) {
	pass := []byte("correct horse battery staple")
	sk1, pk1, err := DeriveSealKey(pass, fixedSalt(), lightParams)
	if err != nil {
		t.Fatal(err)
	}
	sk2, pk2, err := DeriveSealKey(pass, fixedSalt(), lightParams)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sk1, sk2) || !bytes.Equal(pk1, pk2) {
		t.Fatal("derivation must be deterministic for the same (pass, salt, params)")
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pass := []byte("admin-secret")
	sk, pk, err := DeriveSealKey(pass, fixedSalt(), lightParams)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"version":1,"nonce":7}`)
	sig := Sign(body, sk)
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("sig len = %d want %d", len(sig), ed25519.SignatureSize)
	}
	if !Verify(body, sig, pk) {
		t.Fatal("round-trip verify failed")
	}
}

func TestTamperFailsVerify(t *testing.T) {
	sk, pk, err := DeriveSealKey([]byte("admin"), fixedSalt(), lightParams)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"version":1,"nonce":7,"max":"1000"}`)
	sig := Sign(body, sk)

	// Flip a body byte.
	bad := append([]byte{}, body...)
	bad[5] ^= 0x01
	if Verify(bad, sig, pk) {
		t.Error("a tampered body byte must fail verify")
	}
	// Truncated body.
	if Verify(body[:len(body)-1], sig, pk) {
		t.Error("a truncated body must fail verify")
	}
	// Flip a signature byte.
	badSig := append([]byte{}, sig...)
	badSig[0] ^= 0x01
	if Verify(body, badSig, pk) {
		t.Error("a corrupted signature must fail verify")
	}
}

func TestWrongPassphraseDiffersKey(t *testing.T) {
	_, pkA, err := DeriveSealKey([]byte("admin-A"), fixedSalt(), lightParams)
	if err != nil {
		t.Fatal(err)
	}
	skB, pkB, err := DeriveSealKey([]byte("admin-B"), fixedSalt(), lightParams)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(pkA, pkB) {
		t.Fatal("different passphrases must derive different verify keys")
	}
	// An attacker (B) signing a body cannot verify under the operator's (A) key —
	// the asymmetry that makes the agent host unable to forge a seal.
	body := []byte(`{"nonce":1}`)
	sig := Sign(body, skB)
	if Verify(body, sig, pkA) {
		t.Fatal("a B-signed body must not verify under A's pinned key")
	}
}

func TestWrongSaltDiffersKey(t *testing.T) {
	pass := []byte("same-pass")
	_, pk1, err := DeriveSealKey(pass, fixedSalt(), lightParams)
	if err != nil {
		t.Fatal(err)
	}
	other := fixedSalt()
	other[0] ^= 0xff
	_, pk2, err := DeriveSealKey(pass, other, lightParams)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(pk1, pk2) {
		t.Fatal("different salts must derive different verify keys")
	}
}

func TestEmptyPassphraseRefused(t *testing.T) {
	if _, _, err := DeriveSealKey(nil, fixedSalt(), lightParams); err == nil {
		t.Error("nil passphrase must be refused")
	}
	if _, _, err := DeriveSealKey([]byte{}, fixedSalt(), lightParams); err == nil {
		t.Error("empty passphrase must be refused")
	}
}

func TestInvalidParamsRefused(t *testing.T) {
	if _, _, err := DeriveSealKey([]byte("x"), fixedSalt(), ScryptParams{N: 3, R: 8, P: 1}); err == nil {
		t.Error("non-power-of-two N must be refused before scrypt")
	}
}

func TestVerifyRejectsBadLengths(t *testing.T) {
	sk, pk, err := DeriveSealKey([]byte("x"), fixedSalt(), lightParams)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("b")
	sig := Sign(body, sk)
	if Verify(body, sig, pk[:10]) {
		t.Error("short pk must fail (no panic)")
	}
	if Verify(body, sig[:10], pk) {
		t.Error("short sig must fail (no panic)")
	}
	if Verify(body, nil, nil) {
		t.Error("nil sig/pk must fail (no panic)")
	}
}

func TestSealDomainIsLoadBearing(t *testing.T) {
	sk, pk, err := DeriveSealKey([]byte("x"), fixedSalt(), lightParams)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"nonce":1}`)
	sig := Sign(body, sk)
	// A bare ed25519 verify of the body (no domain prefix) must fail — the prefix is
	// required, so a signature from a different daxib-namespaced context can't be
	// replayed as a policy seal.
	if ed25519.Verify(pk, body, sig) {
		t.Fatal("seal must not verify without the domain prefix")
	}
}

func TestNewSaltDistinct(t *testing.T) {
	a, err := NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != SaltSize || len(b) != SaltSize {
		t.Fatalf("salt len: %d,%d want %d", len(a), len(b), SaltSize)
	}
	if bytes.Equal(a, b) {
		t.Fatal("successive salts must differ")
	}
}
