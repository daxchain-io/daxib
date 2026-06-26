package policyseal

import (
	"bytes"
	"strings"
	"testing"
)

const sampleAnchor = `{"verify_key":"ed25519:6sTa5H5EyR4UQWCyzHEuEHDvvDVmQUCRjXi+XWjkhx4=","verify_key_next":null,"salt":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=","scrypt":{"n":16,"r":8,"p":1},"nonce_watermark":12}`

func TestParseAnchorRoundTrip(t *testing.T) {
	a, err := ParseAnchor([]byte(sampleAnchor))
	if err != nil {
		t.Fatal(err)
	}
	if a.NonceWatermark != 12 {
		t.Errorf("watermark = %d want 12", a.NonceWatermark)
	}
	if a.Scrypt.N != 16 || a.Scrypt.R != 8 || a.Scrypt.P != 1 {
		t.Errorf("scrypt = %+v", a.Scrypt)
	}
	if a.VerifyKeyNext != "" {
		t.Errorf("verify_key_next from null must be empty, got %q", a.VerifyKeyNext)
	}
	pk, err := a.VerifyKeyBytes()
	if err != nil || len(pk) != 32 {
		t.Fatalf("VerifyKeyBytes err=%v len=%d", err, len(pk))
	}
	salt, err := a.SaltBytes()
	if err != nil || len(salt) != 32 {
		t.Fatalf("SaltBytes err=%v len=%d", err, len(salt))
	}
}

func TestMarshalParseStable(t *testing.T) {
	a, err := ParseAnchor([]byte(sampleAnchor))
	if err != nil {
		t.Fatal(err)
	}
	b1, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	b2, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatal("Marshal must be byte-stable")
	}
	a2, err := ParseAnchor(b1)
	if err != nil {
		t.Fatal(err)
	}
	if a2 != a {
		t.Fatalf("round-trip changed the anchor:\n%+v\n%+v", a, a2)
	}
}

func TestMarshalEmitsNullNext(t *testing.T) {
	a, err := ParseAnchor([]byte(sampleAnchor))
	if err != nil {
		t.Fatal(err)
	}
	b, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"verify_key_next":null`) {
		t.Errorf("expected literal null next key, got %s", b)
	}
	if strings.Contains(string(b), "staged_salt") {
		t.Errorf("staged_salt must be omitted when empty, got %s", b)
	}
}

func TestMarshalEmitsStagedSalt(t *testing.T) {
	a, err := ParseAnchor([]byte(sampleAnchor))
	if err != nil {
		t.Fatal(err)
	}
	a.VerifyKeyNext = a.VerifyKey
	a.StagedSalt = a.Salt
	b, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "staged_salt") {
		t.Errorf("staged_salt missing: %s", s)
	}
	a2, err := ParseAnchor(b)
	if err != nil {
		t.Fatal(err)
	}
	if a2.VerifyKeyNext != a.VerifyKey || a2.StagedSalt != a.Salt {
		t.Errorf("staged fields not preserved: %+v", a2)
	}
}

func TestParseAnchorRejectsUnknownField(t *testing.T) {
	bad := `{"verify_key":"ed25519:6sTa5H5EyR4UQWCyzHEuEHDvvDVmQUCRjXi+XWjkhx4=","verify_key_next":null,"salt":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=","scrypt":{"n":16,"r":8,"p":1},"nonce_watermark":12,"injected_key":"attacker"}`
	if _, err := ParseAnchor([]byte(bad)); err == nil {
		t.Fatal("an unknown anchor field must be rejected")
	}
}

func TestParseAnchorRejectsIncomplete(t *testing.T) {
	cases := []string{
		`{}`,
		`{"salt":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=","scrypt":{"n":16,"r":8,"p":1}}`,                                                                    // missing verify_key
		`{"verify_key":"ed25519:6sTa5H5EyR4UQWCyzHEuEHDvvDVmQUCRjXi+XWjkhx4=","scrypt":{"n":16,"r":8,"p":1}}`,                                                      // missing salt
		`{"verify_key":"ed25519:6sTa5H5EyR4UQWCyzHEuEHDvvDVmQUCRjXi+XWjkhx4=","salt":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=","scrypt":{"n":3,"r":8,"p":1}}`, // bad N
		`{"verify_key":"notakey","salt":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=","scrypt":{"n":16,"r":8,"p":1}}`,                                             // bad key form
		`garbage`,
	}
	for _, c := range cases {
		if _, err := ParseAnchor([]byte(c)); err == nil {
			t.Errorf("expected ParseAnchor to reject %q", c)
		}
	}
}

func TestEncodeKeyRoundTrip(t *testing.T) {
	_, pk, err := DeriveSealKey([]byte("x"), fixedSalt(), lightParams)
	if err != nil {
		t.Fatal(err)
	}
	enc := EncodeKey(pk)
	if !strings.HasPrefix(enc, "ed25519:") {
		t.Fatalf("encoded key lacks prefix: %s", enc)
	}
	a := Anchor{VerifyKey: enc, Salt: EncodeSalt(fixedSalt()), Scrypt: lightParams}
	got, err := a.VerifyKeyBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pk) {
		t.Fatal("VerifyKeyBytes did not round-trip the encoded key")
	}
}
