package policyseal

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
)

// keyPrefix tags the anchor's encoded verify keys so a base64 salt can never be
// mistaken for a key (and a future key type stays self-describing).
const keyPrefix = "ed25519:"

// Anchor is the machine-only trust root pinned in $DAXIB_CONFIG/policy-anchor.json
// (the config state class). It pairs the verify key (the seal verifier), the admin
// KDF salt + params, and the monotonic nonce watermark (anti-rollback floor). It is
// read DIRECTLY by internal/config — never via a TOML key, env var, or flag, so a
// compromised agent cannot outvote the admin passphrase from its own environment.
//
// VerifyKeyNext is the staged-rotation key (signing verifies against either key
// during a passphrase change); "" when no rotation is in flight. StagedSalt is the
// salt the next key was derived under, set by --stage and cleared by --commit.
type Anchor struct {
	VerifyKey      string       `json:"verify_key"`            // "ed25519:base64(32B)"
	VerifyKeyNext  string       `json:"verify_key_next"`       // staged key; "" → JSON null
	Salt           string       `json:"salt"`                  // base64(32B)
	Scrypt         ScryptParams `json:"scrypt"`                // {n,r,p}
	NonceWatermark uint64       `json:"nonce_watermark"`       // monotonic anti-rollback floor
	StagedSalt     string       `json:"staged_salt,omitempty"` // base64(32B); omitted when absent
}

// Sentinel errors for anchor decode.
var (
	// ErrAnchorMalformed is a structurally invalid anchor (bad JSON, unknown field,
	// missing required field, invalid scrypt, trailing garbage).
	ErrAnchorMalformed = errors.New("policyseal: malformed anchor")
	// ErrKeyMalformed is a verify key not in "ed25519:base64(32B)" form.
	ErrKeyMalformed = errors.New("policyseal: malformed verify key")
	// ErrSaltMalformed is a salt that is not valid base64.
	ErrSaltMalformed = errors.New("policyseal: malformed salt")
)

// anchorWire decodes the anchor with a pointer for verify_key_next so JSON null vs
// absent vs "" are all reconciled to the empty string (the "no staged key" state).
type anchorWire struct {
	VerifyKey      string       `json:"verify_key"`
	VerifyKeyNext  *string      `json:"verify_key_next"`
	Salt           string       `json:"salt"`
	Scrypt         ScryptParams `json:"scrypt"`
	NonceWatermark uint64       `json:"nonce_watermark"`
	StagedSalt     string       `json:"staged_salt,omitempty"`
}

// ParseAnchor strictly decodes anchor JSON. Unknown fields are rejected
// (DisallowUnknownFields) so a future-version anchor a present binary cannot fully
// understand fails closed rather than being silently truncated. A missing required
// field, an invalid scrypt cost, a malformed key/salt, or trailing garbage are all
// ErrAnchorMalformed (key/salt get their specific sentinels).
func ParseAnchor(b []byte) (Anchor, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var w anchorWire
	if err := dec.Decode(&w); err != nil {
		return Anchor{}, ErrAnchorMalformed
	}
	// Reject trailing content after the object.
	if dec.More() {
		return Anchor{}, ErrAnchorMalformed
	}
	if w.VerifyKey == "" || w.Salt == "" {
		return Anchor{}, ErrAnchorMalformed
	}
	if !w.Scrypt.Valid() {
		return Anchor{}, ErrAnchorMalformed
	}
	a := Anchor{
		VerifyKey:      w.VerifyKey,
		Salt:           w.Salt,
		Scrypt:         w.Scrypt,
		NonceWatermark: w.NonceWatermark,
		StagedSalt:     w.StagedSalt,
	}
	if w.VerifyKeyNext != nil {
		a.VerifyKeyNext = *w.VerifyKeyNext
	}
	// Eagerly validate the encoded fields so a malformed anchor fails at parse, not
	// at first verify.
	if _, err := a.VerifyKeyBytes(); err != nil {
		return Anchor{}, err
	}
	if a.VerifyKeyNext != "" {
		if _, _, err := a.VerifyKeyNextBytes(); err != nil {
			return Anchor{}, err
		}
	}
	if _, err := a.SaltBytes(); err != nil {
		return Anchor{}, err
	}
	if a.StagedSalt != "" {
		if _, _, err := a.StagedSaltBytes(); err != nil {
			return Anchor{}, err
		}
	}
	return a, nil
}

// Marshal renders the anchor as canonical, byte-stable JSON with a fixed key order
// (verify_key, verify_key_next, salt, scrypt, nonce_watermark, [staged_salt]).
// verify_key_next is written as literal null when empty (not omitted), so the
// "no staged key" state is explicit. It refuses a half-built anchor.
func (a Anchor) Marshal() ([]byte, error) {
	if a.VerifyKey == "" || a.Salt == "" || !a.Scrypt.Valid() {
		return nil, ErrAnchorMalformed
	}
	var b bytes.Buffer
	b.WriteString(`{"verify_key":`)
	writeJSONString(&b, a.VerifyKey)
	b.WriteString(`,"verify_key_next":`)
	if a.VerifyKeyNext == "" {
		b.WriteString("null")
	} else {
		writeJSONString(&b, a.VerifyKeyNext)
	}
	b.WriteString(`,"salt":`)
	writeJSONString(&b, a.Salt)
	b.WriteString(`,"scrypt":{"n":`)
	b.WriteString(itoa(a.Scrypt.N))
	b.WriteString(`,"r":`)
	b.WriteString(itoa(a.Scrypt.R))
	b.WriteString(`,"p":`)
	b.WriteString(itoa(a.Scrypt.P))
	b.WriteString(`},"nonce_watermark":`)
	b.WriteString(utoa(a.NonceWatermark))
	if a.StagedSalt != "" {
		b.WriteString(`,"staged_salt":`)
		writeJSONString(&b, a.StagedSalt)
	}
	b.WriteString("}")
	return b.Bytes(), nil
}

// VerifyKeyBytes decodes the pinned verify key to 32 raw ed25519 bytes.
func (a Anchor) VerifyKeyBytes() (ed25519.PublicKey, error) { return decodeKey(a.VerifyKey) }

// VerifyKeyNextBytes decodes the staged verify key; ok=false (no error) when none
// is staged.
func (a Anchor) VerifyKeyNextBytes() (ed25519.PublicKey, bool, error) {
	if a.VerifyKeyNext == "" {
		return nil, false, nil
	}
	pk, err := decodeKey(a.VerifyKeyNext)
	if err != nil {
		return nil, false, err
	}
	return pk, true, nil
}

// SaltBytes decodes the base64 admin KDF salt.
func (a Anchor) SaltBytes() ([]byte, error) { return decodeSalt(a.Salt) }

// StagedSaltBytes decodes the base64 staged-rotation salt; ok=false when absent.
func (a Anchor) StagedSaltBytes() ([]byte, bool, error) {
	if a.StagedSalt == "" {
		return nil, false, nil
	}
	b, err := decodeSalt(a.StagedSalt)
	if err != nil {
		return nil, false, err
	}
	return b, true, nil
}

// EncodeKey renders pk as "ed25519:base64(32B)".
func EncodeKey(pk ed25519.PublicKey) string {
	return keyPrefix + base64.StdEncoding.EncodeToString(pk)
}

// EncodeSalt renders salt as bare base64.
func EncodeSalt(salt []byte) string { return base64.StdEncoding.EncodeToString(salt) }

func decodeKey(s string) (ed25519.PublicKey, error) {
	if len(s) <= len(keyPrefix) || s[:len(keyPrefix)] != keyPrefix {
		return nil, ErrKeyMalformed
	}
	raw, err := base64.StdEncoding.DecodeString(s[len(keyPrefix):])
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, ErrKeyMalformed
	}
	return ed25519.PublicKey(raw), nil
}

func decodeSalt(s string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, ErrSaltMalformed
	}
	return raw, nil
}

// writeJSONString writes a minimally-escaped JSON string (the anchor only ever
// holds base64 + "ed25519:" prefixes, so no control chars; escape the two
// structural characters defensively).
func writeJSONString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
}

// itoa / utoa are decimal renderers for the byte-stable anchor writer.
func itoa(n int) string { return strconv.Itoa(n) }

func utoa(u uint64) string { return strconv.FormatUint(u, 10) }
