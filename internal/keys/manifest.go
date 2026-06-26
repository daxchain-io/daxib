package keys

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"os"

	"github.com/daxchain-io/daxib/internal/secret"
)

const manifestFormatVersion = 1

// kdfDefaults is the manifest's template KDF block (the scrypt cost a new
// keystore writes; per-file salts still vary). Mirrors the design's
// kdf_defaults.
type kdfDefaults struct {
	KDF   string `json:"kdf"`
	N     int    `json:"n"`
	R     int    `json:"r"`
	P     int    `json:"p"`
	DKLen int    `json:"dklen"`
}

// manifest is keystore.json: the format version, creation time, the light flag
// (downgrade guard), the kdf defaults, and the verifier envelope.
type manifest struct {
	Format      int         `json:"daxib_keystore"`
	CreatedAt   string      `json:"created_at"`
	Light       bool        `json:"light,omitempty"` // set only if DAXIB_KDF_LIGHT was active at creation
	KDFDefaults kdfDefaults `json:"kdf_defaults"`
	Verifier    envelope    `json:"verifier"` // 32 random bytes sealed under the keystore passphrase
}

// loadManifest reads + parses keystore.json. Returns (nil, nil) when the manifest
// does not exist (fresh keystore).
func (s *Store) loadManifest() (*manifest, error) {
	b, err := s.readKeystoreFile(s.manifestPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if perr := s.checkPerms(s.manifestPath()); perr != nil {
		return nil, perr
	}
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, errWrap(CodeStateCorrupt, "keystore.json is corrupt", err)
	}
	if m.Format != manifestFormatVersion {
		return nil, errKeysf(CodeStateCorrupt, "unsupported keystore format version %d (want %d)", m.Format, manifestFormatVersion)
	}
	return &m, nil
}

// saveManifest atomically writes keystore.json (0600).
func (s *Store) saveManifest(m *manifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return errWrap(CodeStateCorrupt, "encoding keystore.json", err)
	}
	return s.writeFile(s.manifestPath(), b)
}

// initManifest builds a fresh manifest, sealing a 32-byte verifier under pass at
// the store's scrypt cost. The store's light flag becomes the manifest's light
// flag (so the downgrade guard is locked in at creation).
func (s *Store) initManifest(pass *secret.Bytes) (*manifest, error) {
	n := s.scryptN()
	verifierPlain := make([]byte, 32)
	if _, err := rand.Read(verifierPlain); err != nil {
		return nil, errWrap(CodeStateCorrupt, "generating keystore verifier", err)
	}
	defer zeroBytes(verifierPlain)

	env, err := seal(verifierPlain, pass.Reveal(), n)
	if err != nil {
		return nil, err
	}
	return &manifest{
		Format:    manifestFormatVersion,
		CreatedAt: s.now(),
		Light:     s.light,
		KDFDefaults: kdfDefaults{
			KDF: kdfName, N: n, R: scryptR, P: scryptP, DKLen: scryptDKLen,
		},
		Verifier: env,
	}, nil
}

// verifyAgainst decrypts the manifest's verifier under pass, proving the
// passphrase. A GCM auth failure surfaces as keystore.bad_passphrase.
func verifyAgainst(m *manifest, pass *secret.Bytes) error {
	plain, err := open(m.Verifier, pass.Reveal())
	if err != nil {
		return err // already keystore.bad_passphrase / state.corrupt
	}
	zeroBytes(plain)
	return nil
}

// VerifyPassphrase loads the manifest and proves pass against the verifier.
// Every operation that ADDS key material calls this first (one-passphrase-per-
// keystore, §3.4).
func (s *Store) VerifyPassphrase(pass *secret.Bytes) error {
	m, err := s.loadManifest()
	if err != nil {
		return err
	}
	if m == nil {
		return errKeys(CodeKeystoreBadPassphrase, "the keystore is not initialized")
	}
	return verifyAgainst(m, pass)
}

// ensureInitialized is the first-init gate (§3.4). If the keystore already exists,
// it verifies pass (confirm is ignored). If it does not, confirm MUST be supplied
// and MUST match pass (constant-time) before the verifier is written — a missing
// or mismatched confirm is keystore.confirm_required (never a prompt hang).
func (s *Store) ensureInitialized(pass, confirm *secret.Bytes) error {
	m, err := s.loadManifest()
	if err != nil {
		return err
	}
	if m != nil {
		return verifyAgainst(m, pass)
	}

	// First init: require a matching confirmation.
	if confirm == nil || confirm.Len() == 0 {
		return errKeys(CodeKeystoreConfirmRequired,
			"first keystore use requires passphrase confirmation: supply --passphrase-confirm-stdin|file or DAXIB_PASSPHRASE_CONFIRM[_FILE] (interactive double-entry at a TTY)")
	}
	if subtle.ConstantTimeCompare(pass.Reveal(), confirm.Reveal()) != 1 {
		return errKeys(CodeKeystoreConfirmRequired, "the passphrase and its confirmation do not match")
	}

	if err := s.ensureDirs(); err != nil {
		return err
	}
	nm, err := s.initManifest(pass)
	if err != nil {
		return err
	}
	return s.saveManifest(nm)
}
