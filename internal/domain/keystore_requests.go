package domain

// keystore_requests.go is the wire contract for the `keystore` noun
// (change-passphrase + info). change-passphrase is operator-only administration:
// it re-encrypts the whole keystore atomically (§3.8) and has NO MCP tool. info is
// a read-only summary. Neither holds a secret in the wire struct — passphrases
// arrive out-of-band via the service inputs (stdin/file/env), never serialized.

// KeystoreChangePassphraseRequest is the wire input for `keystore
// change-passphrase`. It carries no payload of its own (the old/new passphrases
// are out-of-band); Yes is the frontend confirmation flag, never serialized.
type KeystoreChangePassphraseRequest struct {
	Yes bool `json:"-"`
}

// KeystoreChangePassphraseResult is the wire output: the count of secret files
// re-encrypted (the verifier + every wallet blob).
type KeystoreChangePassphraseResult struct {
	RotatedFiles int `json:"rotated_files"`
}

// KeystoreInfoRequest is the wire input for `keystore info` (no fields).
type KeystoreInfoRequest struct{}

// KeystoreInfoResult is the wire output for `keystore info`: the keystore path,
// manifest format, KDF template, and wallet count. Read-only; no secrets.
type KeystoreInfoResult struct {
	Path        string `json:"path"`
	Format      int    `json:"format"`
	Initialized bool   `json:"initialized"`
	Wallets     int    `json:"wallets"`
	KDF         string `json:"kdf"`
	ScryptN     int    `json:"scrypt_n"`
}
