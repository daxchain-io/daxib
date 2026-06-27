package domain

// message_requests.go is the wire contract for the `sign` and `verify` nouns:
// BIP-322 "simple" message signing for P2WPKH addresses (§ sign/verify). `sign`
// needs the keystore passphrase to unlock the address's key; `verify` is
// passphrase-free (it only reconstructs the BIP-322 virtual txs and runs the
// script engine). No struct here carries a float or a secret — the message and
// signature are plain strings; the passphrase arrives out-of-band.

// MessageSignRequest is the wire input for `sign message`. Ref is the address OR a
// "<wallet>/<branch>/<index>" derivation ref whose key signs the message. The
// message itself is resolved by the service (flag/file/stdin) and travels here as
// the resolved Message string for attribution; the keystore passphrase never does.
type MessageSignRequest struct {
	Wallet  string `json:"wallet,omitempty"`
	Ref     string `json:"ref"`     // address or "<wallet>/<branch>/<index>"
	Message string `json:"message"` // the message that was signed
	Yes     bool   `json:"-"`
}

// MessageSignResult is the wire output for `sign message`: the address the message
// was signed for and the base64 BIP-322 witness (the signature).
type MessageSignResult struct {
	Address   string `json:"address"`
	Message   string `json:"message"`
	Signature string `json:"signature"` // base64 BIP-322 "simple" witness
	Format    string `json:"format"`    // "bip322-simple"
}

// MessageVerifyRequest is the wire input for `verify`. It is passphrase-free:
// Address, Message, and the base64 Signature fully determine the verification.
type MessageVerifyRequest struct {
	Address   string `json:"address"`
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

// MessageVerifyResult is the wire output for `verify`: whether the signature is
// valid for (address, message). An INVALID signature is NOT an error — it is a
// successful verification with Valid=false (exit 0), so an agent branches on the
// field rather than the exit code. Only a malformed input is an error.
type MessageVerifyResult struct {
	Valid     bool   `json:"valid"`
	Address   string `json:"address"`
	Message   string `json:"message"`
	Signature string `json:"signature"`
	Format    string `json:"format"` // "bip322-simple"
}
