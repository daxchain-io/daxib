package keys

import "github.com/daxchain-io/daxib/internal/domain"

// Canonical keystore error codes (the dotted strings the domain exit-code
// registry maps to exit numbers). These mirror daxie's keys/errors.go spellings,
// adjusted for Bitcoin (mnemonic.invalid, wallet.exists / wallet.not_found).
const (
	CodeKeystoreBadPassphrase       = "keystore.bad_passphrase"       //nolint:gosec // G101: dotted error-code string, not a credential // exit 4
	CodeKeystoreConfirmRequired     = "keystore.confirm_required"     // exit 2
	CodeKeystoreReadOnly            = "keystore.read_only"            // exit 10
	CodeKeystoreNotFound            = "keystore.not_found"            // exit 10
	CodeKeystorePermsInsecure       = "keystore.perms_insecure"       // exit 12
	CodeKeystoreDerivationWatermark = "keystore.derivation_watermark" // exit 12
	CodeWalletNotFound              = "wallet.not_found"              // exit 10
	CodeWalletExists                = "wallet.exists"                 // exit 2
	CodeMnemonicInvalid             = "mnemonic.invalid"              // exit 2
	CodeUsageWords                  = "usage.words"                   // exit 2
	CodeUsageInvalidName            = "usage.invalid_name"            // exit 2
	CodeUsageBadIndex               = "usage.bad_index"               // exit 2
	CodeNetworkMismatch             = "usage.network_mismatch"        // exit 2 (under usage prefix)
	CodeStateLockTimeout            = "state.lock_timeout"            // exit 11
	CodeStateCorrupt                = "state.corrupt"                 // exit 11
)

// errKeys constructs a keystore domain error with the given code and message.
func errKeys(code, msg string) *domain.Error { return domain.New(code, msg) }

// errKeysf is errKeys with a formatted message.
func errKeysf(code, format string, args ...any) *domain.Error {
	return domain.Newf(code, format, args...)
}

// errWrap wraps a cause under the given keystore code.
func errWrap(code, msg string, cause error) *domain.Error {
	return domain.Wrap(code, msg, cause)
}
