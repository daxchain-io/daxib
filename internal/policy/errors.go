package policy

import "github.com/daxchain-io/daxib/internal/domain"

// The policy error codes (canonical dotted strings; the exit projection lives in
// domain's registry). policy.denied.* → exit 3; policy.admin_auth → exit 4;
// policy.seal_violation / policy.rollback / policy.version / policy.state_error →
// exit 8.
const (
	codeSealViolation = "policy.seal_violation"
	codeRollback      = "policy.rollback"
	codeVersion       = "policy.version"
	codeAdminAuth     = "policy.admin_auth"
	codeStateError    = "policy.state_error"

	codeDenied             = "policy.denied"
	codeDeniedTxLimit      = "policy.denied.tx_limit"
	codeDeniedDayLimit     = "policy.denied.day_limit"
	codeDeniedFeeRate      = "policy.denied.fee_rate"
	codeDeniedNotAllowlist = "policy.denied.not_allowlisted"
	codeDeniedDenylisted   = "policy.denied.denylisted"
)

// errSeal builds a policy.seal_violation carrying the seal status + reason. The
// status string ("missing", "unparseable", "bad_sig", "anchor_missing") rides in
// data so an operator can tell which fail-closed branch fired.
func errSeal(status, msg string) error {
	return domain.WithData(domain.New(codeSealViolation, msg), map[string]any{"seal_status": status})
}

// errRollback builds a policy.rollback (an older sealed file replayed under the
// watermark).
func errRollback(bodyNonce, watermark uint64) error {
	return domain.WithData(
		domain.New(codeRollback, "policy nonce is below the anchor watermark; refusing a rolled-back policy"),
		map[string]any{"body_nonce": bodyNonce, "watermark": watermark})
}

// errVersion builds a policy.version refusal (unknown field / future schema).
func errVersion(writtenBy string, bodyVer int) error {
	return domain.WithData(
		domain.New(codeVersion, "policy.json was written by a newer daxib; upgrade the agent image to read it"),
		map[string]any{"written_by": writtenBy, "body_version": bodyVer})
}

// errAdminAuth builds a policy.admin_auth (the admin passphrase did not derive the
// pinned verify key, or no admin secret was provided / the anchor is missing).
func errAdminAuth(msg string) error {
	return domain.New(codeAdminAuth, msg)
}

// errState builds a policy.state_error (a durable counter/reservation file could
// not be read/locked/written — fail closed).
func errState(msg string, cause error) error {
	if cause != nil {
		return domain.Wrap(codeStateError, msg, cause)
	}
	return domain.New(codeStateError, msg)
}
