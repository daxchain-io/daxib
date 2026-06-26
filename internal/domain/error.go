package domain

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Error is daxib's one error taxonomy. The dotted Code string is canonical and
// survives every transport (CLI exit code, MCP tool-error envelope); Exit is the
// CLI projection of that code. Error() returns the JSON envelope so the MCP
// frontend can pack it byte-identically to the CLI --json error.
//
// No float field appears here. Data carries structured detail ("data":{…}).
type Error struct {
	Code      string         `json:"code"`           // canonical dotted, e.g. "policy.denied.day_limit"
	Exit      ExitCode       `json:"exit"`           // 0..12
	Msg       string         `json:"message"`        // human one-liner
	Retryable bool           `json:"retryable"`      // agent hint: safe to retry as-is
	Data      map[string]any `json:"data,omitempty"` // structured detail

	wrapped error // unexported; surfaced via Unwrap()
}

// envelope is the on-the-wire shape: {"error":{…}}. It is its own type (not the
// Error tags above) so Error() emits the nested object the CLI --json contract
// and the MCP tool-error contract both expect.
type envelope struct {
	Err envelopeBody `json:"error"`
}

type envelopeBody struct {
	Code      string         `json:"code"`
	Exit      ExitCode       `json:"exit"`
	Msg       string         `json:"message"`
	Retryable bool           `json:"retryable"`
	Data      map[string]any `json:"data,omitempty"`
}

// Error returns the canonical JSON envelope. This is what the CLI writes to
// stderr under --json and what the MCP frontend embeds in its tool-error result,
// so the two are byte-identical.
func (e *Error) Error() string {
	b, err := json.Marshal(envelope{Err: envelopeBody{
		Code:      e.Code,
		Exit:      e.Exit,
		Msg:       e.Msg,
		Retryable: e.Retryable,
		Data:      e.Data,
	}})
	if err != nil {
		// Marshal of these fields cannot realistically fail; fall back to a
		// plain string so Error() is always non-empty.
		return e.Code + ": " + e.Msg
	}
	return string(b)
}

// Unwrap returns the wrapped cause, if any, so errors.Is/As traverse the chain.
func (e *Error) Unwrap() error { return e.wrapped }

// New constructs an Error and derives Exit from Code via the registry (ExitOf).
func New(code, msg string) *Error {
	return &Error{Code: code, Exit: ExitOf(code), Msg: msg, Retryable: retryableFor(code)}
}

// Newf is New with a fmt.Sprintf'd message.
func Newf(code, msg string, args ...any) *Error {
	return New(code, fmt.Sprintf(msg, args...))
}

// Wrap constructs an Error around a cause, preserving it for Unwrap/errors.Is.
// Exit is derived from Code.
func Wrap(code, msg string, cause error) *Error {
	e := New(code, msg)
	e.wrapped = cause
	return e
}

// WithData attaches (or merges into) the structured data map and returns e for
// fluent use. A nil receiver is returned unchanged.
func WithData(e *Error, data map[string]any) *Error {
	if e == nil {
		return nil
	}
	if e.Data == nil {
		e.Data = make(map[string]any, len(data))
	}
	for k, v := range data {
		e.Data[k] = v
	}
	return e
}

// AsError extracts a *domain.Error from anywhere in err's chain (an errors.As
// wrapper). If none is found it synthesizes a generic {code:"internal", exit:1}
// carrying the original message and wrapping err, so every command can exit
// through the registry even on a raw Go error. A nil err yields nil.
func AsError(err error) *Error {
	if err == nil {
		return nil
	}
	var de *Error
	if errors.As(err, &de) {
		return de
	}
	return &Error{
		Code:      CodeInternal,
		Exit:      ExitInternal,
		Msg:       err.Error(),
		Retryable: false,
		wrapped:   err,
	}
}

// ───────────────────────── the registry (ExitOf) ─────────────────────────────

// Canonical code constants. M1 commands emit only the internal/usage family;
// the rest are the registry's stable spellings for the subsystems later
// milestones author (keys, backend, coin-selection, fee, policy, tx, state).
const (
	CodeInternal = "internal"
	CodeUsage    = "usage" // family prefix; specific: usage.<reason>
	// Backend (chain-read provider) codes — exit 6 NETWORK for the live-but-failing
	// classes, exit 10 NOT_FOUND for the missing-config classes. They are the
	// stable spellings the backend provider + service emit (docs/PLAN.md §6).
	CodeBackendUnreachable   = "backend.unreachable"    // dial/transport failure (exit 6)
	CodeBackendRPCError      = "backend.rpc_error"      // answered with an error (exit 6)
	CodeBackendNotFound      = "backend.not_found"      // no endpoint by that name (exit 10)
	CodeBackendNotConfigured = "backend.not_configured" // no backend (and no default) for the network (exit 10)
	CodeBackendExists        = "backend.exists"         // duplicate endpoint name on add (exit 2)
	// CodeMnemonicRequired is the usage-class code for a missing BIP-39 mnemonic
	// input (no --mnemonic-stdin/--mnemonic-file, no TTY). It is distinct from the
	// keystore-passphrase auth class so the missing-secret error is label-aware
	// (§3.6): the mnemonic has no env channel, and a missing input is a usage (exit
	// 2) failure, not an auth (exit 4) one.
	CodeMnemonicRequired = "mnemonic.required"

	// M4 tx-send codes (the transaction pipeline). The funds.* / coin.* / tx.* /
	// state.* spellings the send pipeline, journal, and tx status/wait emit.
	// usage.* sub-codes carry the send-input failures.
	CodeUsageBadAmount       = "usage.bad_amount"            // malformed/over-cap/negative --amount (exit 2)
	CodeUsageBadAddress      = "usage.bad_address"           // --to does not decode for the active network (exit 2)
	CodeUsageBadFeeRate      = "usage.bad_fee_rate"          // --fee-rate is not a positive integer sat/vB (exit 2)
	CodeUsageBadTimeout      = "usage.bad_timeout"           // --timeout is not a valid duration (exit 2)
	CodeUsageDustOutput      = "usage.dust_output"           // recipient amount below the P2WPKH dust threshold (exit 2)
	CodeUsageConfirmRequired = "usage.confirmation_required" // mutating send, no TTY, no --yes (exit 2)
	CodeFundsInsufficient    = "funds.insufficient"          // spendable < amount+fee (exit 5)
	CodeCoinSelectionFailed  = "coin.selection_failed"       // BnB/knapsack could not assemble the spend (exit 5)
	CodeTxBroadcastRejected  = "tx.broadcast_rejected"       // a permanent network reject (exit 6)
	CodeTxFeeTooLow          = "tx.fee_too_low"              //nolint:gosec // G101: dotted error-code string // min-relay/mempool-min reject (exit 6)
	CodeTxInputSpent         = "tx.input_spent"              // bad-txns-inputs-missingorspent (exit 9, retryable: re-select)
	CodeTxWaitTimeout        = "tx.wait_timeout"             // a --wait deadline hit with the tx still pending (exit 8, retryable)
	CodeStateLockTimeout     = "state.lock_timeout"          // flock contention (exit 11)
	CodeStateCorrupt         = "state.corrupt"               // unrecoverable state file (exit 11)
	CodeRefNotFound          = "ref.not_found"               // unknown txid/wallet (exit 10)
)

// codeExit is the (prefix -> exit) registry, highest-specificity wins. The key
// is a canonical dotted prefix; a code matches the LONGEST key that is either
// equal to it or a dotted-prefix of it (so "policy.denied.day_limit" matches the
// "policy.denied" key, not "policy"). An unmatched code maps to ExitInternal.
//
// This table IS the exit-code registry. cli/render.go projects every error
// through ExitOf. The lanes follow docs/PLAN.md §4 (Bitcoin-flavored 0..12).
var codeExit = map[string]ExitCode{
	// 1 — INTERNAL
	"internal": ExitInternal,

	// 2 — USAGE
	"usage": ExitUsage,
	// First-init passphrase confirmation is missing/mismatched and there is no
	// TTY to double-enter at — a distinct, non-hanging usage failure (never a
	// prompt hang). Keystore subsystem (M2 keys); see §3.3/§3.4.
	"keystore.confirm_required": ExitUsage,
	// A BIP-39 mnemonic failed checksum/wordlist validation on import.
	"mnemonic.invalid": ExitUsage,
	// A required BIP-39 mnemonic input was not supplied via --mnemonic-stdin /
	// --mnemonic-file and stdin is not a TTY — a usage failure (the mnemonic has no
	// env channel), distinct from the keystore-passphrase auth class.
	"mnemonic.required": ExitUsage,
	// A wallet with that name already exists in the keystore.
	"wallet.exists": ExitUsage,
	// A backend endpoint with that name already exists in the config.
	"backend.exists": ExitUsage,
	// The config file is malformed TOML or carries a bad value.
	"config.invalid": ExitUsage,
	// M4 tx-send usage failures (all under the usage prefix → exit 2, but spelled
	// out so each is greppable and a future per-code retryable/message tweak is
	// local). A malformed --amount, an --to that does not decode for the active
	// network, a non-positive --fee-rate, a bad --timeout, a recipient output below
	// the dust threshold, and the non-TTY-without---yes confirmation gate.
	"usage.bad_amount":            ExitUsage,
	"usage.bad_address":           ExitUsage,
	"usage.bad_fee_rate":          ExitUsage,
	"usage.bad_timeout":           ExitUsage,
	"usage.dust_output":           ExitUsage,
	"usage.confirmation_required": ExitUsage,

	// 3 — POLICY_DENIED (covers all policy.denied.* via the prefix rule:
	// spend limit, destination allowlist, protected-UTXO refusal, coin-control).
	"policy.denied": ExitPolicyDenied,

	// 4 — AUTH (the "wrong/MISSING/unusable keystore OR admin passphrase" class)
	"keystore.bad_passphrase":      ExitAuth,
	"keystore.passphrase_required": ExitAuth, // missing passphrase, no TTY — distinct exit, never a prompt hang
	// The admin passphrase did not derive the anchor's pinned verify key (a policy
	// admin mutation), OR no admin-passphrase source was provided for a mutation.
	// This is an AUTH-class failure (the admin secret is wrong/missing), distinct
	// from a SEAL violation (the file/anchor pair is inconsistent), so an operator
	// can tell "my passphrase is wrong" (exit 4) from "the sealed state is tampered"
	// (exit 8). Independent of the keystore passphrase (§3.7).
	"policy.admin_auth":                ExitAuth,
	"policy.admin_passphrase_required": ExitAuth,
	// A ${env:}/${file:} secret reference (e.g. a backend rpcpassword) could not be
	// resolved at dial time — a missing/unusable credential, an auth-class failure.
	"secret.unresolved": ExitAuth,

	// 5 — INSUFFICIENT_FUNDS (coin-selection / insufficient-confirmed lane)
	"funds.insufficient":           ExitInsufficientFunds,
	"funds.insufficient_confirmed": ExitInsufficientFunds, // only unconfirmed UTXOs would cover it
	"coin.selection_failed":        ExitInsufficientFunds, // BnB/knapsack could not assemble the spend

	// 6 — NETWORK (the bitcoind RPC / Electrum / Esplora backend)
	"backend.unreachable": ExitNetwork, // dial/transport failure: nothing listening, 5xx, timeout
	"backend.rpc_error":   ExitNetwork, // the backend answered but with an error (bad JSON-RPC, 4xx REST)
	// A signed tx the network PERMANENTLY rejected (dust output, bad scriptpubkey,
	// non-final, non-mandatory-script-verify). The journal record is terminalized
	// `failed`; this is NOT a re-broadcast-the-same-bytes class (exit 6).
	"tx.broadcast_rejected": ExitNetwork,
	"tx.rejected":           ExitNetwork,
	// A reject for a fee below the min-relay / mempool-min floor — the operator can
	// retry with a higher --fee-rate (exit 6).
	"tx.fee_too_low": ExitNetwork,

	// 7 — FEE_POLICY_DENIED (anti-fee-burn: the computed fee/fee-rate exceeds the cap)
	"policy.fee_cap": ExitFeePolicyDenied,

	// 8 — TIMEOUT_PENDING / SEAL. The policy SEAL class (the sealed-state integrity
	// failures): a bad/absent seal, a nonce rollback, a corrupt durable counter, or
	// an unknown-field version skew — all of which HALT signing. policy.admin_auth
	// is NOT here (it is AUTH/exit 4: a wrong passphrase, not a tampered file).
	"tx.wait_timeout":       ExitTimeoutPending,
	"receive.timeout":       ExitTimeoutPending,
	"policy.seal_violation": ExitTimeoutPending,
	"policy.rollback":       ExitTimeoutPending,
	"policy.version":        ExitTimeoutPending, // unknown body field / future schema — fail closed
	"policy.state_error":    ExitTimeoutPending,

	// 9 — TX_CONFLICT (double-spend / replacement family)
	"tx.input_spent":          ExitTxConflict, // bad-txns-inputs-missingorspent
	"tx.replaced":             ExitTxConflict, // RBF target already resolved (confirmed/replaced)
	"tx.replacement_rejected": ExitTxConflict,

	// 10 — NOT_FOUND / READONLY
	"ref.not_found":          ExitNotFound,
	"config.read_only":       ExitNotFound,
	"config.not_found":       ExitNotFound,
	"backend.not_found":      ExitNotFound, // no backend endpoint by that name
	"backend.not_configured": ExitNotFound, // no backend (and no default) for the active network
	"keystore.read_only":     ExitNotFound,
	"keystore.not_found":     ExitNotFound, // the keystore directory is uninitialized
	"wallet.not_found":       ExitNotFound, // unknown wallet name/uuid

	// 11 — STATE
	"state.lock_timeout": ExitState,
	"state.corrupt":      ExitState,

	// 12 — INTEGRITY (tamper/misconfig tripwires)
	"backend.network_mismatch":      ExitIntegrity, // backend genesis/network != declared network
	"keystore.perms_insecure":       ExitIntegrity, // insecure keystore/secret file perms — a misconfig tripwire, not a daxib bug
	"keystore.derivation_watermark": ExitIntegrity, // meta.json watermark is below a materialized index — a restore-coupling tripwire (§3.4)
}

// ExitOf maps a canonical code to its exit number using the longest-dotted-prefix
// rule. "policy.denied.day_limit" -> 3 (via "policy.denied"); an unknown code ->
// ExitInternal. This is the single registry the whole CLI surface funnels
// through.
func ExitOf(code string) ExitCode {
	if code == "" {
		return ExitInternal
	}
	// Exact match short-circuit.
	if ex, ok := codeExit[code]; ok {
		return ex
	}
	// Walk the dotted prefixes from longest to shortest: "a.b.c" -> "a.b" -> "a".
	for {
		i := strings.LastIndexByte(code, '.')
		if i < 0 {
			break
		}
		code = code[:i]
		if ex, ok := codeExit[code]; ok {
			return ex
		}
	}
	return ExitInternal
}

// retryableDefaults marks the codes whose default Retryable hint is true (the
// "wait/retry later" classes the agent send-loop branches on). Explicit
// per-error overrides are still possible by setting Error.Retryable directly.
var retryableDefaults = map[string]bool{
	"backend.unreachable":     true, // retry later
	"backend.rpc_error":       true, // a transient backend error may clear on retry
	"tx.wait_timeout":         true, // keep waiting / re-poll
	"receive.timeout":         true,
	"tx.replaced":             true, // re-quote / replace
	"tx.input_spent":          true, // re-select coins and rebuild
	"tx.fee_too_low":          true, // the fee market moves; a higher --fee-rate may clear it
	"state.lock_timeout":      true, // contention; retry
	"policy.denied.day_limit": true, // rolling-24h window ages out; the engine returns retry_after
	"policy.fee_cap":          true, // the fee market moves; a later estimate may clear the cap
}

// retryableFor returns the default Retryable hint for a code, using the same
// longest-prefix walk as ExitOf so a sub-code inherits its family's default.
func retryableFor(code string) bool {
	if code == "" {
		return false
	}
	if r, ok := retryableDefaults[code]; ok {
		return r
	}
	for {
		i := strings.LastIndexByte(code, '.')
		if i < 0 {
			return false
		}
		code = code[:i]
		if r, ok := retryableDefaults[code]; ok {
			return r
		}
	}
}
