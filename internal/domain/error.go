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

	// 3 — POLICY_DENIED (covers all policy.denied.* via the prefix rule:
	// spend limit, destination allowlist, protected-UTXO refusal, coin-control).
	"policy.denied": ExitPolicyDenied,

	// 4 — AUTH (the "wrong/MISSING/unusable keystore passphrase" class)
	"keystore.bad_passphrase":      ExitAuth,
	"keystore.passphrase_required": ExitAuth, // missing passphrase, no TTY — distinct exit, never a prompt hang

	// 5 — INSUFFICIENT_FUNDS (coin-selection / insufficient-confirmed lane)
	"funds.insufficient":           ExitInsufficientFunds,
	"funds.insufficient_confirmed": ExitInsufficientFunds, // only unconfirmed UTXOs would cover it
	"coin.selection_failed":        ExitInsufficientFunds, // BnB/knapsack could not assemble the spend

	// 6 — NETWORK (the bitcoind RPC / Electrum / Esplora backend)
	"backend.unreachable": ExitNetwork,

	// 7 — FEE_POLICY_DENIED (anti-fee-burn: the computed fee/fee-rate exceeds the cap)
	"policy.fee_cap": ExitFeePolicyDenied,

	// 8 — TIMEOUT_PENDING / SEAL
	"tx.wait_timeout":       ExitTimeoutPending,
	"receive.timeout":       ExitTimeoutPending,
	"policy.seal_violation": ExitTimeoutPending,
	"policy.rollback":       ExitTimeoutPending,
	"policy.admin_auth":     ExitTimeoutPending,
	"policy.state_error":    ExitTimeoutPending,

	// 9 — TX_CONFLICT (double-spend / replacement family)
	"tx.input_spent":          ExitTxConflict, // bad-txns-inputs-missingorspent
	"tx.already_mined":        ExitTxConflict, // RBF speedup/cancel target already confirmed
	"tx.replaced":             ExitTxConflict,
	"tx.replacement_rejected": ExitTxConflict,

	// 10 — NOT_FOUND / READONLY
	"ref.not_found":      ExitNotFound,
	"config.read_only":   ExitNotFound,
	"config.not_found":   ExitNotFound,
	"keystore.read_only": ExitNotFound,

	// 11 — STATE
	"state.lock_timeout": ExitState,
	"state.corrupt":      ExitState,

	// 12 — INTEGRITY (tamper/misconfig tripwires)
	"backend.network_mismatch": ExitIntegrity, // backend genesis/network != declared network
	"keystore.perms_insecure":  ExitIntegrity, // insecure keystore/secret file perms — a misconfig tripwire, not a daxib bug
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
	"tx.wait_timeout":         true, // keep waiting / re-poll
	"receive.timeout":         true,
	"tx.replaced":             true, // re-quote / replace
	"tx.input_spent":          true, // re-select coins and rebuild
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
