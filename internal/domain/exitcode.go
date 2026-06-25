// Package domain is the wire contract: the one error taxonomy, the exit-code
// registry, and (later) the value types and parsers the commands need.
//
// domain imports NOTHING internal. It does no I/O and holds no float field on
// any wire type. In M1 the package ships the exit-code registry + the Error
// taxonomy; later milestones add the Bitcoin value types (amounts in sats,
// addresses, descriptors, PSBTs) here.
package domain

// ExitCode is the process exit status the CLI returns. The numeric set is kept
// deliberately small and agent-branchable; the canonical dotted
// domain.Error.Code string namespaces finer causes *within* one exit number.
//
// Numbers 0..12 are assigned; 13..63 are reserved (never emitted); 64+ are never
// used so daxib never collides with BSD sysexits(3) conventions.
//
// The table mirrors daxie's 0..12 skeleton (docs/PLAN.md §4), repurposing the
// EVM-specific lanes for Bitcoin: exit 5 covers coin-selection / insufficient
// confirmed funds, exit 7 is fee-policy denial (replacing daxie's contract
// revert), exit 9 is the double-spend / replacement conflict lane.
type ExitCode int

const (
	// ExitOK is success. With --wait it means "confirmed"; for receive it means
	// the target was reached. A no-wait `tx send` exits 0 on accepted broadcast
	// (0 != mined there, by design).
	ExitOK ExitCode = 0
	// ExitInternal is a daxib bug or unexpected panic.
	ExitInternal ExitCode = 1
	// ExitUsage is bad input: unknown flag/alias/wallet, malformed
	// address/amount, a fee flag that does not apply, or a confirmation needed
	// with no TTY and no --yes.
	ExitUsage ExitCode = 2
	// ExitPolicyDenied is a guardrail refusal *before* signing (spend limit,
	// destination allowlist, protected-UTXO refusal).
	ExitPolicyDenied ExitCode = 3
	// ExitAuth is a wrong/missing keystore passphrase or an undecryptable
	// keystore.
	ExitAuth ExitCode = 4
	// ExitInsufficientFunds is the Bitcoin funds lane: spendable balance <
	// value + fee, OR coin selection cannot assemble the spend (incl.
	// insufficient *confirmed* funds when unconfirmed inputs are excluded).
	ExitInsufficientFunds ExitCode = 5
	// ExitNetwork is a backend failure: the Bitcoin Core RPC / Electrum / Esplora
	// endpoint is unreachable/timeout/5xx, or a broadcast transport failure
	// (state journaled; resumable).
	ExitNetwork ExitCode = 6
	// ExitFeePolicyDenied is a fee-policy refusal: the computed fee or fee-rate
	// exceeds the operator's max-fee / max-fee-rate cap (anti-fee-burn, §3.8).
	// This is the Bitcoin repurposing of daxie's exit-7 contract-revert lane.
	ExitFeePolicyDenied ExitCode = 7
	// ExitTimeoutPending is the "wall is broken or still waiting" class: a wait
	// deadline hit with the tx still pending, receive still listening (NOT a
	// failure), and the policy seal/rollback/admin-auth/state class (all signing
	// halted).
	ExitTimeoutPending ExitCode = 8
	// ExitTxConflict is the double-spend / replacement family: an input was
	// already spent (bad-txns-inputs-missingorspent), an RBF speedup/cancel
	// target already confirmed, or a replacement was rejected.
	ExitTxConflict ExitCode = 9
	// ExitNotFound is an unknown reference, OR a read-only config/keystore
	// mutation attempt (the conflict/not-found class).
	ExitNotFound ExitCode = 10
	// ExitState is a state-dir problem: lock-acquisition timeout, corrupt
	// journal beyond tolerance.
	ExitState ExitCode = 11
	// ExitIntegrity is a tamper/misconfig tripwire: a backend whose network/genesis
	// disagrees with the declared network, insecure keystore file perms, or a
	// counted-tx reservation that has vanished.
	ExitIntegrity ExitCode = 12
)

// String returns the registry name for the exit code (e.g. ExitOK -> "OK"). An
// out-of-range code renders as "EXIT(<n>)".
func (c ExitCode) String() string {
	switch c {
	case ExitOK:
		return "OK"
	case ExitInternal:
		return "INTERNAL"
	case ExitUsage:
		return "USAGE"
	case ExitPolicyDenied:
		return "POLICY_DENIED"
	case ExitAuth:
		return "AUTH"
	case ExitInsufficientFunds:
		return "INSUFFICIENT_FUNDS"
	case ExitNetwork:
		return "NETWORK"
	case ExitFeePolicyDenied:
		return "FEE_POLICY_DENIED"
	case ExitTimeoutPending:
		return "TIMEOUT_PENDING"
	case ExitTxConflict:
		return "TX_CONFLICT"
	case ExitNotFound:
		return "NOT_FOUND"
	case ExitState:
		return "STATE"
	case ExitIntegrity:
		return "INTEGRITY"
	default:
		return "EXIT(" + itoa(int(c)) + ")"
	}
}

// itoa is a tiny dependency-free int->decimal (avoids pulling strconv into the
// String fast path; domain stays minimal). Handles the full int range.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	// Work in uint to handle math.MinInt without overflow on negation.
	var u uint
	if neg {
		u = uint(-(n + 1))
		u++
	} else {
		u = uint(n)
	}
	var buf [20]byte
	i := len(buf)
	for u > 0 {
		i--
		buf[i] = byte('0' + u%10)
		u /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
