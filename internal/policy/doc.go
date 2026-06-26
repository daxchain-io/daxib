// Package policy is daxib's M5 spend-limit guardrail engine — the security spine
// by which an operator sets limits an autonomous agent CANNOT raise. It owns the
// sealed policy file (policy.json, STATE class), the rolling-24h spend counters
// (STATE class, durable, fail-closed), the pure rule evaluator, and the admin
// mutation surface. The trust root (the anchor: verify key + KDF salt + nonce
// watermark) lives in the config class and is read directly by internal/config;
// the Ed25519 seal crypto lives in internal/policyseal.
//
// The package is a PURE evaluation function plus an IMPURE engine shell:
//
//   - Evaluate(p, req, spentWindowSat, now) is total and table-testable: no I/O, no
//     clock read, no lock. The window POLICY (rolling-24h) lives in how the caller
//     computes spentWindowSat (filter ts > now-24h) — Evaluate compares the numbers
//     it is handed.
//   - Engine.Reserve verifies the seal + anti-rollback nonce, sums the window under
//     a per-network flock, runs Evaluate, and (if allowed) durably appends a
//     reservation BEFORE the caller can sign. Commit on broadcast; Release on a
//     pre-sign failure. Two parallel sends cannot each pass a limit they jointly
//     exceed.
//
// Fail direction is fail-closed: once an anchor exists, an absent/unverifiable
// policy.json is itself a violation (the "delete the policy to escape it" hole is
// closed). With NO anchor AND no policy.json the engine is a permissive no-op
// (guardrails are opt-in — the petty-cash default). The admin secret and the
// keystore secret are INDEPENDENT (§3.7): a compromised agent holding the keystore
// passphrase gains nothing toward forging a seal or raising a limit.
//
// policy is a provider leaf: it imports domain, policyseal, fsx, and secret only —
// never the core (service) or a frontend. service drives orphan reconciliation
// (policy may not import journal).
package policy
