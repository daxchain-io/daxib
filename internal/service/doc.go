// Package service is THE daxib core: the composition root and every use case
// (build → policy → sign → broadcast → wait). The CLI (internal/cli) and the MCP
// server (internal/mcpserver) are thin adapters over it — there is no second
// signing path to audit, and neither frontend can bypass the guardrails because
// the guardrails live BELOW both, inside one signing chokepoint (docs/PLAN.md
// §1, §5).
//
// M2 wires the first real use cases: the local keystore (BIP-39 mnemonics,
// BIP-84 HD derivation, the encrypted keystore) behind the `wallet` and `address`
// commands. The UTXO + coin-selection engine, the PSBT/tx pipeline, the
// sealed-policy engine, and the backend provider seam land in later milestones
// (docs/PLAN.md §8).
//
// Determinism is structural: this package threads wall time through an injected
// clock (Options.Clock) and acquires secrets through an injected SecretIO rather
// than reaching for os.Stdin / time.Now directly, so the core stays testable and
// frontend-agnostic.
package service
