// Package service is THE daxib core: the composition root and every use case
// (build → policy → sign → broadcast → wait). The CLI (internal/cli) and the MCP
// server (internal/mcpserver) are thin adapters over it — there is no second
// signing path to audit, and neither frontend can bypass the guardrails because
// the guardrails live BELOW both, inside one signing chokepoint (docs/PLAN.md
// §1, §5).
//
// M1 is the compiling skeleton: this package is an empty-but-real placeholder so
// the one-core/two-frontends import lattice (internal/arch_test.go) has a core to
// bind. The composition root (Open/Service), the keystore/descriptor wiring, the
// UTXO + coin-selection engine, the PSBT/tx pipeline, the sealed-policy engine,
// and the backend provider seam land in later milestones (docs/PLAN.md §8).
//
// Determinism is structural: this package must not import os/net/crypto-rand and
// must not call the time.Now family directly — it takes wall time only through an
// injected clock. (The guard arrives with the first real use case.)
package service
