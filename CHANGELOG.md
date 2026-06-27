# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Pre-alpha. The v1 feature set is complete on `main` but unreleased — interfaces
may still change before the first tagged release. Use a testnet and a small
mainnet float while evaluating.

### Added

- **M1 — skeleton + pipeline:** compiling one-core/two-frontends scaffold,
  `version` command (human + `--json`), the architecture lattice
  (`internal/arch_test.go`), and the CI/release pipeline (lint, race tests,
  cross-OS, six-target cross-compile, govulncheck, goreleaser, SHA-pinned actions).
- **M2 — keys + HD wallet:** BIP-39 mnemonics, BIP-84 derivation (P2WPKH bech32),
  an encrypted keystore (scrypt N=2¹⁸ + AES-256-GCM), verifier-based fail-fast
  unlock, and `wallet create/import/list/show/export` + `address new/list`.
- **M3 — backend:** one `Client` provider with **Bitcoin Core RPC** and **Esplora**
  implementations (default Core), a TOML backend config store with `${env:}`/
  `${file:}` secret refs, and `backend add/list/use/test/remove` + `balance` +
  `utxo list`.
- **M4 — transaction pipeline:** coin selection (BnB + fallback, accurate P2WPKH
  vsize), BIP-143 signing, an append-only crash-safe journal, and
  `tx send/status/list/wait` + `fee`. Sends signal RBF by default.
- **M5 — policy engine:** Ed25519-sealed spend policy (scrypt→HKDF→ed25519) with a
  config-class anchor, two passphrases (keystore vs admin), rolling-24h durable
  counters, per-tx / per-day / fee-rate caps, allow/deny lists, and the `policy`
  noun. Enforced in the one signing chokepoint, before signing.
- **M6 — MCP server:** the agent interface (Frontend 2) over the same core, with a
  narrowed, schema-locked tool surface and `mcp serve` / `mcp tools`. Guardrails
  bind MCP identically to the CLI.
- **testnet4 (BIP-94)** network support.
- **RBF (BIP-125):** `tx speedup` / `tx cancel` — fee-bump or void an unconfirmed
  send; policy charges only the fee delta; journal links original→replacement.

### Changed

- `policy set` now defaults the destination **allowlist OFF** (opt-in via
  `--allowlist on`); spend limits and the denylist are always enforced.

### Security

- Backend URLs carrying embedded credentials (API key in the path, or
  `user:pass@host`) are redacted in all error messages, logs, and masked views.
- Policy limit parsing and the rolling-24h counter now **fail closed**: a
  malformed/unit-suffixed limit is rejected at write time and never silently
  disables a cap; an unparseable limit or counter timestamp denies rather than
  lifting the guardrail.
- The broadcast reject-classifier is conservative: transient/unknown backend
  errors leave a record recoverable instead of terminalizing a possibly-live tx.

### Validated

- End-to-end on real Bitcoin **testnet**: a confirmed send, and a live RBF
  replacement (`tx speedup`) superseding a lower-fee transaction.
