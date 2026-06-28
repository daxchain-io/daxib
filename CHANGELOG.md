# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-06-27

The first feature release on the stable v1.0 surface — **additive and
backward-compatible**. Every v1.0 command, `--json` schema, exit code, and on-disk
format is unchanged; this adds the `psbt` noun (and three MCP tools).

### Added

- **`psbt` — BIP-174 partially-signed Bitcoin transactions** for hardware-wallet /
  multisig / air-gapped interop, with no change to the custody model. Verbs:
  `create` (coin-select → unsigned PSBT), `sign`, `combine`, `finalize`, `extract`,
  `broadcast`, `decode`. **`psbt sign` enforces the sealed spend policy first** — it
  signs only the wallet's own inputs (matched by script, never a counterparty's
  derivation hint), re-verifies their values against the backend, runs the per-recipient
  allow/deny gate, and reserves the wallet's true net outflow (multisig-safe — never a
  co-signer's value) before a single byte is signed, so PSBT is not a guardrail bypass.
  New `internal/psbt` provider leaf over `btcd/btcutil/psbt`. MCP exposes
  `psbt_decode` / `psbt_sign` / `psbt_broadcast` (both signing tools policy-bound);
  `psbt_create` / `combine` / `finalize` / `extract` are operator-only (kept off the
  agent surface). Proven end-to-end against a real `bitcoind` regtest node in CI.

## [1.0.0] - 2026-06-27

First **stable** release. The CLI command surface, the `--json` schemas, the exit
codes, the MCP tool surface, and the on-disk formats (keystore, `meta.json` v2,
sealed policy anchor, tx journal) are now **semver-protected** — a breaking change
bumps the major version. daxib reaches full daxie-v1 command-surface parity,
hardened by a dedicated v1-readiness audit and validated end-to-end against a real
`bitcoind` regtest node in CI.

### Added

Command-surface parity with daxie's v1 — seven new nouns over the same one-core,
two-frontends architecture (CLI + MCP), each with a human form, `--json`, a
non-interactive path, and a documented exit code:

- **`sign` / `verify`** — BIP-322 "simple" message signing/verification for P2WPKH.
  `sign message <addr|wallet/branch/index>` produces a base64 signature (needs the
  keystore passphrase); `verify` is passphrase-free (reconstructs the BIP-322 virtual
  txs and runs the script engine). A well-formed-but-wrong signature is `valid=false`
  with exit `0`; malformed input is `usage.bad_signature` (exit `2`). New
  `internal/bip322` provider leaf.
- **`keystore`** — `info` (read-only: path, format, KDF, scrypt N, wallet count) and
  `change-passphrase`, an atomic two-phase (stage → commit-marker → swap) re-encryption
  of the verifier + every wallet blob under fresh per-file salts/nonces. Crash-safe:
  recovery on the next open rolls forward (marker present) or back (orphaned staging),
  never a mixed-passphrase keystore. Mandatory new-passphrase double-entry confirmation.
- **`receive`** — derive/peek a receive address, emit it immediately, then block until
  paid; NDJSON event stream (`listening → detected → confirmed → complete`) or a bounded
  `--timeout` (exit `8`, resumable). Detection is baselined at listen-start so a
  pre-existing balance is not a false positive.
- **`contacts`** — `add` / `list` / `show` / `remove` address book (state-class registry,
  per-network address validation). Names resolve in `tx send --to <name>` and
  `policy allow <name>`; a raw address always wins over a colliding contact name, and a
  contact name that parses as an address is rejected.
- **`convert`** — float-free sat ⇄ BTC conversion (bare numbers are BTC, per the
  `sendtoaddress` convention).
- **`completion`** — shell completion scripts for bash / zsh / fish / powershell.
- **`config`** — `get` / `set` / `list` over `config.toml` (per-network default backend).
  The sealed `policy.*` subtree is read-only here (`usage.policy_key`); an unknown key is
  `ref.not_found` (exit `10`).

Plus, from the v1-readiness pass:

- **`network`** — `use` / `show` / `list` to select + inspect the active network and
  persist a default (the `defaults.network` config key).
- **`tx abandon`** — an operator escape hatch that frees a never-broadcast `signed`
  tx's UTXOs and refunds its spend reservation. Refuses any tx with a recorded
  broadcast or a committed reservation (it may still confirm).
- **`policy release`** — admin-gated clearing of a stuck **pending** spend
  reservation (refuses a committed one).
- **5 new MCP tools** — `tx_speedup`, `tx_cancel`, `sign_message`, `verify`,
  `convert` (18 tools total), each under the same guardrails as its CLI counterpart.
- **Documentation set** — `docs/COMMANDS.md` (full reference), `docs/AGENTS.md`
  (driving daxib from an agent), `docs/SECURITY.md` (the security model), and
  `docs/CONFIGURATION.md` (paths, env, networks, backends).
- **Real-node integration suite** — a build-tagged regtest `bitcoind` end-to-end
  test (fund → send → confirm → RBF-replace → confirm) in its own CI workflow.

### Changed

- **Wallets are network-agnostic by default — one wallet, any network.** A
  newly created or imported wallet now stores both BIP-44 coin_type account xpubs
  (ct0 = mainnet, ct1 = all test nets) and derives addresses for whatever
  `--network` is active (bc1 on mainnet, tb1 on testnet/testnet4/signet, bcrt1 on
  regtest) from the same watermark. Pass `--bind` to `wallet create` / `wallet
  import` to opt into a **locked** wallet that stores only one network's coin_type
  and refuses ops on any other active network. The cross-network guard
  (`usage.network_mismatch`, exit 2) now fires **only for bound wallets**, and now
  also covers `sign message` (previously the one ungated key op) so a bound wallet
  is consistently locked across every operation. `wallet upgrade <name>` promotes a
  bound (or migrated-legacy) wallet to agnostic by deriving the missing coin_type.
  `meta.json` is bumped to format **v2** (per-coin_type `chains` + `scope`), with a
  lossless, passphrase-free on-read migration that maps every existing v1 wallet to
  a **bound** v2 wallet (persisted on its next write).

- **Default on-disk home is now a single `~/.daxib/` dotfolder** (holding `config.toml`,
  `keystore/`, and `state/`) instead of the platform XDG/AppData path
  (`~/.config/daxib` on Linux, `~/Library/Application Support/daxib` on macOS). One
  discoverable, easy-to-back-up directory; a deliberate divergence from daxie's
  `~/.config/daxie`. The `--config` / `--keystore` / `--state-dir` flags and the
  `DAXIB_CONFIG` / `DAXIB_KEYSTORE` / `DAXIB_STATE_DIR` env vars still override it. An
  existing alpha install under the old path keeps working if you point those at it (or
  move the directory to `~/.daxib`).

- **No silent network default.** Every network-using command now requires an
  explicit network (`--network` > `DAXIB_NETWORK` > a persisted `network use`
  default) and otherwise fails `usage.network_required` (exit 2) — it can no longer
  silently act on **mainnet**. (The built-in mainnet fallback was removed.)
- **`--yes` now gates a real confirmation.** `tx send` / `speedup` / `cancel` /
  `abandon` show a y/N prompt (recipient / amount / fee / network) at a TTY; `--yes`
  skips it, and a non-interactive run without `--yes` still fails closed.
- **Exit `7` (fee-policy-denied) is live again** and `retryable=true` for a
  fee-rate-cap denial, distinct from the exit-`3` per-tx / per-day / allow-deny
  denials.

### Security

- **Crash-safe admin-passphrase rotation.** `policy change-admin-passphrase` uses a
  three-phase staged rotation over a transitional dual-key anchor; recovery at the
  next open converges any crash point to a verifiable single-key anchor — the
  guardrails can never be left wiped or unverifiable mid-rotation.
- **No spend-budget refund for a possibly-live tx.** The offline reconciler leaves a
  still-`signed` (maybe-broadcast) transaction's rolling-24h reservation in place
  (fail closed) until an online path positively settles it.
- **`sign message` is now covered by the wallet network-scope guard** — the last
  ungated key operation, so a `--bind` wallet is consistently locked across every op.

## [0.1.3] - 2026-06-27

Build/release-pipeline parity with daxie. No change to the wallet itself.

### Added

- **`scripts/install.sh`** — a `curl | sh` installer (downloads + SHA256-verifies the
  release archive, optional `cosign verify-blob`, installs to a prefix). Folded into
  the release + `checksums.txt` so the one curl'd asset is self-verifying.
- **`.github/workflows/ci-install-script.yml`** — shellcheck + a snapshot-based
  install smoke (catches install.sh ↔ goreleaser drift before a release).
- **`.github/workflows/static.yml`** — markdownlint / shellcheck / actionlint CI.
- **`release.yml` hardening** to daxie parity: SLSA L3 **provenance**, a stable-only
  **cask-publish** two-phase (render → normalize checksums → push to the tap, holding
  the tap PAT off the build job), post-publish **install-smoke** (alpine/debian/ubuntu/
  fedora + macOS + a cosign-verify variant), and **image-smoke** (GHCR pull + cosign
  verify by digest). Plus the pre-approval asset-name + cosign-bundle gates in `verify`.

## [0.1.2] - 2026-06-27

A release-pipeline verification cut — no functional, dependency, or format changes
since 0.1.1.

## [0.1.1] - 2026-06-27

Maintenance: a Windows CI test fix and a Dependabot dependency refresh. No change to
the wallet's behavior or on-disk formats.

### Fixed

- `internal/fsx` `TestWriteAtomicCreatesAt0600` asserted POSIX `0600` permissions,
  which don't hold on Windows (Go reports `0666`; owner-only access is enforced by a
  DACL in `perms_windows.go`). The assertion is now POSIX-only, turning the
  windows-latest / windows-11-arm CI test jobs green.

### Changed

- Dependency refresh (Dependabot): `actions/setup-go` 6.4.0 → 6.5.0;
  `btcd/btcec/v2` 2.3.5 → 2.5.0, `btcd/chaincfg/chainhash` 1.1.0 → 1.2.0,
  `go-toml/v2` 2.4.0 → 2.4.2, `x/crypto` 0.47.0 → 0.53.0, `x/text` 0.33.0 → 0.38.0.

## [0.1.0] - 2026-06-27

First release — a cosign-signed GitHub Release, a Homebrew cask
(`brew install --cask daxchain-io/tap/daxib`), and a multi-arch GHCR image. Alpha:
the CLI surface and JSON schemas may still change before v1.0. Use a testnet and a
small mainnet float while evaluating.

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
