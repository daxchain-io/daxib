# Daxib

**The Bitcoin wallet for AI.** An agent-first Bitcoin CLI wallet in Go, with a
built-in MCP server. Non-interactive flags/env/stdin, `--json` everywhere,
deterministic exit codes, and **sealed spend-limit guardrails an autonomous agent
cannot raise** — over a one-core/two-frontends architecture, so the CLI and the MCP
server traverse the *exact same* wallet logic and the *exact same* guardrails.

Daxib is the Bitcoin sibling of [**daxie**](https://github.com/daxchain-io/daxie),
"the Ethereum wallet for AI" — the same security spine (two passphrases, an
Ed25519-sealed policy, one signing chokepoint) re-grounded on Bitcoin's UTXO model.

[![CI](https://github.com/daxchain-io/daxib/actions/workflows/ci.yml/badge.svg)](https://github.com/daxchain-io/daxib/actions/workflows/ci.yml)
[![Release](https://github.com/daxchain-io/daxib/actions/workflows/release.yml/badge.svg)](https://github.com/daxchain-io/daxib/actions/workflows/release.yml)
[![Go 1.26](https://img.shields.io/badge/go-1.26-00ADD8.svg)](https://go.dev/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

> **Status: `v1.0.0` — stable.** The CLI command surface, the `--json` schemas, the
> exit codes, the MCP tool surface, and the on-disk formats are **semver-protected**:
> a breaking change bumps the major version. Validated end-to-end against a real
> `bitcoind` regtest node in CI. Daxib signs and broadcasts real transactions and its
> custody is a hot keystore in one OS trust domain — keep mainnet balances to a
> petty-cash float and read [docs/SECURITY.md](docs/SECURITY.md) first.

---

## Install

### Homebrew (macOS / Linux)

```sh
brew install --cask daxchain-io/tap/daxib
```

### go install

```sh
go install github.com/daxchain-io/daxib/cmd/daxib@latest
```

Pure-Go (`CGO_ENABLED=0`). Skips checksum/signature verification — prefer a release
artifact for production.

### Direct download

Signed archives for darwin / linux / windows × amd64 / arm64 are on the
[releases page](https://github.com/daxchain-io/daxib/releases). Releases are
cosign-signed (keyless OIDC, Rekor transparency log) with SHA256 checksums; a
multi-arch, distroless, non-root OCI image is published to
`ghcr.io/daxchain-io/images/daxib`.

**Verify before you trust it.** Confirm the release was built and signed by this
repo's release workflow, then check your archive against the signed checksums:

```sh
# 1. verify the cosign keyless signature on checksums.txt. The identity flags are
#    REQUIRED — without them, cosign trusts ANY valid Sigstore signature.
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/daxchain-io/daxib/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

# 2. check your downloaded archive against the now-trusted checksums
#    (Linux: sha256sum; macOS: shasum -a 256):
sha256sum --check --ignore-missing checksums.txt
```

The `curl | sh` installer (with `--verify-signature`) and the `brew` cask do this
for you. See [docs/SECURITY.md](docs/SECURITY.md#supply-chain-verifying-a-release)
for the full recipe — the GHCR image signature, the SLSA provenance, and the SBOMs.

```sh
daxib version
```

---

## Quickstart

On **testnet**, against a free public Esplora backend (no node required):

```sh
# 1. Create a wallet (shows the mnemonic ONCE; encrypts it under your keystore passphrase).
#    Wallets are NETWORK-AGNOSTIC by default: this one wallet works on every
#    network. --network here only picks which HRP the printed receive address uses.
daxib wallet create treasury --network testnet

# 2. Point at a backend — your own bitcoind (Core RPC) or a light Esplora server.
daxib backend add esplora --network testnet --type esplora \
  --url https://blockstream.info/testnet/api
daxib backend use esplora

# 3. Get a receive address + check the balance (UTXO-derived; no passphrase needed).
daxib address new --wallet treasury --network testnet
daxib balance --wallet treasury --network testnet --json

# 4. Set guardrails. THIS uses the ADMIN passphrase, not the keystore passphrase.
daxib policy set --max-tx 100000 --max-fee-rate 50 --network testnet

# 5. Send — the policy is enforced in core, BEFORE signing.
daxib tx send --to tb1q... --amount 50000sat --network testnet --wait --yes --json

# 6. Bump a stuck transaction (RBF).
daxib tx speedup <txid> --fee-rate 10 --network testnet --yes

# 7. Serve the SAME wallet to an AI agent over MCP (stdio).
daxib mcp serve
```

Secrets arrive non-interactively for unattended/agent use:
`DAXIB_PASSPHRASE[_FILE]` (keystore / signing), `DAXIB_ADMIN_PASSPHRASE[_FILE]`
(policy), stdin for mnemonics. Every command has a `--json` form and a stable exit
code to branch on.

---

## What daxib does

Most Bitcoin tooling assumes a human at a terminal confirming each spend. Daxib
inverts that: it is built for an **autonomous agent** to hold a wallet and move sats
*within operator-set limits it cannot raise*.

- **Native Bitcoin essentials.** A BIP-39/BIP-84 HD wallet (native-SegWit `bech32`
  addresses), UTXO coin control, **sat/vByte fee policy** (so an unsupervised agent
  can't torch the treasury on fees), and **RBF** fee-bumping (`tx speedup` / `cancel`).
- **Two backends, your choice.** Talk to your own **bitcoind** (Core RPC, trust-
  minimized) or a light **Esplora** server — on mainnet, testnet, testnet4, signet, or
  regtest.
- **Sealed spend guardrails.** **Two passphrases**: the *keystore* passphrase unlocks
  signing (the agent may hold it); the *admin* passphrase authorizes policy changes
  (the agent never holds it). An **Ed25519-sealed policy** carries rolling-24h limits
  (per-tx / per-day / max fee-rate) and allow/deny lists, enforced in the **one signing
  chokepoint, before signing**. A fully prompt-hijacked agent can spend up to the
  limits — it cannot change them or read a key out.
- **One core, two frontends.** A single core owns every use case (gather UTXOs →
  coin-select → policy → sign → broadcast → wait). The **CLI** and the **MCP server**
  are thin adapters over it; neither can bypass the guardrails because they live
  *below* both frontends.

---

## Command surface

Every command ships a human form **and** `--json`, a non-interactive path, and a
documented exit code.

| Noun | Verbs |
|---|---|
| `wallet` | `create` · `import` · `list` · `show` · `export` · `upgrade` (bound → agnostic) |
| `keystore` | `info` · `change-passphrase` (atomic, crash-safe re-encryption) |
| `address` | `new` · `list` (BIP-84 receive / `--change`) |
| `receive` | wait for inbound funds — emits the address, then blocks until paid |
| `balance` | confirmed / unconfirmed, UTXO-derived |
| `utxo` | `list` |
| `tx` | `send` · `status` · `wait` · `list` · `speedup` (RBF) · `cancel` (RBF) · `abandon` |
| `fee` | sat/vB estimates + a recommendation |
| `psbt` | `create` · `sign` · `combine` · `finalize` · `extract` · `broadcast` · `decode` (BIP-174; `sign` is policy-bound) |
| `sign` / `verify` | BIP-322 "simple" message signing for P2WPKH (`verify` is passphrase-free) |
| `contacts` | `add` · `list` · `show` · `remove` — names resolve in `tx send --to` / `policy allow` |
| `backend` | `add` · `list` · `use` · `test` · `remove` (Bitcoin Core RPC / Esplora) |
| `policy` | `show` · `set` · `allow` · `deny` · `check` · `counters` · `verify` · `reset` · `pin` · `release` · `change-admin-passphrase` |
| `network` | `use` · `show` · `list` (select + persist the active network) |
| `config` | `get` · `set` · `list` (per-network default backend; the sealed `policy.*` subtree is read-only) |
| `mcp` | `serve` · `tools` |
| utility | `version` · `convert` (sat ⇄ BTC) · `completion` (bash/zsh/fish/powershell) |

Network is a global `--network mainnet\|testnet\|testnet4\|signet\|regtest` flag
that selects the active network for a command. Wallets are **network-agnostic by
default** — one wallet works on every network, and `--network` simply picks which
network the command operates on (and which HRP its addresses use). Create a wallet
with `--bind` to lock it to a single network; a bound wallet refuses ops (including
`sign message`) on any other active network with `usage.network_mismatch` (exit 2).
`wallet upgrade <name>` promotes a bound (or older, migrated) wallet to agnostic.

**Exit codes (stable):** `0` ok · `1` internal (a daxib bug) · `2` usage · `3`
policy-denied (spend-limit / allowlist / protected-UTXO) · `4` auth (keystore or admin
passphrase) · `5` insufficient funds (coin-selection) · `6` backend/network · `7`
fee-policy-denied (the computed fee-rate exceeds the max-fee-rate cap; **retryable** —
the fee market moves) · `8` timeout-pending / seal · `9` tx-conflict (double-spend /
RBF replacement; the **retryable** `tx.input_spent` re-select signal lives here) · `10`
not-found / read-only · `11` state-dir · `12` integrity tripwire.

---

## The agent / MCP story

`daxib mcp serve` exposes the wallet to any MCP client (Claude, an autonomous agent, a
custom harness) over **stdio**. The tool schemas are derived from the same Go structs
the CLI binds, so the two can never drift, and **the same guardrails bind both
frontends** — set the policy once with the CLI; every MCP `send` is checked against it.

The MCP surface is deliberately narrowed: it can **move funds within policy and read
everything**, but it **cannot** export keys, create/import wallets, mutate policy, or
change a backend — those are operator-only, out-of-band acts. List the tools with
`daxib mcp tools`.

```text
   operator domain  ───────────────────────────────────  agent domain (one uid)
   admin passphrase                                       keystore passphrase
   policy mutations         policy-anchor.json            daxib mcp serve / daxib <cmd>
   key export / backup     (verify key — read-only) ────► one core (coin-select→policy→sign)
        │                                                        │
        └── never crosses this line writably                    └─► signed tx ─► backend (broadcast)
```

---

## Security model

The objective, in one sentence: *a fully prompt-hijacked agent holding the keystore
passphrase must not be able to extract key material, spend beyond operator-set policy,
or change that policy — while a thief with the disk but no passphrase gets nothing.*

- **Two independent passphrases** (distinct salts + scrypt params): the keystore secret
  buys nothing toward forging policy.
- **Ed25519-sealed policy + a pinned anchor.** The agent host holds only the verify key
  (read directly, never via env/flag), so it can verify on every signing op but never
  forge. A tampered or rolled-back policy fails closed.
- **Rolling-24h limits** (per-tx, per-day, max fee-rate; fee included) on durable
  counters that survive restarts and fail closed on corruption, plus a destination
  allow/deny list.

This is the same posture as daxie v1, and it makes the same honest scoped claim:
custody is an encrypted local keystore inside **one OS trust domain** (the agent's
uid). The stronger Bitcoin-native postures (watch-only + external signer, Miniscript
co-sign) are on the roadmap below, not in this release.

---

## Roadmap

The roadmap lives in GitHub issues (label
[`roadmap`](https://github.com/daxchain-io/daxib/issues?q=is%3Aissue+is%3Aopen+label%3Aroadmap)),
grouped by milestone:

- **[v1.1](https://github.com/daxchain-io/daxib/milestone/1):** watch-only + external
  PSBT signer · CPFP fee-bumping
- **[v1.2](https://github.com/daxchain-io/daxib/milestone/2):** Runes / Ordinals
  (asset-aware coin control)
- **Backlog:** Miniscript / Taproot co-sign · Lightning + L402 · Silent Payments
  (BIP-352) · BIP-353 name resolution

PSBT (BIP-174) and BIP-322 message signing have shipped — see the command surface
above.

---

## Documentation

| Doc | What |
|---|---|
| [docs/COMMANDS.md](docs/COMMANDS.md) | The full command reference — every noun, verb, flag, exit code, and JSON shape |
| [docs/AGENTS.md](docs/AGENTS.md) | Driving daxib from an AI agent: the MCP tools, the secret env channels, the exit codes to branch on, and the safety contract |
| [docs/SECURITY.md](docs/SECURITY.md) | The security model: the two passphrases, the sealed policy, the threat model, and the honest residual |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Paths (`~/.daxib`), environment variables, networks, and backends (incl. the `txindex=1` requirement for a Core node) |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | The design rationale: one-core/two-frontends, the guardrail spine, the Bitcoin-native choices, and the daxie→daxib mapping |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

See the sibling project [daxie](https://github.com/daxchain-io/daxie) for the mature
Ethereum implementation whose architecture daxib mirrors.

## Risk notice

Daxib is provided under Apache-2.0 on an as-is basis. It signs and broadcasts
blockchain transactions, which may be irreversible and may result in loss of funds.
Review your configuration, policies, keys, backends, and transaction details before
using it with real assets. Use testnets and small balances while evaluating.

## License

[Apache License 2.0](LICENSE).
