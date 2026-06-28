# daxib command reference

`daxib` is an agent-first Bitcoin CLI wallet with a built-in MCP server: one
core, two thin frontends (CLI + MCP), non-interactive flags/env/stdin, `--json`
output, and deterministic exit codes. It speaks native SegWit (P2WPKH /
BIP-84) across five networks: `mainnet`, `testnet`, `testnet4`, `signet`, and
`regtest`.

This page is the authoritative reference for every command, flag, and exit
code. Every verb, flag, default, and exit number below was read from the built
binary and the source registry.

## Contents

- [Global flags](#global-flags)
- [Environment variables](#environment-variables)
- [Exit codes](#exit-codes)
- [Wallets and keys](#wallets-and-keys)
  - [wallet](#wallet)
  - [keystore](#keystore)
- [Addresses and funds](#addresses-and-funds)
  - [address](#address)
  - [receive](#receive)
  - [balance](#balance)
  - [utxo](#utxo)
- [Transactions and fees](#transactions-and-fees)
  - [tx](#tx)
  - [fee](#fee)
  - [psbt](#psbt)
- [Messages](#messages)
  - [sign](#sign)
  - [verify](#verify)
- [Operator surface](#operator-surface)
  - [contacts](#contacts)
  - [backend](#backend)
  - [policy](#policy)
  - [config](#config)
  - [network](#network)
- [The agent interface](#the-agent-interface)
  - [mcp](#mcp)
- [Utilities](#utilities)
  - [version](#version)
  - [convert](#convert)
  - [completion](#completion)

## Global flags

These persistent flags are bound on the root command and accepted by every
subcommand.

| Flag | Default | What it does |
| --- | --- | --- |
| `--network <net>` | none — must be resolved | Active Bitcoin network (`mainnet`/`testnet`/`testnet4`/`signet`/`regtest`). Overrides `DAXIB_NETWORK` and the persisted default for this call. |
| `--backend <name>` | network default | Named backend endpoint to dial (bitcoind RPC / Esplora); overrides the network's default backend for this call. |
| `--json` | off | Machine-readable JSON on stdout. |
| `--quiet` | off | Suppress non-essential human lines. |
| `-y`, `--yes` | off | Skip the interactive `y/N` confirmation prompt for irreversible ops (`tx send`/`speedup`/`cancel`/`abandon`); required for those ops when non-interactive. |
| `--config <dir>` | `~/.daxib` | Config directory holding `config.toml` (+ `policy-anchor.json`). |
| `--keystore <dir>` | `~/.daxib/keystore` | Keystore directory (encrypted wallet blobs + verifier). |
| `--state-dir <dir>` | `~/.daxib/state` | Mutable state directory (journal, counters, reservations, locks). |

### Network resolution (no silent default)

Any command that touches a network resolves it in this order:

1. `--network <net>` flag
2. `DAXIB_NETWORK` environment variable
3. The persisted default in `config.toml` (`defaults.network`, set via
   `network use`)
4. **Error** — `usage.network_required` (exit 2)

daxib never silently picks `mainnet` (or any network). A network-using command
with nothing resolved fails with exit 2.

### Wallets are network-agnostic by default

A wallet created with `wallet create` works on **every** network; `--network`
only selects which HRP the printed address uses. Opt into a single-network
lock with `wallet create --bind` (or promote a bound/legacy wallet later with
`wallet upgrade`).

## Environment variables

| Variable | Purpose |
| --- | --- |
| `DAXIB_NETWORK` | Active network (resolution rung 2). |
| `DAXIB_WALLET` | Default wallet name when `--wallet` is omitted. |
| `DAXIB_CONFIG` | Config directory (same as `--config`). |
| `DAXIB_KEYSTORE` | Keystore directory (same as `--keystore`). |
| `DAXIB_STATE_DIR` | State directory (same as `--state-dir`). |
| `DAXIB_PASSPHRASE` / `DAXIB_PASSPHRASE_FILE` | Keystore (signing) passphrase. The agent may hold this. |
| `DAXIB_NEW_PASSPHRASE` / `DAXIB_NEW_PASSPHRASE_FILE` | New keystore passphrase for `keystore change-passphrase`. |
| `DAXIB_NEW_PASSPHRASE_CONFIRM` / `DAXIB_NEW_PASSPHRASE_CONFIRM_FILE` | Confirmation of the new keystore passphrase. |
| `DAXIB_ADMIN_PASSPHRASE` / `DAXIB_ADMIN_PASSPHRASE_FILE` | Policy admin passphrase (policy mutations only). The agent never holds this. |

### Two passphrases, two roles

- **Keystore passphrase** unlocks signing keys (`tx send`, `sign message`,
  wallet export/upgrade). An agent running `mcp serve` may hold it.
- **Admin passphrase** authorizes policy mutations (`policy set`/`allow`/
  `deny`/`reset`/`change-admin-passphrase`/`release`). It is independent of the
  keystore passphrase, and the agent never holds it.

### Secret sourcing

Secrets never arrive as a flag value (so they cannot leak into a process
listing or shell history). Each passphrase/mnemonic has a stdin and a file
channel, plus an env channel where noted above:

- Keystore: `--passphrase-stdin` / `--passphrase-file <path>`
- New keystore (rotation): `--new-passphrase-stdin` / `--new-passphrase-file`,
  confirmed via `--new-passphrase-confirm-stdin` / `--new-passphrase-confirm-file`
- First-init confirmation: `--passphrase-confirm-stdin` /
  `--passphrase-confirm-file`
- Mnemonic (import): `--mnemonic-stdin` / `--mnemonic-file`
- BIP-39 passphrase / 25th word: `--bip39-passphrase-stdin` /
  `--bip39-passphrase-file`
- Admin: `--admin-passphrase-stdin` / `--admin-passphrase-file`
- New admin (rotation): `--new-admin-passphrase-stdin` /
  `--new-admin-passphrase-file`

Backend RPC credentials in `backend add` should be `${env:VAR}` / `${file:/path}`
references — they are stored raw and resolved only at dial time.

## Exit codes

daxib returns a small, agent-branchable set of process exit codes. The
canonical dotted `code` string (e.g. `policy.denied.day_limit`) namespaces finer
causes within one exit number; with `--json`, the error envelope carries both:

```json
{"error":{"code":"wallet.not_found","exit":10,"message":"...","retryable":false}}
```

| Exit | Name | Meaning | Representative codes |
| --- | --- | --- | --- |
| 0 | `OK` | Success. With `--wait`/`tx wait` it means *confirmed*; for `receive` the target was reached; a no-wait `tx send` exits 0 on *accepted broadcast*. A `verify` mismatch is also exit 0 (branch on the field). | — |
| 1 | `INTERNAL` | A daxib bug or unexpected panic; an unmatched error code. | `internal` |
| 2 | `USAGE` | Bad input: unknown flag/wallet, malformed address/amount/fee-rate/timeout, a confirmation needed with no TTY and no `--yes`, or no network resolved. | `usage`, `usage.bad_amount`, `usage.bad_address`, `usage.bad_fee_rate`, `usage.bad_timeout`, `usage.dust_output`, `usage.confirmation_required`, `usage.message_required`, `usage.bad_signature`, `usage.network_required`, `mnemonic.required`, `mnemonic.invalid`, `keystore.confirm_required`, `wallet.exists`, `backend.exists`, `config.invalid` |
| 3 | `POLICY_DENIED` | A guardrail refusal *before* signing: per-tx / per-day spend limit, or destination allow/deny list. | `policy.denied.*` (e.g. `policy.denied.tx_limit`, `policy.denied.day_limit`, `policy.denied.not_allowlisted`, `policy.denied.denylisted`) |
| 4 | `AUTH` | Wrong/missing keystore or admin passphrase, an undecryptable keystore, or an unresolvable secret reference. | `keystore.bad_passphrase`, `keystore.passphrase_required`, `policy.admin_auth`, `policy.admin_passphrase_required`, `secret.unresolved` |
| 5 | `INSUFFICIENT_FUNDS` | Spendable balance < amount + fee, or coin selection cannot assemble the spend (incl. insufficient *confirmed* funds). | `funds.insufficient`, `funds.insufficient_confirmed`, `coin.selection_failed` |
| 6 | `NETWORK` | Backend failure: the bitcoind RPC / Esplora endpoint is unreachable/timeout/5xx, an RPC error, or a permanent broadcast reject. | `backend.unreachable`, `backend.rpc_error`, `tx.broadcast_rejected`, `tx.rejected`, `tx.fee_too_low` |
| 7 | `FEE_POLICY_DENIED` | Anti-fee-burn: the computed fee rate exceeds the operator's max-fee-rate cap. Retryable (the fee market moves). | `policy.denied.fee_rate` |
| 8 | `TIMEOUT_PENDING` | A `--wait`/`receive` deadline hit with the tx still pending or the listener still waiting (not a failure — resume), or a policy seal/rollback/version/state class (signing halted). | `tx.wait_timeout`, `receive.timeout`, `policy.seal_violation`, `policy.rollback`, `policy.version`, `policy.state_error` |
| 9 | `TX_CONFLICT` | Double-spend / replacement family: an input was already spent, an RBF target already resolved, a replacement was rejected, or `tx abandon` refused a broadcast tx. | `tx.input_spent`, `tx.replaced`, `tx.replacement_rejected`, `tx.already_broadcast` |
| 10 | `NOT_FOUND` | Unknown reference, or a read-only config/keystore mutation attempt. | `ref.not_found`, `config.read_only`, `config.not_found`, `backend.not_found`, `backend.not_configured`, `keystore.read_only`, `keystore.not_found`, `wallet.not_found` |
| 11 | `STATE` | State-dir problem: lock-acquisition timeout, corrupt journal beyond tolerance. | `state.lock_timeout`, `state.corrupt` |
| 12 | `INTEGRITY` | Tamper/misconfig tripwire: a backend whose network/genesis disagrees with the declared network, insecure keystore file perms, or a derivation-watermark restore mismatch. | `backend.network_mismatch`, `keystore.perms_insecure`, `keystore.derivation_watermark` |

Codes `13..63` are reserved (never emitted); `64+` are never used so daxib does
not collide with BSD `sysexits(3)`.

## Wallets and keys

### wallet

Manage HD wallets (create, import, list, show, export, upgrade). BIP-39 seed,
BIP-84 native SegWit.

#### wallet create

```text
daxib wallet create <name> [flags]
```

Generates a fresh BIP-39 mnemonic, shows it **once**, and encrypts it into the
keystore. **Record the mnemonic** — it is the only backup and is never shown
again. On the first wallet, the keystore passphrase is confirmed by
double-entry (a typo cannot fork the keystore). The wallet is network-agnostic
unless `--bind` is given.

| Flag | Default | What it does |
| --- | --- | --- |
| `--words <12\|24>` | `12` | Mnemonic length. |
| `--bind` | off (agnostic) | Lock the wallet to the resolved `--network`, refusing ops on any other. |
| `--passphrase-stdin` / `--passphrase-file` | — | Keystore passphrase source. |
| `--passphrase-confirm-stdin` / `--passphrase-confirm-file` | — | First-init only: confirm the new keystore passphrase. |

- Exit codes: `0`; `2` (bad name / `wallet.exists` / `keystore.confirm_required`
  / `usage.network_required` when `--bind` and no network); `4`
  (`keystore.bad_passphrase` / `keystore.passphrase_required`); `10`
  (`keystore.read_only`); `11` (`state.lock_timeout`); `12`
  (`keystore.perms_insecure`).

```bash
DAXIB_PASSPHRASE=hunter2 daxib wallet create treasury --words 24
DAXIB_PASSPHRASE=hunter2 daxib --json wallet create alice
```

#### wallet import

```text
daxib wallet import <name> [flags]
```

Imports a BIP-39 mnemonic (NFKD-normalized, checksum-validated). The mnemonic
arrives only via `--mnemonic-stdin` / `--mnemonic-file`, never a flag value.
Network-agnostic unless `--bind`.

| Flag | Default | What it does |
| --- | --- | --- |
| `--bind` | off (agnostic) | Lock the wallet to the resolved `--network`. |
| `--mnemonic-stdin` / `--mnemonic-file` | — | BIP-39 mnemonic source (required input). |
| `--bip39-passphrase-stdin` / `--bip39-passphrase-file` | — | Optional BIP-39 passphrase (25th word). |
| `--passphrase-stdin` / `--passphrase-file` | — | Keystore passphrase source. |
| `--passphrase-confirm-stdin` / `--passphrase-confirm-file` | — | First-init only: confirm the new keystore passphrase. |

- Exit codes: `0`; `2` (`mnemonic.required` / `mnemonic.invalid` /
  `wallet.exists` / `usage.network_required`); `4` (keystore passphrase); `10`
  (`keystore.read_only`); `11`; `12`.

```bash
DAXIB_PASSPHRASE=hunter2 daxib wallet import restored --mnemonic-file ./seed.txt
```

#### wallet list

```text
daxib wallet list
```

Lists wallets (names, networks, address counts).

- Exit codes: `0`; `4` (locked keystore); `10` (`keystore.not_found`).

```bash
daxib --json wallet list
```

#### wallet show

```text
daxib wallet show <name>
```

Shows one wallet's detail (xpub, watermarks, address count).

- Exit codes: `0`; `2` (`usage.network_required` for an agnostic wallet with no
  network); `10` (`wallet.not_found`).

```bash
daxib --network testnet wallet show alice
```

#### wallet export

```text
daxib wallet export <name> [flags]
```

Prints the wallet's BIP-39 mnemonic and optional passphrase under explicit
labels. **Operator-only** — the agent's MCP surface never exposes this.

| Flag | Default | What it does |
| --- | --- | --- |
| `--passphrase-stdin` / `--passphrase-file` | — | Keystore passphrase source. |

- Exit codes: `0`; `4` (keystore passphrase); `10` (`wallet.not_found`).

```bash
DAXIB_PASSPHRASE=hunter2 daxib wallet export treasury
```

#### wallet upgrade

```text
daxib wallet upgrade <name> [flags]
```

Promotes a bound (or legacy) wallet to network-agnostic by deriving the missing
coin-type account key (one-time passphrase). An already-agnostic wallet is a
no-op error.

| Flag | Default | What it does |
| --- | --- | --- |
| `--passphrase-stdin` / `--passphrase-file` | — | Keystore passphrase source. |

- Exit codes: `0`; `2` (already agnostic); `4` (keystore passphrase); `10`
  (`wallet.not_found` / `keystore.read_only`); `11`.

```bash
DAXIB_PASSPHRASE=hunter2 daxib wallet upgrade legacy
```

### keystore

Keystore maintenance: re-encrypt under a new passphrase, inspect metadata.

#### keystore change-passphrase

```text
daxib keystore change-passphrase [flags]
```

Re-encrypts every keystore secret (the verifier and every wallet blob) under a
new passphrase. The rotation is **atomic and crash-safe** — a crash leaves the
all-old or all-new keystore, never a mix. **Operator-only**; no MCP tool
exposes this. Rotating under a running `mcp serve` requires restarting it.

| Flag | Default | What it does |
| --- | --- | --- |
| `--passphrase-stdin` / `--passphrase-file` | — | Old keystore passphrase (or `DAXIB_PASSPHRASE[_FILE]`). |
| `--new-passphrase-stdin` / `--new-passphrase-file` | — | New keystore passphrase (or `DAXIB_NEW_PASSPHRASE[_FILE]`). |
| `--new-passphrase-confirm-stdin` / `--new-passphrase-confirm-file` | — | Confirm the new passphrase (or `DAXIB_NEW_PASSPHRASE_CONFIRM[_FILE]`). |

- Exit codes: `0`; `2` (`keystore.confirm_required` / mismatch); `4`
  (`keystore.bad_passphrase` / `keystore.passphrase_required`); `10`
  (`keystore.read_only` / `keystore.not_found`); `11`; `12`
  (`keystore.perms_insecure`).

```bash
DAXIB_PASSPHRASE=old DAXIB_NEW_PASSPHRASE=new \
  DAXIB_NEW_PASSPHRASE_CONFIRM=new daxib keystore change-passphrase
```

#### keystore info

```text
daxib keystore info
```

Shows keystore path, format, KDF, and wallet count (read-only).

- Exit codes: `0`; `10` (`keystore.not_found`).

```bash
daxib --json keystore info
```

## Addresses and funds

### address

Derive and list wallet addresses (BIP-84 native SegWit).

#### address new

```text
daxib address new [flags]
```

Allocates the next receive (or `--change`) address.

| Flag | Default | What it does |
| --- | --- | --- |
| `--change` | off | Allocate an internal change address instead of a receive address. |
| `--wallet <name>` | `--wallet` > `DAXIB_WALLET` > default wallet | Wallet to derive from. |

- Exit codes: `0`; `2` (`usage.network_required`); `10` (`wallet.not_found` /
  `keystore.read_only`); `11`.

```bash
daxib --network testnet address new --wallet alice
```

#### address list

```text
daxib address list [flags]
```

Lists a wallet's derived addresses.

| Flag | Default | What it does |
| --- | --- | --- |
| `--wallet <name>` | `--wallet` > `DAXIB_WALLET` > default wallet | Wallet to list. |

- Exit codes: `0`; `2` (`usage.network_required`); `10` (`wallet.not_found`).

```bash
daxib --network testnet --json address list --wallet alice
```

### receive

```text
daxib receive [--wallet <w>] [--new] [--amount <v>] [flags]
```

Waits for inbound funds: derives/peeks a receive address, emits it
**immediately** (before blocking), then blocks until paid. Without `--new` the
next-unused receive address is peeked; `--new` derives a fresh receive index
(requires a writable keystore). With `--json` the output is a line-delimited
NDJSON event stream (`listening` -> `detected` -> `confirmed` -> `complete`);
on timeout the terminal line is `timeout` (exit 8 — not a failure; re-run to
resume, detection is stateless).

| Flag | Default | What it does |
| --- | --- | --- |
| `--wallet <name>` | `--wallet` > `DAXIB_WALLET` > default wallet | Wallet to receive on. |
| `--new` | off | Derive a fresh receive address (requires a writable keystore). |
| `--amount <v>` | any-inbound | Cumulative confirmed target: `<btc>` (e.g. `0.001`) or `<n>sat`. |
| `--confirmations <n>` | `1` | Confirmation target. |
| `--poll-interval <dur>` | `5s` | Backend poll cadence. |
| `--timeout <dur>` | none (unbounded) | Bounded listen, e.g. `30m`. Set one for agents. |

- Exit codes: `0` (target reached); `2` (`usage.network_required` / bad amount
  or timeout); `6` (`backend.unreachable`); `8` (`receive.timeout`); `10`
  (`wallet.not_found` / `keystore.read_only` with `--new`).

```bash
daxib --network testnet receive --wallet alice --amount 0.001 --timeout 30m
daxib --network testnet --json receive --new --confirmations 2
```

### balance

```text
daxib balance [flags]
```

Shows a wallet's confirmed/unconfirmed balance (UTXO-derived). Derives the
wallet's gap-window address set from its stored xpub (no passphrase), queries
the backend, and aggregates.

| Flag | Default | What it does |
| --- | --- | --- |
| `--wallet <name>` | `--wallet` > `DAXIB_WALLET` > default wallet | Wallet to total. |
| `--utxos` | off | Enumerate the individual UTXOs. |

- Exit codes: `0`; `2` (`usage.network_required`); `6` (`backend.unreachable` /
  `backend.rpc_error`); `10` (`wallet.not_found` / `backend.not_configured`);
  `12` (`backend.network_mismatch`).

```bash
daxib --network testnet balance --wallet alice
daxib --network testnet --json balance --wallet alice --utxos
```

### utxo

Inspect a wallet's unspent transaction outputs.

#### utxo list

```text
daxib utxo list [flags]
```

Lists a wallet's UTXOs (outpoint, address, value, confirmations).

| Flag | Default | What it does |
| --- | --- | --- |
| `--wallet <name>` | `--wallet` > `DAXIB_WALLET` > default wallet | Wallet to inspect. |

- Exit codes: `0`; `2` (`usage.network_required`); `6` (backend); `10`
  (`wallet.not_found` / `backend.not_configured`); `12`.

```bash
daxib --network testnet --json utxo list --wallet alice
```

## Transactions and fees

### tx

Send Bitcoin and inspect transactions (send/status/wait/list, plus RBF and
recovery).

#### tx send

```text
daxib tx send [flags]
```

Builds, signs, and broadcasts a transaction. Coin-selects from confirmed UTXOs,
then **policy-checks the spend before a single byte is signed** — a denied or
over-limit send produces no signature and moves no funds. A no-wait send exits
0 on accepted broadcast; `--wait` blocks for confirmation. Requires `--yes`
when non-interactive (no TTY).

| Flag | Default | What it does |
| --- | --- | --- |
| `--to <addr>` | — | Recipient address (bech32 P2WPKH or any standard address); a contact name is also accepted. |
| `--amount <v>` | — | Amount to send: `<btc>` (e.g. `0.001`) or `<n>sat` (e.g. `150000sat`). |
| `--fee-rate <sat/vB>` | estimate by `--speed` | Fee rate in sat/vByte. |
| `--speed <slow\|normal\|fast>` | `normal` | Fee tier when `--fee-rate` is unset. |
| `--wait` | off | Wait for confirmation before returning. |
| `--confirmations <n>` | `1` | Confirmations to wait for (with `--wait`). |
| `--timeout <dur>` | — | Max wait duration with `--wait` (e.g. `30m`). |
| `--dry-run` | off | Build + select + estimate + preview; sign/broadcast nothing. |
| `--wallet <name>` | `--wallet` > `DAXIB_WALLET` > default wallet | Sender wallet. |

- Exit codes: `0`; `2` (`usage.bad_amount` / `usage.bad_address` /
  `usage.bad_fee_rate` / `usage.bad_timeout` / `usage.dust_output` /
  `usage.confirmation_required` / `usage.network_required`); `3`
  (`policy.denied.*` spend limit / allow-deny list); `4` (keystore passphrase);
  `5` (`funds.insufficient` / `coin.selection_failed`); `6`
  (`backend.unreachable` / `tx.broadcast_rejected` / `tx.fee_too_low`); `7`
  (`policy.denied.fee_rate`); `8` (`tx.wait_timeout` with `--wait`; policy seal
  class); `9` (`tx.input_spent`); `10` (`wallet.not_found` /
  `backend.not_configured`); `11`; `12`.

```bash
DAXIB_PASSPHRASE=hunter2 daxib --network testnet tx send \
  --wallet alice --to tb1q... --amount 0.001 --yes
DAXIB_PASSPHRASE=hunter2 daxib --network testnet --json tx send \
  --wallet alice --to tb1q... --amount 150000sat --fee-rate 5 --wait --yes
daxib --network testnet tx send --wallet alice --to tb1q... --amount 0.001 --dry-run
```

#### tx status

```text
daxib tx status <txid>
```

Shows a transaction's status (journal record folded with a single live backend
re-check; never broadcasts).

- Exit codes: `0`; `2` (`usage.network_required`); `6` (backend); `10`
  (`ref.not_found`).

```bash
daxib --network testnet --json tx status <txid>
```

#### tx wait

```text
daxib tx wait <txid> [flags]
```

Waits for a transaction to confirm. Rebroadcasts a still-signed journal record
first (the lost-broadcast window), then polls.

| Flag | Default | What it does |
| --- | --- | --- |
| `--confirmations <n>` | `1` | Confirmations to wait for. |
| `--timeout <dur>` | `30m` | Max wait duration (e.g. `30m`). |

- Exit codes: `0` (confirmed); `2` (`usage.network_required` /
  `usage.bad_timeout`); `6` (backend); `8` (`tx.wait_timeout` — re-run to
  resume); `10` (`ref.not_found`).

```bash
daxib --network testnet tx wait <txid> --confirmations 3 --timeout 1h
```

#### tx list

```text
daxib tx list [flags]
```

Lists journaled transactions (newest-first).

| Flag | Default | What it does |
| --- | --- | --- |
| `--limit <n>` | `0` (all) | Max rows. |
| `--wallet <name>` | all wallets | Filter to a wallet. |

- Exit codes: `0`; `2` (`usage.network_required`); `11`.

```bash
daxib --network testnet --json tx list --wallet alice --limit 20
```

#### tx speedup

```text
daxib tx speedup <txid> [flags]
```

Replaces an unconfirmed, RBF-signaling send with a higher-fee transaction
paying the **same recipient** (BIP-125). The replacement is policy-checked
before signing exactly like a fresh send. Requires `--yes` when non-interactive.

| Flag | Default | What it does |
| --- | --- | --- |
| `--fee-rate <sat/vB>` | backend fast tier, never below original + 1 | New fee rate in sat/vByte. |
| `--wait` | off | Wait for confirmation before returning. |
| `--confirmations <n>` | `1` | Confirmations to wait for (with `--wait`). |
| `--timeout <dur>` | — | Max wait duration with `--wait`. |
| `--wallet <name>` | `--wallet` > `DAXIB_WALLET` > default | Wallet that owns the tx. |

- Exit codes: `0`; `2` (usage / `usage.network_required`); `3`
  (`policy.denied.*`); `4` (keystore passphrase); `6` (backend); `7`
  (`policy.denied.fee_rate`); `8` (`tx.wait_timeout`; seal class); `9`
  (`tx.replaced` / `tx.replacement_rejected` / `tx.input_spent`); `10`
  (`ref.not_found`); `11`.

```bash
DAXIB_PASSPHRASE=hunter2 daxib --network testnet tx speedup <txid> --fee-rate 12 --yes
```

#### tx cancel

```text
daxib tx cancel <txid> [flags]
```

Cancels an unconfirmed, RBF-signaling send by replacing it with a higher-fee
self-paying transaction that redirects all funds to a fresh wallet-owned change
address, voiding the original payment (BIP-125). Policy-checked before signing
(paying yourself satisfies destination rules; the fee-rate cap still applies).
Requires `--yes` when non-interactive. Flags mirror `tx speedup`.

| Flag | Default | What it does |
| --- | --- | --- |
| `--fee-rate <sat/vB>` | backend fast tier, never below original + 1 | New fee rate in sat/vByte. |
| `--wait` | off | Wait for confirmation before returning. |
| `--confirmations <n>` | `1` | Confirmations to wait for (with `--wait`). |
| `--timeout <dur>` | — | Max wait duration with `--wait`. |
| `--wallet <name>` | `--wallet` > `DAXIB_WALLET` > default | Wallet that owns the tx. |

- Exit codes: same set as `tx speedup` (`0`/`2`/`3`/`4`/`6`/`7`/`8`/`9`/`10`/`11`).

```bash
DAXIB_PASSPHRASE=hunter2 daxib --network testnet tx cancel <txid> --yes
```

#### tx abandon

```text
daxib tx abandon <txid> [flags]
```

Recovers a signed-but-never-broadcast transaction whose inputs are otherwise
locked out of coin-selection forever: terminalizes the journal record as
`failed` (freeing its UTXOs) and releases its policy reservation. **Refuses any
tx with a recorded broadcast** (it may still confirm). Irreversible — requires
`--yes`.

| Flag | Default | What it does |
| --- | --- | --- |
| `--wallet <name>` | `--wallet` > `DAXIB_WALLET` > default | Wallet that owns the tx. |

- Exit codes: `0`; `2` (`usage.confirmation_required` without `--yes`;
  `usage.network_required`); `9` (`tx.already_broadcast`); `10`
  (`ref.not_found`); `11`.

```bash
daxib --network testnet tx abandon <txid> --yes
```

### fee

```text
daxib fee [flags]
```

Shows backend fee estimates (sat/vB) at three speeds plus a recommendation and
the relay floor.

| Flag | Default | What it does |
| --- | --- | --- |
| `--speed <slow\|normal\|fast>` | `normal` | Which tier is the headline recommendation. |

- Exit codes: `0`; `2` (`usage.network_required`); `6` (`backend.unreachable` /
  `backend.rpc_error`); `10` (`backend.not_configured`).

```bash
daxib --network testnet fee --speed fast
daxib --network testnet --json fee
```

### psbt

BIP-174 partially-signed Bitcoin transactions — for hardware-wallet, multisig, and
air-gapped interop. A PSBT is passed as a positional base64 argument, `--psbt-file
<path>`, or `--psbt-stdin`; output is base64 to stdout (or `--out <file>`), so the
verbs pipe (`daxib psbt create … | daxib psbt sign --psbt-stdin`).

- **`psbt create`** — coin-select the wallet's confirmed UTXOs to `--to`/`--amount`
  and emit an UNSIGNED, fully-populated PSBT (prevout values + BIP-32 derivation).
  Advances the change index; takes no policy reservation and signs nothing. Same fee
  flags as `tx send` (`--fee-rate` / `--speed`).
- **`psbt sign`** — **the policy chokepoint.** Detects the wallet's own inputs (by
  script match), re-verifies their values against the backend, runs the per-recipient
  allow/deny gate, and reserves the wallet's net outflow against the sealed limits
  **before** signing — then attaches a partial signature to each owned input only
  (foreign co-signer inputs are left untouched). Needs the keystore passphrase;
  `--yes` skips the confirmation. Does not finalize.
- **`psbt combine`** — merge PSBTs that share the same unsigned tx, unioning partial
  signatures (multisig co-signer collection). Pure; rejects a merge of differing txs.
- **`psbt finalize`** — assemble the final witness from the collected partial
  signatures. Pure.
- **`psbt extract`** — emit the raw network transaction (hex) from a finalized PSBT.
  Pure.
- **`psbt broadcast`** — finalize-if-needed, extract, and submit through the active
  backend (the same broadcast + journal path as `tx send`); `--yes` gated.
- **`psbt decode`** — inspect a PSBT (inputs/outputs/fee/which-are-mine/signed/
  complete), human or `--json`. Read-only, passphrase-free.

Over MCP only `psbt_decode`, `psbt_sign`, and `psbt_broadcast` are exposed (the last
two policy-bound); `psbt_create`/`combine`/`finalize`/`extract` are operator-only.

- Exit codes: `0`; `2` (`usage.psbt_required`, `usage.bad_psbt`, `psbt.not_owned`,
  `psbt.incomplete`, `psbt.combine_mismatch`); `3` (`policy.denied.*`); `4`
  (`keystore.bad_passphrase`); `7` (`policy.denied.fee_rate`); plus the `tx send`
  lanes on `psbt broadcast`.

```bash
# air-gapped: create online, sign offline, broadcast online
daxib --network testnet psbt create --to tb1q... --amount 50000sat --out unsigned.psbt
daxib --network testnet psbt sign --psbt-file unsigned.psbt --out signed.psbt
daxib --network testnet psbt broadcast --psbt-file signed.psbt --yes --json
daxib --network testnet psbt decode --psbt-file signed.psbt --json
```

## Messages

### sign

BIP-322 message signing.

#### sign message

```text
daxib sign message <address|wallet/branch/index> [flags]
```

Signs a message with the private key behind a P2WPKH address using BIP-322
"simple". The signing target is an address or a `<wallet>/<branch>/<index>` ref.
Unlocking the key needs the keystore passphrase. The base64 signature is
verifiable with `daxib verify` (no passphrase).

| Flag | Default | What it does |
| --- | --- | --- |
| `--message <text>` | — | The message to sign (inline). |
| `--message-file <path>` | — | Read the message from a file. |
| `--message-stdin` | — | Read the message from stdin. |
| `--wallet <name>` | `--wallet` > `DAXIB_WALLET` | Wallet to scope the address lookup. |
| `--passphrase-stdin` / `--passphrase-file` | — | Keystore passphrase source. |

- Exit codes: `0`; `2` (`usage.message_required` / `usage.bad_address` /
  `usage.network_required`); `4` (keystore passphrase); `10`
  (`wallet.not_found`).

```bash
DAXIB_PASSPHRASE=hunter2 daxib --network testnet sign message alice/0/0 \
  --message "proof of control"
```

### verify

```text
daxib verify [flags]
```

Verifies a BIP-322 "simple" signature for an address + message.
**Passphrase-free.** A well-formed signature that does **not** match returns
`valid=false` with **exit 0** (not an error) — branch on the field. The message
arrives via `--message`, `--message-file`, or `--message-stdin`.

| Flag | Default | What it does |
| --- | --- | --- |
| `--address <addr>` | — | The P2WPKH address that signed the message. |
| `--signature <b64>` | — | The base64 BIP-322 signature to verify. |
| `--message <text>` | — | The signed message (inline). |
| `--message-file <path>` | — | Read the signed message from a file. |
| `--message-stdin` | — | Read the signed message from stdin. |

- Exit codes: `0` (matched **or** not matched — branch on `valid`); `2`
  (`usage.message_required` / `usage.bad_address` / `usage.bad_signature` /
  `usage.network_required`).

```bash
daxib --network testnet --json verify \
  --address tb1q... --signature Akcw... --message "proof of control"
```

## Operator surface

### contacts

Local address book mapping a name to a network-scoped Bitcoin address. Any
`--to` (and `policy allow`) accepts a contact name in place of a raw address.

#### contacts add

```text
daxib contacts add <name> <address> [flags]
```

Adds a contact. The name follows the 1-64 char `[a-z0-9_-]` grammar; the
address is validated against the active `--network` and pinned. A duplicate
name is a usage error.

| Flag | Default | What it does |
| --- | --- | --- |
| `--label <text>` | — | Optional operator note stored with the contact. |

- Exit codes: `0`; `2` (`usage.network_required` / bad name / bad address /
  duplicate); `10` (`config.read_only`).

```bash
daxib --network testnet contacts add exchange tb1q... --label "cold deposit"
```

#### contacts list

```text
daxib contacts list
```

Lists contacts (name-sorted).

- Exit codes: `0`; `2` (`usage.network_required`).

```bash
daxib --network testnet --json contacts list
```

#### contacts show

```text
daxib contacts show <name>
```

Shows one contact by name.

- Exit codes: `0`; `2` (`usage.network_required`); `10` (`ref.not_found`).

```bash
daxib --network testnet contacts show exchange
```

#### contacts remove

```text
daxib contacts remove <name>
```

Removes a contact by name.

- Exit codes: `0`; `2` (`usage.network_required`); `10` (`ref.not_found` /
  `config.read_only`).

```bash
daxib --network testnet contacts remove exchange
```

### backend

Manage Bitcoin backends (bitcoind RPC / Esplora). Secrets should be
`${env:VAR}` / `${file:/path}` references — stored raw, resolved only at dial
time.

#### backend add

```text
daxib backend add <name> [flags]
```

Adds a named backend endpoint bound to a network.

| Flag | Default | What it does |
| --- | --- | --- |
| `--type <core\|esplora>` | — | Backend type: `core` (bitcoind RPC) or `esplora` (REST). |
| `--url <url>` | — | Endpoint URL (Core: JSON-RPC; Esplora: REST base). |
| `--network <net>` | active `--network` | Network this backend serves. |
| `--rpcuser <ref>` | — | Core RPC username (`${env:}`/`${file:}` ref or literal). |
| `--rpcpassword <ref>` | — | Core RPC password (`${env:}`/`${file:}` ref — avoid literals). |
| `--rpccookie <path>` | — | Path to a bitcoind `.cookie` file (alternative to user/password). |

- Exit codes: `0`; `2` (`backend.exists` / bad type or URL / missing network);
  `10` (`config.read_only`).

```bash
daxib backend add core-test --type core --network testnet \
  --url http://127.0.0.1:18332 --rpccookie ~/.bitcoin/testnet3/.cookie
daxib backend add blockstream --type esplora --network mainnet \
  --url https://blockstream.info/api
```

#### backend list

```text
daxib backend list
```

Lists configured backends (masked URLs).

- Exit codes: `0`.

```bash
daxib --json backend list
```

#### backend test

```text
daxib backend test [name]
```

Dials the named backend (or the active network's default) and calls TipHeight,
reporting the observed block height and round-trip latency. A dead endpoint
exits 6.

- Exit codes: `0`; `2` (`usage.network_required` when no name and no default
  network); `6` (`backend.unreachable` / `backend.rpc_error`); `10`
  (`backend.not_found` / `backend.not_configured`); `12`
  (`backend.network_mismatch`).

```bash
daxib backend test core-test
daxib --network testnet --json backend test
```

#### backend use

```text
daxib backend use <name>
```

Makes a backend the default for its network (persisted in `config.toml`).

- Exit codes: `0`; `10` (`backend.not_found` / `config.read_only`).

```bash
daxib backend use core-test
```

#### backend remove

```text
daxib backend remove <name>
```

Removes a backend (clears any network default that pointed at it).

- Exit codes: `0`; `10` (`backend.not_found` / `config.read_only`).

```bash
daxib backend remove core-test
```

### policy

The sealed spend-limit guardrails: an operator sets limits an autonomous agent
cannot raise. Limits are sealed (Ed25519 over `scrypt(admin-passphrase)`) and
pinned in a machine-only anchor, enforced in the one signing chokepoint
**before** signing. `show`/`verify`/`check`/`counters`/`pin` are read-only;
`set`/`allow`/`deny`/`reset`/`change-admin-passphrase`/`release` require the
admin passphrase.

#### policy show

```text
daxib policy show
```

Shows the active policy + seal status (read-only).

- Exit codes: `0`; `2` (`usage.network_required`); `8` (`policy.seal_violation`
  / `policy.rollback` / `policy.version`).

```bash
daxib --network mainnet --json policy show
```

#### policy set

```text
daxib policy set [flags]
```

Sets guardrails under the admin passphrase. Limits accept a sat amount, the
literal `none` to lift the limit, or are omitted to leave unchanged. The
**first** `policy set` bootstraps the anchor (a fresh keypair + salt +
watermark). On a read-only config mount, pass `--anchor-out` to land the new
anchor JSON out-of-band.

| Flag | Default | What it does |
| --- | --- | --- |
| `--max-tx <sats\|none>` | unchanged | Per-tx limit in sats (amount + fee). |
| `--max-day <sats\|none>` | unchanged | Rolling-24h limit in sats (fee included). |
| `--max-fee-rate <sat/vB\|none>` | unchanged | Max fee rate (anti-fee-burn). |
| `--allowlist <on\|off>` | unchanged | Require allowlisted recipients. |
| `--include-self <on\|off>` | unchanged | Let own/change addresses pass the allowlist. |
| `--network <net>` | the default block | Scope the rule to one network. |
| `--anchor-out <path>` | — | On a read-only config mount, write the anchor JSON here. |
| `--admin-passphrase-stdin` / `--admin-passphrase-file` | — | Admin passphrase source. |

> Note: on `policy set` the `--network` flag scopes the rule (it is not the
> global active-network override). The other resolution rungs (`DAXIB_NETWORK`,
> persisted default) are not consulted for this scope.

- Exit codes: `0`; `2` (bad value); `4` (`policy.admin_auth` /
  `policy.admin_passphrase_required`); `8` (`policy.seal_violation` /
  `policy.rollback`); `10` (`config.read_only` without `--anchor-out`); `11`.

```bash
DAXIB_ADMIN_PASSPHRASE=admin-secret daxib policy set \
  --max-tx 500000 --max-day 2000000 --max-fee-rate 50
DAXIB_ADMIN_PASSPHRASE=admin-secret daxib policy set \
  --network mainnet --allowlist on --include-self on
```

#### policy allow / policy deny

```text
daxib policy allow <address> [flags]
daxib policy deny  <address> [flags]
```

Add (or `--remove`) an allowlist / denylist address pin under the admin
passphrase. A contact name is accepted in place of an address.

| Flag | Default | What it does |
| --- | --- | --- |
| `--remove` | off | Remove the pin instead of adding it. |
| `--label <text>` | — | Operator note stored with the pin. |
| `--anchor-out <path>` | — | On a read-only config mount, write the anchor JSON here. |
| `--admin-passphrase-stdin` / `--admin-passphrase-file` | — | Admin passphrase source. |

- Exit codes: `0`; `2` (bad address / `usage.network_required`); `4`
  (`policy.admin_auth` / `policy.admin_passphrase_required`); `8` (seal class);
  `10` (`config.read_only` without `--anchor-out`); `11`.

```bash
DAXIB_ADMIN_PASSPHRASE=admin-secret daxib --network mainnet \
  policy allow bc1q... --label "treasury cold"
DAXIB_ADMIN_PASSPHRASE=admin-secret daxib --network mainnet \
  policy deny bc1q... --remove
```

#### policy check

```text
daxib policy check [flags]
```

Dry-run evaluates a hypothetical send against the active policy — no
reservation, no signing. Returns `allowed:true`, or `allowed:false` with the
dotted denial code.

| Flag | Default | What it does |
| --- | --- | --- |
| `--to <addr>` | — | Recipient address. |
| `--amount <v>` | — | Amount (sats or BTC, like `tx send`). |
| `--fee-rate <sat/vB>` | — | Assumed fee rate. |
| `--fee-sat <sats>` | — | Assumed absolute fee in sats. |

- Exit codes: `0` (allowed); `2` (`usage.network_required` / bad input); `3`
  (`policy.denied.*` spend limit / allow-deny list); `7`
  (`policy.denied.fee_rate`); `8` (seal class).

```bash
daxib --network mainnet --json policy check --to bc1q... --amount 0.01 --fee-rate 20
```

#### policy counters

```text
daxib policy counters
```

Shows rolling-24h spend usage per network (read-only).

- Exit codes: `0`; `2` (`usage.network_required`); `11`.

```bash
daxib --network mainnet --json policy counters
```

#### policy verify

```text
daxib policy verify
```

Verifies `policy.json` under the pinned anchor (passphrase-free).

- Exit codes: `0` (verifies); `8` (`policy.seal_violation` — does not verify).

```bash
daxib policy verify
```

#### policy pin

```text
daxib policy pin [flags]
```

Prints the pinned anchor (default) or canary-verifies `policy.json` under a
supplied key.

| Flag | Default | What it does |
| --- | --- | --- |
| `--verify <ed25519:key>` | — | Canary: does `policy.json` verify under this key? |

- Exit codes: `0` (verifies / printed); `8` (`policy.seal_violation` with
  `--verify`).

```bash
daxib --json policy pin
daxib policy pin --verify ed25519:<base64-key>
```

#### policy reset

```text
daxib policy reset [flags]
```

Re-seals a fresh default policy under the **existing** key (admin passphrase).
Destructive — requires `--force`.

| Flag | Default | What it does |
| --- | --- | --- |
| `--force` | off | Required acknowledgement (destructive). |
| `--anchor-out <path>` | — | On a read-only config mount, write the anchor JSON here. |
| `--admin-passphrase-stdin` / `--admin-passphrase-file` | — | Admin passphrase source. |

- Exit codes: `0`; `2` (missing `--force`); `4` (`policy.admin_auth` /
  `policy.admin_passphrase_required`); `8` (seal class); `10`
  (`config.read_only` without `--anchor-out`); `11`.

```bash
DAXIB_ADMIN_PASSPHRASE=admin-secret daxib policy reset --force
```

#### policy change-admin-passphrase

```text
daxib policy change-admin-passphrase [flags]
```

Rotates the admin passphrase (re-derives + re-seals under a new key).

| Flag | Default | What it does |
| --- | --- | --- |
| `--admin-passphrase-stdin` / `--admin-passphrase-file` | — | Current admin passphrase source. |
| `--new-admin-passphrase-stdin` / `--new-admin-passphrase-file` | — | New admin passphrase source. |
| `--anchor-out <path>` | — | On a read-only config mount, write the anchor JSON here. |

- Exit codes: `0`; `4` (`policy.admin_auth` /
  `policy.admin_passphrase_required`); `8` (seal class); `10`
  (`config.read_only` without `--anchor-out`); `11`.

```bash
DAXIB_ADMIN_PASSPHRASE=old DAXIB_ADMIN_NEW_PASSPHRASE=new \
  daxib policy change-admin-passphrase
```

#### policy release

```text
daxib policy release <reservation-id> [flags]
```

Releases a **stuck pending** pre-signature spend reservation so a crash between
reserve and settle does not strand the rolling-24h budget. Admin-gated; refuses
a committed reservation. Irreversible — requires `--yes`.

| Flag | Default | What it does |
| --- | --- | --- |
| `--admin-passphrase-stdin` / `--admin-passphrase-file` | — | Admin passphrase source. |

- Exit codes: `0`; `2` (`usage.confirmation_required` without `--yes`); `4`
  (`policy.admin_auth`); `9` (refused a committed reservation); `10`
  (`ref.not_found`); `11`.

```bash
DAXIB_ADMIN_PASSPHRASE=admin-secret daxib policy release <reservation-id> --yes
```

### config

Inspect and modify operator settings in `config.toml`. Named backends are
managed with `backend`; policy keys live in the sealed policy file and are set
only via `policy` (`config set policy.<key>` is rejected).

#### config get

```text
daxib config get <key>
```

Prints one config key's effective value.

- Exit codes: `0`; `10` (`ref.not_found` / `config.not_found`).

```bash
daxib config get networks.mainnet.default-backend
```

#### config set

```text
daxib config set <key> <value>
```

Writes one operator key into `config.toml` via an atomic, locked rewrite.
Settable: `networks.<network>.default-backend` (empty clears it). `policy.*`
keys are rejected; a read-only mount fails with `config.read_only` (exit 10).

- Exit codes: `0`; `2` (`config.invalid` / `policy.*` rejected); `10`
  (`config.read_only` / `ref.not_found` for an unknown backend or network).

```bash
daxib config set networks.testnet.default-backend core-test
```

#### config list

```text
daxib config list
```

Lists all operator config keys with their effective values and sources.

- Exit codes: `0`.

```bash
daxib --json config list
```

### network

Select and inspect the active network without a silent default.

#### network use

```text
daxib network use <net>
```

Persists the default active network into `config.toml` (`defaults.network`, the
third resolution rung). `<net>` is one of the five networks; `none` / `clear` /
empty clears the default. A `--network` flag or `DAXIB_NETWORK` still overrides
this for a single call.

- Exit codes: `0`; `2` (unknown network); `10` (`config.read_only`).

```bash
daxib network use testnet
daxib network use clear
```

#### network show

```text
daxib network show
```

Prints the resolved active network and its source (flag / env / config /
unset).

- Exit codes: `0` (prints the resolution, including `unset`).

```bash
daxib --json network show
DAXIB_NETWORK=signet daxib network show
```

#### network list

```text
daxib network list
```

Lists the five supported networks with their coin types.

- Exit codes: `0`.

```bash
daxib --json network list
```

## The agent interface

### mcp

daxib's Model Context Protocol server exposes the same wallet over the same
policy guardrails as the CLI — a second thin frontend, not a second core.

#### mcp serve

```text
daxib mcp serve [flags]
```

Opens the wallet and serves the MCP server until the client disconnects or the
process is signaled (SIGINT/SIGTERM). The same guardrails the CLI enforces apply
identically to MCP-initiated signing (policy reservation runs in the core,
below both frontends). The keystore passphrase is acquired the same way as every
signing command (`DAXIB_PASSPHRASE[_FILE]`); a long-lived server caches its
unlock — restart after a keystore passphrase change.

| Flag | Default | What it does |
| --- | --- | --- |
| `--transport <stdio>` | `stdio` | MCP transport (v1: `stdio`; `http` reserved for v1.1). |

- Exit codes: `0` (clean shutdown); `2` (`usage.network_required`); `4`
  (keystore passphrase); `10` (`keystore.not_found`); plus the runtime classes
  any served tool can surface.

```bash
DAXIB_PASSPHRASE=hunter2 daxib --network testnet mcp serve
```

#### mcp tools

```text
daxib mcp tools [name]
```

Prints the tool surface a connecting client sees. Default: a compact
`TOOL/KIND/DESCRIPTION` table. `--json` emits the exact `tools/list` payload
(every name, description, inputSchema, outputSchema, annotations). A positional
`<name>` prints that one tool's full schema. This command builds the server
lazily — it never unlocks the keystore or dials a backend.

- Exit codes: `0`; `10` (`ref.not_found` — unknown tool name).

The v1 surface is **18 tools** (13 read-only, 5 signing). It can move funds
within policy and read everything, but it **cannot** mutate policy, create /
import / export wallets, repoint the backend, or rotate the keystore passphrase
(those operations are deliberately absent — the operator-only boundary).

| Tool | Kind | Summary |
| --- | --- | --- |
| `balance` | read | Confirmed + unconfirmed balance (sats + BTC), UTXO count, tip. |
| `utxo_list` | read | A wallet's coins: outpoint, address, value, depth, total. |
| `wallet_list` | read | Wallets (non-secret metadata): names, scope, network, counts, default. |
| `wallet_show` | read | One wallet's detail (non-secret): scope, xpub, next indices. |
| `address_list` | read | A wallet's materialized addresses (ref, branch, index, bech32). |
| `fee` | read | Backend fee estimates (sat/vB) at slow/normal/fast + relay floor. |
| `verify` | read | BIP-322 signature verify (passphrase-free; `valid:false` is not an error). |
| `convert` | read | Exact sat<->BTC conversion (no floating point). |
| `tx_status` | read | A tx's status (journal folded with one live backend re-check). |
| `tx_wait` | read | Block until a tx confirms; dual-signal timeout with a resume command. |
| `tx_list` | read | A wallet's journaled transactions, newest first. |
| `policy_show` | read | The active policy + seal status (no mutation tool exists). |
| `policy_check` | read | Dry-run a hypothetical send against policy (no reservation). |
| `send` | sign | Coin-select, policy-check, sign, broadcast (waits by default over MCP). |
| `tx_speedup` | sign | RBF fee-bump to the same recipient (policy-gated like send). |
| `tx_cancel` | sign | RBF cancel/void to a fresh change address (policy-gated). |
| `address_new` | sign | Derive + record the next receive address (no signing). |
| `sign_message` | sign | BIP-322 sign (keystore-gated; moves no funds). |

```bash
daxib mcp tools
daxib mcp tools --json
daxib mcp tools send
```

## Utilities

### version

```text
daxib version
```

Prints version, commit, and build date.

- Exit codes: `0`.

```bash
daxib version
daxib --json version
```

### convert

```text
daxib convert <amount> [sat|btc] [flags]
```

Converts a Bitcoin amount between satoshis and BTC, float-free. The amount
carries its source unit as a suffix; an optional second argument names the
target unit (`sat`|`btc`) and defaults to the other unit. A bare number is BTC.
A leading `-` is a flag to the shell — pass a literal `--` first so a negative
amount reaches (and is rejected by) the parser.

- Exit codes: `0`; `2` (bad amount / negative).

```bash
daxib convert 0.001btc        # 100000
daxib convert 100000sat       # 0.00100000
daxib convert 0.5             # 50000000   (a bare number is BTC)
daxib convert 100000sat btc --json
daxib convert -- -1sat        # rejected: amounts must be non-negative
```

### completion

```text
daxib completion [bash|zsh|fish|powershell]
```

Outputs a completion script for the given shell, generated from the live
command tree. Source it from your shell rc.

- Exit codes: `0`; `2` (unsupported shell).

```bash
daxib completion bash > /etc/bash_completion.d/daxib
daxib completion zsh  > "${fpath[1]}/_daxib"
daxib completion fish > ~/.config/fish/completions/daxib.fish
```
