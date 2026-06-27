# Driving daxib from an AI agent

daxib is a Bitcoin wallet built for an AI agent to drive. It can read balances
and UTXOs, derive receive addresses, estimate fees, sign messages, and move
funds — all within hard, operator-set guardrails the agent cannot lift. There
are two ways in, and they sit on the **same core**:

- the **MCP server** — `daxib mcp serve` exposes the wallet as Model Context
  Protocol tools an agent calls directly;
- the **CLI** — every verb is `--json`-clean with a small, deterministic set of
  exit codes to branch on.

Both frontends call the same service methods, so the same spend policy is
enforced for an MCP `send` and a shell `tx send` — identically, in one signing
chokepoint, *before* a single byte is signed. This doc covers the MCP surface,
non-interactive operation, the safety contract you operate under, and an
end-to-end recipe.

## The MCP server

Start it over stdio (the v1 transport):

```sh
daxib mcp serve
```

`mcp serve` opens the wallet and serves until the client disconnects or the
process is signaled (SIGINT/SIGTERM). The keystore passphrase is acquired the
same way as any signing command (`DAXIB_PASSPHRASE[_FILE]`, see below); a
long-lived server caches its unlock, so restart it after a keystore passphrase
change (hot-reload is deliberately unsupported). `--transport` accepts only
`stdio` in v1 (http is reserved for a later release).

To see exactly what a connecting client gets — without unlocking the keystore or
dialing a backend — use `mcp tools`:

```sh
daxib mcp tools              # compact TOOL / KIND / DESCRIPTION table
daxib mcp tools --json       # the exact tools/list payload (schemas + annotations)
daxib mcp tools send         # one tool's full input/output schema
```

`mcp tools` builds the server lazily and never touches the network or the
keystore, so it works in any environment.

### The tool roster

There are **18 tools**: 13 read-only and 5 signing. The input/output JSON
schemas are inferred from the same Go request/result structs the CLI binds, so
the MCP and CLI contracts cannot drift.

| Tool | Kind | Moves funds? | What it does |
| --- | --- | --- | --- |
| `balance` | read | no | Confirmed + unconfirmed balance for a wallet (sats + exact BTC string, UTXO count, chain tip). |
| `utxo_list` | read | no | The wallet's unspent coins: outpoint, address, value, confirmation depth. |
| `wallet_list` | read | no | HD wallets in the keystore (names, ids, scope, network, counts, default). Non-secret metadata only. |
| `wallet_show` | read | no | One wallet's id, scope, network, BIP-84 path prefix, account xpub, next indices. Non-secret only. |
| `address_list` | read | no | A wallet's materialized addresses (ref, branch, index, bech32, created-at). |
| `fee` | read | no | Backend fee-rate estimates (sat/vByte) at slow / normal / fast plus the per-target table. |
| `verify` | read | no | Verify a BIP-322 message signature against an address (passphrase-free). |
| `convert` | read | no | Exact sat ↔ BTC conversion (no floating point). Touches no wallet/key/backend. |
| `tx_status` | read | no | A transaction's lifecycle status by txid (folds the journal with one live re-check). |
| `tx_wait` | read | no | Block until a tx reaches its confirmation target, streaming progress. |
| `tx_list` | read | no | The wallet's transactions from the local journal, newest first. |
| `policy_show` | read | no | The active signing policy: limits, allow/deny lists, seal status. Read-only. |
| `policy_check` | read | no | Dry-run a hypothetical send against policy without reserving or signing. |
| `send` | sign | **yes** | Coin-select → policy-check → sign → broadcast a transfer. The one money mover. |
| `tx_speedup` | sign | **yes** | RBF fee-bump an unconfirmed send to the same recipient (policy-checked like a send). |
| `tx_cancel` | sign | **yes** | RBF-replace an unconfirmed send, redirecting funds to your own change (policy-checked). |
| `address_new` | sign | no | Derive and record the next receive address (from the xpub; no passphrase, no signing). |
| `sign_message` | sign | no | BIP-322 message signature with an address's key (proves ownership; moves no funds). |

Five tools carry the `sign` kind, but only **three move funds**: `send`,
`tx_speedup`, and `tx_cancel`. These three route through the same service
methods that hold the only path to the keystore signer, with the policy check
run *inside* each before signing. `address_new` mutates the wallet's
address watermark but never signs; `sign_message` unlocks a key to produce a
BIP-322 signature but charges nothing against the spend policy. The three
fund-movers plus `address_new` are marked `destructiveHint: true` in their MCP
annotations so a host can surface a confirmation (`sign_message` is the one
`sign`-kind tool that is not destructive); read-only tools are
`readOnlyHint: true`.

### What is deliberately *not* a tool

The MCP surface can move funds within policy and read everything, but it cannot
change who holds the keys, change what the keys may do, export a key, or repoint
the backend. These operations have **no tool handler at all** — the boundary is
enforced by absence and pinned by a test. A prompt-injected agent cannot raise
its own limits, exfiltrate a key, or redirect the backend through the tool
channel. Absent by design:

- **policy mutation** — `policy_set`, `policy_allow`, `policy_deny`,
  `policy_reset`, `policy_change_admin_passphrase` (admin-passphrase-gated,
  operator-only);
- **wallet create / import / export** — no mnemonic or seed ever crosses the
  tool channel;
- **backend add / use / remove** — repointing the node is an operator act;
- **keystore passphrase rotation** and **network mutation** — CLI-only.

`policy_show` and `policy_check` (both read-only) *are* exposed — use them to
pre-flight a transfer.

## Non-interactive operation

### `--json` everywhere

Every command emits machine-readable JSON under `--json`. A successful `send`
returns a `TxResult` whose fields include:

| Field | Meaning |
| --- | --- |
| `txid` | The broadcast transaction id. |
| `status` | Lifecycle: `signed`, `broadcast`, `pending`, `confirmed`, `failed`, or `timeout`. |
| `amount_sat` / `amount_btc` | The amount sent (integer sats + exact BTC string). |
| `fee_sat` / `fee_btc` / `fee_rate` | Fee in sats, exact BTC, and the sat/vByte rate. |
| `vsize` | Virtual size of the signed transaction. |
| `change_sat` / `change_address` | Change returned and the address it went to. |
| `confirmations` / `block_height` | Set once the tx confirms. |
| `journal_id` | The durable local record id. |
| `raw_tx_hex` | The fully-signed transaction (hex, no `0x`) for re-broadcast or inspection. |
| `resume` | A resume command, present when a wait timed out. |
| `replacement` / `replaces_txid` | Set on an RBF `tx_speedup` / `tx_cancel` result. |

Amounts are always integer sats plus an exact decimal string — **there is no
float field anywhere on the wire**. Pass amounts the same way: a decimal BTC
string (`0.001`) or an integer-sat string (`150000sat`), never a float you
computed.

### Exit codes to branch on

The CLI returns a small, stable set of exit codes (0..12). The same canonical
dotted error code (`policy.denied.day_limit`, `tx.input_spent`, …) rides every
transport, so an MCP tool error carries the same code an agent would branch on
at the shell. Each error envelope also carries a `retryable` boolean hint.

| Exit | Name | When | Retryable |
| --- | --- | --- | --- |
| 0 | `OK` | Success. No-wait `send` exits 0 on accepted broadcast; with a wait it means confirmed. | — |
| 1 | `INTERNAL` | A daxib bug or unexpected panic. | no |
| 2 | `USAGE` | Bad input: malformed address/amount/fee-rate, an inapplicable flag, **no network selected** (`usage.network_required`), or a confirmation needed with no TTY and no `--yes`. | no |
| 3 | `POLICY_DENIED` | A guardrail refusal before signing: per-tx / per-day limit, allowlist/denylist. | no (except `policy.denied.day_limit`) |
| 4 | `AUTH` | Wrong/missing keystore passphrase, or a wrong/missing **admin** passphrase for a policy mutation. | no |
| 5 | `INSUFFICIENT_FUNDS` | Spendable balance < amount + fee, or coin selection cannot assemble the spend. | no |
| 6 | `NETWORK` | Backend unreachable / RPC error, a permanent broadcast reject, or `tx.fee_too_low`. | mostly yes |
| 7 | `FEE_POLICY_DENIED` | The computed fee-rate exceeds the operator's cap (anti-fee-burn; code `policy.denied.fee_rate`). | **yes** |
| 8 | `TIMEOUT_PENDING` | A wait deadline hit with the tx still pending (`tx.wait_timeout`), **or** a policy seal/rollback/state failure (signing halted). | wait-timeout: yes; seal: no |
| 9 | `TX_CONFLICT` | An input was already spent (`tx.input_spent`), or an RBF target already confirmed/replaced. | yes |
| 10 | `NOT_FOUND` | Unknown txid/wallet/backend, or a read-only-mount mutation attempt. | no |
| 11 | `STATE` | State-dir problem: lock-acquisition timeout, corrupt journal. | lock-timeout: yes |
| 12 | `INTEGRITY` | Tamper/misconfig tripwire: backend network/genesis mismatch, insecure file perms. | no |

The retryable lanes worth special-casing in a send loop:

- **`tx.input_spent` (exit 9)** — a coin you selected was spent out from under
  you. Re-fetch UTXOs and rebuild; the same bytes will never broadcast again.
- **`policy.denied.fee_rate` (exit 7)** — the fee market moved above the cap. The
  fee-rate cap is fixed, but a later estimate (or a lower `fee_rate`) may clear
  it. Distinct from a spend-limit denial (exit 3), which a retry will not fix.
- **`policy.denied.day_limit` (exit 3)** — the rolling-24h budget is exhausted;
  the engine returns a `retry_after`. Wait for the window to age out.
- **`tx.wait_timeout` (exit 8)** — the tx is still pending; keep waiting. The
  result carries a `resume` command (`tx_wait` re-call) to resume cleanly.
- **`backend.unreachable` / `backend.rpc_error` (exit 6)** and
  **`state.lock_timeout` (exit 11)** — transient; retry later.

> A wait timeout (exit 8 / `tx.wait_timeout`) is **not** a failed send. Over MCP,
> `send` and `tx_wait` return *both* the tool-error signal *and* the structured
> result, so an agent gets the txid and a resume hint even at the deadline.

### Secret channels (environment, not arguments)

Secrets never arrive as a flag value or a tool argument — only via stdin, a
file, or an environment variable — so a passphrase or mnemonic cannot leak into
a process listing or shell history. For each secret the resolver applies the
precedence **`--*-stdin` > `--*-file` > `*_FILE` env > direct env > TTY prompt**,
and it never hangs: with no source and no terminal it returns a deterministic
error instead of blocking.

| Purpose | stdin flag | file flag | file env var | direct env var |
| --- | --- | --- | --- | --- |
| Keystore passphrase (signing) | `--passphrase-stdin` | `--passphrase-file` | `DAXIB_PASSPHRASE_FILE` | `DAXIB_PASSPHRASE` |
| First-init confirm | `--passphrase-confirm-stdin` | `--passphrase-confirm-file` | `DAXIB_PASSPHRASE_CONFIRM_FILE` | `DAXIB_PASSPHRASE_CONFIRM` |
| Policy admin passphrase (mutations) | `--admin-passphrase-stdin` | `--admin-passphrase-file` | `DAXIB_ADMIN_PASSPHRASE_FILE` | `DAXIB_ADMIN_PASSPHRASE` |
| BIP-39 mnemonic (import) | `--mnemonic-stdin` | `--mnemonic-file` | — | — |

Notes for unattended operation:

- The **`*_FILE` channel** (a path to a file, perms-checked) is the recommended
  unattended source; the direct env var is documented but least safe. A `*_FILE`
  source strips one trailing newline (matching `echo` and Kubernetes Secrets); a
  direct env value is used verbatim.
- The **mnemonic has no env channel** by design — it arrives only via
  `--mnemonic-stdin` / `--mnemonic-file` (and `wallet import` consumes it from
  stdin). A missing mnemonic is a usage error (exit 2), not an auth error.
- Over MCP, signing tools (`send`, `tx_speedup`, `tx_cancel`, `sign_message`)
  take **no passphrase argument** — the server resolves `DAXIB_PASSPHRASE[_FILE]`
  out-of-band at startup. The admin passphrase is never an MCP input at all.

## The safety contract

An agent operating daxib runs under a contract enforced in the core, below both
frontends:

1. **A sealed policy it cannot raise.** Spend guardrails — per-tx limit, rolling
   24-hour limit, max fee-rate, and allow/deny destination lists — are sealed
   with Ed25519 over `scrypt(admin-passphrase)` and pinned in a machine-only
   anchor. The check runs in the one signing chokepoint, *after* coin selection
   and *before* the keystore signs. A denied or over-limit spend produces no
   signature and moves no funds. The agent can `policy_show` and `policy_check`
   but has no path to mutate the policy.

2. **Two separate passphrases.** The **keystore passphrase** unlocks signing —
   the agent (or the MCP server) may hold it via `DAXIB_PASSPHRASE[_FILE]`. The
   **admin passphrase** authorizes policy mutations via
   `DAXIB_ADMIN_PASSPHRASE[_FILE]` — and the agent should **never** hold it. The
   two are cryptographically independent: holding one grants nothing about the
   other.

3. **No silent network default.** Every network-using operation needs an explicit
   network — resolved as `--network` flag > `DAXIB_NETWORK` env > the persisted
   default (`network use`) > **error**. With none selected, the command fails
   `usage.network_required` (exit 2). daxib never silently picks mainnet (or any
   network). Wallets are network-agnostic by default (one wallet works on every
   network); a `wallet create --bind` locks a wallet to a single network.

4. **Explicit confirmation for money-moving ops.** At a TTY, `tx send` /
   `tx speedup` / `tx cancel` / `tx abandon` prompt y/N. Non-interactively, pass
   `--yes` (or set it) — and **`--yes` is a confirmation skip, never a policy
   waiver**: the policy check runs regardless. Over MCP the confirmation is
   implicit (there is no TTY to prompt at) and waiting for confirmation is the
   default, but the policy chokepoint is identical to the CLI's.

## An end-to-end agent recipe

A minimal autonomous flow on signet, with secrets supplied via the file
channels. The operator does the policy setup once (it needs the admin
passphrase); the agent then operates within those limits.

### One-time operator setup (admin passphrase required)

```sh
# 1. Select the network (persist it as the default).
daxib network use signet

# 2. Create a wallet — RECORD THE MNEMONIC it prints once.
DAXIB_PASSPHRASE_FILE=/run/secrets/keystore.pass \
  daxib wallet create agent-hot --json

# 3. Seal the spend policy (FIRST `policy set` bootstraps the anchor).
DAXIB_ADMIN_PASSPHRASE_FILE=/run/secrets/admin.pass \
  daxib policy set \
    --network signet \
    --max-tx 100000 \
    --max-day 500000 \
    --max-fee-rate 50 \
    --json
```

### The agent's loop (keystore passphrase only)

```sh
export DAXIB_NETWORK=signet
export DAXIB_PASSPHRASE_FILE=/run/secrets/keystore.pass

# Pre-flight: is this transfer in policy? (read-only, no reservation)
daxib policy check --to tb1qexample... --amount 50000sat --json

# Send within the limits. --yes skips the (absent) TTY prompt; policy still runs.
daxib tx send --to tb1qexample... --amount 50000sat --wait --yes --json
```

Branch on the exit code: `0` confirmed; `3`/`7` a policy refusal (inspect the
`code`); `9` re-fetch UTXOs and rebuild; `8` keep waiting via the `resume`
command. The MCP equivalent is identical — call `policy_check`, then `send`
(which waits and is policy-checked by default), and branch on the same dotted
codes in the tool-error envelope.

The same wallet, the same policy, the same exit codes — whether the caller is a
shell script or an agent over MCP.
