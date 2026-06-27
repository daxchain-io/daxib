# Daxib — Planning & Design Notes

**Daxib is "The Bitcoin wallet for AI" — the Bitcoin sibling of [daxie](../../daxie)
("The Ethereum wallet for AI").** Same spine, different chain. The name says it:
**DAXI‑E** (Ethereum) → **DAXI‑B** (Bitcoin).

This document is the planning artifact for a fresh project. It records (1) what we
inherit from daxie wholesale, (2) what we drop because it does not exist on Bitcoin,
and (3) the *uniquely Bitcoin* capabilities that have no daxie analog — several of
which make daxib **structurally more secure than daxie can be on Ethereum**.

> Status: **mostly implemented and released as `v0.1.0`.** This was the original
> planning artifact; it is kept as the design record + roadmap. The core (M1–M6),
> testnet4, and RBF shipped; for the current built surface see the
> [README](../README.md) and [CHANGELOG](../CHANGELOG.md). Items still marked
> "forward path" / "deferred" below (BIP-322, the standalone PSBT noun,
> Runes/Ordinals, watch-only, Miniscript, Lightning) are **not** in v0.1.0.

---

## 0. The thesis in one paragraph

Most Bitcoin tooling assumes a human at a terminal signing each spend. Daxib inverts
that: an **autonomous agent** holds a wallet and moves sats *within operator‑set
limits it cannot raise*. We keep daxie's proven architecture — **one core, two
frontends** (CLI + MCP server), **two passphrases**, **Ed25519‑sealed policy** — and
then exploit three things Bitcoin gives us that Ethereum does not: **PSBT** (a
protocol‑native builder/signer split), **watch‑only descriptors** (the agent can hold
*zero* key material and still do its job), and **Miniscript/Taproot** (some guardrails
become **consensus‑enforced**, not merely software‑enforced). Bitcoin also gives us the
**Lightning Network + L402**, which is rapidly becoming *the* settlement rail for
machine‑to‑machine micropayments — the most exciting forward story for an agent wallet.

---

## 1. What daxie is (the template we are mirroring)

Daxie (sibling repo, `../daxie`, v1 stable) is an agent‑first Ethereum CLI wallet in
Go with a built‑in MCP server. Its load‑bearing ideas, all of which we keep:

- **One core, two frontends.** A single `internal/service` package owns every use
  case (build → policy → sign → broadcast → wait). The **CLI** (`internal/cli`) and
  **MCP server** (`internal/mcpserver`) are thin adapters. There is no second signing
  path to audit, and neither frontend can bypass the guardrails because the guardrails
  live *below* both, inside one signing chokepoint. Enforced by `internal/arch_test.go`
  and the depguard linter, not by convention.
- **Two passphrases, two privilege levels.** The **keystore passphrase** unlocks
  signing (the agent may hold it). The **admin passphrase** authorizes policy changes
  (the agent *never* holds it). A fully prompt‑hijacked agent can spend up to the
  limits — it cannot change the limits, the allowlist, what an alias means, or read a
  key out.
- **Ed25519‑sealed policy + pinned anchor.** The policy file carries a detached
  Ed25519 seal; the agent host holds only the *verify* key (read directly, never via
  config/env/flag), so it can verify on every signing op but never forge. Tamper →
  fail closed.
- **Rolling‑24h spend limits**, gas/fee included, on durable counters that survive
  restarts and fail closed on corruption.
- **Destination allowlist + name pinning** (an allowlisted name stores name *and*
  resolved target; a later re‑point is refused until re‑allowed).
- **Non‑interactive everything**: flags, `DAXIE_*` env, stdin secrets, `--json` on
  every command, a small stable exit‑code table to branch on.
- **MCP surface deliberately narrowed**: move funds within policy + read everything;
  cannot export keys, create/import wallets, mutate policy, or add registry aliases.
- **Four state classes** (config / keystore / state / cache) for clean container
  mounts; **signed supply chain** (goreleaser, cosign keyless OIDC, SBOM, SLSA,
  distroless non‑root image).

Note: daxie's `go.mod` **already depends on `btcsuite/btcd`, `btcec`, and `btcutil`**
(for secp256k1). The Go Bitcoin stack we need is battle‑tested and partly already in
the family's dependency set.

---

## 2. The mapping: carry over · drop · net‑new

### 2.1 Carries over wholesale (the crown jewels — ~70% of the value)

| From daxie | In daxib | Notes |
|---|---|---|
| One core, two frontends (`service` + `cli` + `mcpserver`) | **identical** | The architecture is chain‑agnostic. |
| Two‑passphrase model (keystore vs admin) | **identical** | Maps perfectly. |
| Ed25519‑sealed policy + anchor | **identical** | Same sealing/verify mechanism. |
| Rolling‑24h spend limits, durable counters, fail‑closed | **identical** | Denominated in BTC/sats; fee included. |
| Destination allowlist + pinning | **identical** | Allowlist scriptPubKey/address; pin name→script. |
| Non‑interactive contract (flags/env/stdin/`--json`/exit codes) | **identical** | `DAXIB_*` env namespace. |
| MCP narrowing + the "what is NOT a tool" exclusion list | **identical** | Same boundary philosophy. |
| Four state classes (config/keystore/state/cache) | **identical** | PSBTs + tx journal live in *state*. |
| Signed supply chain (goreleaser, cosign, SBOM, SLSA, distroless) | **reuse wholesale** | Copy the pipeline. |
| Versioning/SemVer, CI gates, arch lattice (depguard) | **identical discipline** | |
| `wallet` / `balance` / `tx send/status/wait/list` / `receive` / `contacts` / `policy` / `mcp` nouns | **keep** | Verbs adjusted for UTXO semantics. |
| RBF speedup/cancel (daxie already models these) | **keep** | On Bitcoin these are the *native* fee‑bump primitives (BIP‑125). |

### 2.2 Dropped (Ethereum‑only; no Bitcoin base‑layer analog)

| Dropped from daxie | Why it doesn't apply |
|---|---|
| `token` noun, ERC‑20/721/1155, `token_approve`/`allowance`/`revoke` | No native tokens / allowance model on Bitcoin L1. (Runes/Ordinals are an *optional* module — see §3.10, very different shape.) |
| `contract` noun, ABI, `contract_call/send/encode/decode/logs` | No EVM smart contracts. Bitcoin Script is not call‑shaped. The classifier's *spirit* survives as a **PSBT/Script classifier** (§3.2). |
| `nft` noun | No ERC‑721/1155. Ordinals inscriptions are the analog (optional module). |
| EIP‑1559 gas (base/priority/max fee), `gas` noun | Replaced by **sat/vByte fee estimation** (`fee` noun, §3.8). |
| Nonces / nonce‑safety / "single‑writer‑per‑account" | Bitcoin has no nonces. Replaced by **UTXO‑set ownership / single‑writer‑per‑wallet** to avoid conflicting coin selection (§3.1). |
| ENS (`ens_resolve/reverse`) | No canonical Bitcoin name system. Optional resolver for **BIP‑353** + Lightning addresses (§3.12). |
| EIP‑712 typed‑data signing | No analog. Message signing survives via **BIP‑322** (§3.7). |
| Account‑balance model | Replaced by the **UTXO model** (§3.1). |
| `chain‑id` network soup | Bitcoin has 4 well‑known networks (mainnet/testnet/signet/regtest) — simpler `network` noun. |

### 2.3 Net‑new — uniquely Bitcoin (the "special tidbits")

These are the things that make daxib *its own project*, not a find‑and‑replace of
daxie. Each gets a deep dive in §3.

1. **UTXO model + coin control** — balance is a set, not a number; coin selection,
   change, dust, consolidation. New `utxo` noun.
2. **PSBT (BIP‑174/370) as a native builder/signer split** — daxie's "v2 signer
   daemon" future, available on Bitcoin *from day one*. New `psbt` noun.
3. **Watch‑only descriptors (xpub)** — the agent can hold **zero private keys** and
   still build, analyze, track, and receive. Closes daxie's R1 structurally.
4. **Output descriptors (BIP‑380–386)** — the modern wallet definition; a wallet *is*
   a descriptor. New `descriptor` noun.
5. **Address types + native SegWit/Taproot** — BIP‑44/49/84/86; default Taproot.
6. **Miniscript + Taproot script‑path policy** — *consensus‑enforced* guardrails:
   co‑signing, timelocks, vaults. The headline security story.
7. **sat/vByte fee market + RBF/CPFP/package relay** — mempool‑aware fee policy.
8. **Lightning + L402** — instant sub‑cent agent micropayments; the M2M economy.
9. **Ordinals/Runes/inscriptions awareness** — primarily a *protection* guardrail
   ("never burn a rare sat / inscription / Rune as a fee"), optionally transfer.
10. **Silent Payments (BIP‑352)** — static, reuse‑free receive code for privacy.
11. **Privacy as a first‑class concern** — the transparent UTXO graph means coin
    selection leaks; address‑reuse avoidance, change indistinguishability.

---

## 3. Deep dives on the Bitcoin‑unique design

### 3.1 The UTXO model (the foundational change)

Ethereum: `balance(account)` is a number; you debit it. Bitcoin: a wallet owns a *set*
of unspent transaction outputs (UTXOs); a spend **consumes whole UTXOs** and creates
new ones (recipient + change). This ripples through everything:

- **Balance** = Σ(confirmed UTXOs), with a `confirmed / unconfirmed / immature`
  breakdown. `balance --utxos` enumerates the set.
- **Coin selection** is now a core algorithm (Branch‑and‑Bound with knapsack
  fallback, à la Bitcoin Core), trading off fee, change creation, dust avoidance, and
  **privacy**. This is a *policy surface*: operators may constrain it.
- **Change outputs, dust** — sends below the dust threshold are rejected; change
  returns to a fresh internal address.
- **New `utxo` noun**: `list` · `show` · `freeze` · `unfreeze` · `lock` (coin
  control). Freezing is also how we protect ordinals/Runes (§3.10).
- **Concurrency**: daxie's nonce‑collision problem becomes a **UTXO double‑selection**
  problem. Rule: **single‑writer‑per‑wallet UTXO set** (each agent gets its own
  descriptor/account), with conflicts *detected* at broadcast (`bad-txns-inputs-missingorspent`)
  and reconciled from the journal. The PSBT/watch‑only split (§3.3) makes multi‑host
  coordination much cleaner than daxie's flock approach.

### 3.2 The PSBT/Script classifier (daxie's calldata classifier, reimagined)

Daxie decodes the 4‑byte selector before signing to recognize spend‑equivalents.
Daxib's analog inspects the **PSBT / transaction structure** before signing and
classifies intent:

- plain send vs self‑send vs **consolidation** (many‑in/one‑out) vs **batch payout**;
- does any input touch a **protected/frozen UTXO** (inscription, Rune, rare sat)? →
  deny unless explicitly acknowledged;
- does any output **inscribe** or **transfer a Rune / OP_RETURN payload**? → classified
  and gated;
- **fee sanity**: absolute fee and fee‑rate ceilings (anti‑fee‑burn, §3.8);
- **address‑reuse / privacy** flags.

Same principle as daxie: the generic path (`psbt sign`) cannot defeat the typed
guardrails — every PSBT is classified at the one signing chokepoint.

### 3.3 PSBT + watch‑only = the structural security win

This is the single biggest reason a *Bitcoin* agent wallet can be safer than an
Ethereum one. Recall daxie's headline residual:

> **R1 (Critical) — host compromise.** Code running as the agent's uid can read the
> keystore file *and* the co‑resident passphrase, then decrypt offline. "No in‑process
> design stops that in one trust domain." daxie's answer is a *future* v2 signer daemon.

Bitcoin hands us the answer **natively, in v1**, two independent ways:

1. **Watch‑only agent.** Import only the **public descriptor (xpub)** onto the agent
   host. The agent sees balances, derives receive addresses, tracks confirmations, and
   **builds PSBTs** — but there are *no private keys on the box to steal*. Signing
   happens out‑of‑band (operator workstation, hardware wallet, HSM, or a signer
   daemon). R1's "decrypt offline" attack has nothing to decrypt.
2. **PSBT hand‑off.** `psbt create` (agent, watch‑only) → transport → `psbt sign`
   (signer with keys) → `psbt finalize` + `tx broadcast`. This is the BIP‑174 workflow
   that hardware wallets already use; daxib makes it the agent's default deployment
   shape.

So daxib offers **three custody postures** on one core, operator's choice:

| Posture | Keys on agent host? | R1 exposure | Use when |
|---|---|---|---|
| **Hot** (mirror daxie) | yes (encrypted keystore) | same as daxie | low‑value float, simplicity |
| **Watch‑only + external signer** | **no** | **structurally closed** | the recommended agent default |
| **Miniscript co‑sign** (§3.6) | agent key present but **insufficient alone** | closed by consensus | highest assurance |

### 3.4 Output descriptors (BIP‑380–386)

A wallet *is* a descriptor: `wpkh([fingerprint/84h/0h/0h]xpub.../0/*)`,
`tr(...)`, `wsh(multi(2,...))`. Descriptors are checksummed, portable, and unambiguous
about address type + derivation. `wallet import` ingests a descriptor (or a seed +
script type); `descriptor` noun exports/inspects. This replaces daxie's ad‑hoc account
derivation and is what every modern backend (Bitcoin Core ≥0.21, electrs) speaks.

### 3.5 Address types & derivation

Support P2WPKH (BIP‑84, bech32) and **P2TR (BIP‑86, bech32m, default)**, with
P2PKH/P2SH‑P2WPKH for compatibility. Taproot is the default for new wallets: smaller
fees, better privacy, and it's the gateway to Miniscript script‑path policies (§3.6).

### 3.6 Miniscript / Taproot — guardrails the *network* enforces

daxie's guardrails are **software**: a process checks policy *before* it signs. They
are tamper‑*evident*, not tamper‑*proof* (daxie's honest R2). Bitcoin lets us push some
guardrails **into the script itself**, where Bitcoin consensus enforces them and *no
compromise of the agent host can override them*:

- **Co‑signing (`wsh(multi(2, agent, operator))` or a Taproot 2‑of‑2).** The agent key
  *cannot move funds alone*. A fully prompt‑hijacked, host‑compromised agent still
  produces only a half‑signed PSBT — the operator (or a policy oracle) must co‑sign.
  This is R1 closed by consensus, not by software.
- **Timelocks (CLTV/CSV, BIP‑65/112).** Vaults: funds spendable only after a delay, or
  an operator clawback path active for N blocks. Bounds spend *velocity* at the
  consensus layer.
- **Decaying multisig / emergency / inheritance paths** via Taproot script trees —
  multiple spend conditions, only the used leaf revealed.

Miniscript lets us *compile a spending policy* (e.g. "agent + operator, OR operator
alone after 30 days") into Script and analyze it. **This is daxib's flagship
differentiator**: the marketing line is *"guardrails Bitcoin itself enforces."* The
software policy engine (limits, allowlist, fee caps) still runs on top for the
dimensions consensus can't express (rolling‑24h fiat‑denominated limits, destination
allowlists) — defense in depth.

### 3.7 Message signing — BIP‑322 (replaces EIP‑191/712)

`sign message` / `verify` via **BIP‑322** (generic signed messages, incl.
SegWit/Taproot), with legacy BIP‑137 for old verifiers. EIP‑712 typed‑data has no
Bitcoin analog and is dropped.

### 3.8 Fees — sat/vByte, mempool‑aware, anti‑burn

Replace daxie's `gas` noun with `fee`:

- Estimate **sat/vByte** at slow/normal/fast targets from the backend's fee estimator
  / mempool histogram.
- **Fee policy is a guardrail**: max fee‑rate and max absolute fee per tx. During a
  fee spike, an unsupervised agent must not torch the treasury on fees — daxie has no
  equivalent because gas is comparatively bounded; on Bitcoin this is a real attack/footgun.
- **RBF (BIP‑125)** for `tx speedup` / `tx cancel`; **CPFP** for accelerating a
  stuck receive; awareness of replacement‑cycling / pinning as named residuals.

### 3.9 Lightning Network + L402 (the agentic‑payments killer app)

Per the research, Bitcoin's Lightning + **L402** (HTTP 402 + macaroons + Lightning
invoices) is emerging as *the* rail for autonomous machine‑to‑machine micropayments —
agents paying 1–10 sats per API/LLM call, no subscriptions, no fiat rails. Lightning
Labs, Alby (PaidMCP), and Xverse all shipped agent‑facing Lightning tooling in 2025.
This is the most exciting forward capability and has **no Ethereum‑L1 analog**.

Two layers, cleanly separated:

- **L1 (on‑chain):** treasury, settlement, channel opens/closes, larger payments —
  the core of daxib.
- **L2 (Lightning):** instant micropayments + L402 pay‑per‑request. Big lift (needs an
  LN node / LSP integration — LDK, or an Alby/LSP backend). Likely a **separate module
  or `daxib-ln` frontend** rather than v1 core, but the architecture should reserve the
  seam now. **Open decision (§5).**

When present, the *same* policy chokepoint must bound Lightning spends (per‑payment
cap, rolling daily cap in sats, destination/node allowlist) — the guardrail philosophy
does not change, only the rail.

### 3.10 Ordinals / Runes / inscriptions — protect first, transfer maybe

Bitcoin's "tokens & NFTs" (Runes, BRC‑20, Ordinals inscriptions) are **UTXO‑bound**.
The dominant risk for an agent wallet is **accidentally spending a rare sat /
inscription / Rune as a transaction fee or change** — a documented way collectors have
lost five‑figure assets. So even a pure‑BTC daxib must be **ordinals‑aware**:

- coin selection **refuses to spend** UTXOs flagged as inscribed / Rune‑bearing /
  rare‑sat unless explicitly acknowledged (ties into `utxo freeze`, §3.1, and the PSBT
  classifier, §3.2);
- a new guardrail: `protect‑assets` on by default when an ordinals index is available.

*Optionally* (later module): deliberate `runes send` / `inscription send`. This is the
loose analog to daxie's `token`/`nft` nouns, but the *primary* job is protection.

### 3.11 Silent Payments (BIP‑352) — reuse‑free receive

A static **silent‑payment code** lets the agent publish *one* receive identifier that
never reuses an address and doesn't leak its transaction graph — ideal for an agent
that posts a payment endpoint. Modern, optional, privacy‑positive. (Pairs with
descriptor `sp(...)` work landing in the BIP‑381‑style descriptor family.)

### 3.12 Name resolution — BIP‑353 + Lightning addresses (the "ENS analog")

No canonical Bitcoin name system, but `resolve` can map **BIP‑353** DNS payment
instructions (`₿user@domain`) and **Lightning addresses** (`user@domain`) to a
payable target — with the **same pinning discipline as daxie's ENS**: resolve once,
pin the resolved scriptPubKey/offer, refuse silent re‑points (`pin_drift`) until
re‑allowed. Optional.

### 3.13 Privacy — a concern Ethereum's account model doesn't have

The UTXO graph is transparent and linkable. Coin selection, change placement, and
address reuse all leak. Daxib treats privacy as a first‑class policy dimension:
avoid address reuse, prefer change outputs indistinguishable from payments, avoid
merging UTXOs that link distinct identities, gap‑limit‑aware scanning. There's no
daxie equivalent.

---

## 4. Proposed command surface (noun/verb)

Mirrors daxie's shape; diffs called out. Every command ships a human form **and**
`--json`, a non‑interactive path, and documented exit codes.

| Noun | Verbs | vs daxie |
|---|---|---|
| `wallet` | `create` · `import` · `list` · `show` · `rename` · `export` · `delete` | import now takes a **descriptor** or seed |
| `descriptor` | `import` · `export` · `show` · `derive` | **NEW** (watch‑only, BIP‑380) |
| `address` | `new` · `list` · `label` (receive/change, gap‑limit aware) | replaces account‑as‑balance |
| `balance` | (`--utxos`, `--confirmed/--unconfirmed`) | UTXO‑derived |
| `utxo` | `list` · `show` · `freeze` · `unfreeze` · `lock` | **NEW** (coin control) |
| `tx` | `send` · `status` · `wait` · `list` · `speedup` (RBF) · `cancel` (RBF) · `bump` (CPFP) · `abandon` | `send` does coin selection |
| `psbt` | `create` · `decode` · `analyze` · `combine` · `finalize` · `sign` · `broadcast` | **NEW** (BIP‑174/370) |
| `fee` | (sat/vByte slow/normal/fast; mempool view) | replaces `gas` |
| `sign` / `verify` | `sign message` · `verify` (**BIP‑322**) | drops EIP‑712 |
| `receive` | (block until inbound confirms; `--new`; optional silent‑payment / BIP‑21 invoice) | + SP option |
| `resolve` | (BIP‑353 / Lightning address → target, pinned) | replaces `ens` |
| `contacts` | `add` · `list` · `show` · `remove` | same |
| `network` | `use` · `show` (mainnet/testnet/signet/regtest) | simpler than chain‑id |
| `backend` | `add` · `list` · `use` · `test` (bitcoind RPC / Electrum / Esplora) | replaces eth `rpc` |
| `policy` | `show` · `set` · `allow` · `deny` · `verify` · `check` · `counters` · `pin` · `reset` · admin‑passphrase ops · **`fee-cap`** · **`coin-control`** · **`protect-assets`** | extended with BTC dims (`require-cosign` is forward-path, §5a) |
| `mcp` | `serve` · `tools` | same |
| *(forward path)* `runes` / `inscription` | `list` · `show` · `send` | deferred (§7.4) — analog to token/nft |
| *(forward path)* `ln` | `pay` · `invoice` · `balance` · `l402` | Lightning module — deferred (§7.1) |
| utility | `version` · `completion` · `config` · `convert` (BTC/sat/fiat) | same |

**Exit codes** — reuse daxie's `0`–`12` skeleton, repurposing the few EVM‑specific
ones: drop `reverted` (no contract revert); add a Bitcoin lane for *coin‑selection /
insufficient‑confirmed‑funds*, *fee‑policy denied*, and *protected‑UTXO refusal*; keep
`policy‑denied`, `auth`, `network`, `timeout/seal`. Final table is a v1 design task.

---

## 5. Security model — daxie parity in v1, a Bitcoin-native forward path

v1 inherits daxie's threat model **and its honest residuals unchanged**. Same
posture, same caveats — no more, no less. We do **not** try to out-secure daxie in v1;
we match it and ship the fun part.

| daxie residual | daxib v1 status |
|---|---|
| **R1 (Critical) host compromise → offline key decrypt** | **Same residual as daxie v1.** Hot keystore + co-resident passphrase → a host-compromise can decrypt offline. Bounded (like daxie) by policy limits + journal; *fully* closed only on the forward path (§5a). Stated honestly, not hidden. |
| **R2 (High) same‑domain counter tampering** | **Same as daxie.** Tamper-evident (`policy verify` cross-audit), not tamper-proof, within one trust domain. |

New Bitcoin‑specific residuals we must name honestly (daxie has no equivalent):

- **Privacy leakage** via coin selection / address reuse / UTXO linkage.
- **Fee‑market adversarial behavior**: fee‑burn under spikes (mitigated by fee‑cap
  policy), RBF pinning, replacement cycling.
- **Backend trust**: an Electrum/Esplora server can lie by omission about UTXOs/fees;
  Bitcoin Core (own node) is the trust‑minimized option. State the trade‑off.
- **Ordinals burn**: spending a valuable sat as a fee (mitigated by §3.10).

The two‑passphrase model, sealed policy, allowlist, durable counters, and the
narrowed MCP surface all carry over unchanged.

### 5a. Custody posture — decided (2026-06-24)

**v1 ships ONE posture: the hot keystore (daxie parity).** Keys live encrypted on the
agent host; the agent holds the keystore passphrase and signs autonomously within
policy. Frictionless, fully autonomous, identical custody model to daxie v1. This is
deliberate: the project's north star is *"daxie but for Bitcoin"* — the fun, capable
agent wallet — not a vault product.

The stronger Bitcoin-native postures discussed during planning are recorded here as a
**forward path** (the way daxie documents its v2 signer daemon), explicitly **out of
v1 scope**:

- **Watch-only + external PSBT signer** — no keys on the agent host; agent builds
  PSBTs, an out-of-band signer signs. Closes R1 structurally. *(Forward path.)*
- **Miniscript / Taproot co-sign + timelock vaults** — consensus-enforced 2-of-2 and
  velocity bounds for a high-value reserve. *(Forward path.)*

These get *real* once daxib holds meaningful value — a *later* hardening, not a v1
gate. v1's job is the working autonomous wallet; the PSBT plumbing built in v1 is what
makes the forward path a no-refactor add-on.

---

## 6. Backends (the provider seam)

daxie's provider interface (its §2.6) keeps its shape; only the implementation
changes. daxib speaks to a Bitcoin backend behind one interface:

- **Bitcoin Core RPC** (descriptors wallet / `scantxoutset` / `gettxout`) — full
  sovereignty, "don't trust, verify," heavier. *Recommended default for high assurance.*
- **Electrum protocol** (electrs) and/or **Esplora REST** (mempool.space‑style) —
  light, fast, but you trust the server's view. *Good for quick starts / low‑value
  agents.*

Likely support both behind the interface; pick the default in §7.

---

## 7. Open decisions (need operator/owner input before v1 build order)

1. **Lightning in v1?** — **DECIDED: skip for now** (owner, 2026-06-24). On-chain
   only; the LN seam stays reserved in the architecture but no L402 work in v1.
   Revisit post-v1.
2. **Default custody posture.** — **DECIDED: hot keystore (daxie parity)** (owner,
   2026-06-24). Project north star is *"daxie but for Bitcoin"* — ship the fun,
   capable, autonomous agent wallet first, **not** a layered vault system. v1 uses the
   same single hot-keystore posture as daxie v1 (encrypted local keystore, agent holds
   the keystore passphrase, signs autonomously within policy). The stronger
   Bitcoin-native postures (watch-only + PSBT signer, Miniscript co-sign) are a
   documented **forward path**, not v1 work — the same way daxie honestly names its R1
   residual and its future v2 daemon. See §5a.
3. **Backend default.** **Recommend:** support Core RPC *and* Esplora/Electrum;
   default to Core RPC in docs for the trust‑minimized story.
4. **Asset scope.** — **DECIDED: pure BTC for v1** (owner, 2026-06-24, revised).
   Runes / Ordinals / inscriptions are **deferred to the forward path** — Rune activity
   has cooled since its 2024 peak and it's a nice-to-have, not a v1 must. Get plain BTC
   - the agent/MCP core solid first; add `runes` / `inscription` nouns (and the
   asset-protection guardrail that comes with an ordinals index) later if demand is
   real.
5. **Miniscript depth in v1.** — **DECIDED: not in v1** (follows from #2). Co-sign /
   timelock vaults are part of the forward-path hardening, not the first release. The
   PSBT *plumbing* is still built in v1 (it's a normal capability — hardware-wallet /
   multi-wallet interop), just not wired into a custody ceremony.

---

## 8. Suggested v1 build order (mirrors daxie's milestone discipline)

1. **Skeleton + arch lattice.** Port daxie's `service`/`cli`/`mcpserver`/`domain`
   split, depguard rules, `arch_test.go`, supply‑chain pipeline. (Mostly copy.)
2. **Keys + descriptors.** BIP‑39 seed, BIP‑84/86 derivation, descriptor wallet,
   encrypted keystore (reuse daxie's KDF/keystore design), **watch‑only import**.
3. **Backend provider.** Core RPC first; UTXO scan, fee estimate, broadcast.
4. **UTXO + coin selection + `balance`/`utxo`/`address`/`receive`.**
5. **Tx pipeline + PSBT.** `tx send` (coin‑select → build → classify → sign →
   broadcast → wait), full `psbt` noun, RBF/CPFP, journal.
6. **Policy engine.** Port the sealed‑policy + two‑passphrase + rolling‑limits +
   allowlist core; add fee‑cap, coin‑control, protected‑UTXO, `require-cosign` dims.
7. **MCP server.** Schemas derived from the same structs; the narrowed tool surface +
   exclusion list.
8. **Docs, demos, release.** Mirror daxie's `docs/` set + checked‑in demo scripts.

Then, as fast‑follows / forward path: **Runes / Ordinals / inscriptions** (§7.4) with
their asset-protection guardrail, the custody hardening (watch-only + PSBT signer,
Miniscript co-sign + timelock vaults — §5a), Lightning/L402, Silent Payments, BIP‑353
resolver.

---

## 9. Why this is worth building

- **Real, current market.** 2025–26 saw Xverse's Bitcoin Agentic Wallet + MCP server,
  Alby's PaidMCP, Coinbase Payments MCP (incl. Bitcoin), MoonPay Agents, and Lightning
  Labs' agent toolkit — all betting that agents need Bitcoin rails. Daxib's angle is
  the one none of them lead with: **operator‑set guardrails an agent cannot raise,
  several of them consensus‑enforced.**
- **The fun, capable thing first.** v1 is *"daxie but for Bitcoin"*: an autonomous
  agent that holds a real Bitcoin wallet — UTXO coin control, Taproot, sat/vByte fees,
  RBF, PSBT interop — driven over CLI + MCP. (Runes / Ordinals come on the forward
  path, §7.4.)
- **Maximum architecture reuse.** ~70% of daxie (the hard‑won core/policy/supply‑chain
  spine) ports directly; the new 30% is the fun, Bitcoin‑native part.
- **A clean forward path on security.** When the wallet matures into real value,
  Bitcoin's watch-only + PSBT + Miniscript give a no-refactor route to close daxie's R1
  residual — but that's later hardening, not a v1 gate (§5a).

---

## Appendix — research sources

- Agent payments / Bitcoin agent wallets: Xverse Agentic Wallet & MCP, Alby PaidMCP,
  Coinbase Payments MCP, MoonPay Agents, Lightning Labs agent tools (2025–26).
- Standards: PSBT (BIP‑174/370), output descriptors (BIP‑380–386), BIP‑322 message
  signing, BIP‑352 Silent Payments (+ `sp()` descriptor work), BIP‑353 DNS payment
  instructions, Taproot (BIP‑340/341/342), BIP‑44/49/84/86 derivation, RBF (BIP‑125),
  CLTV/CSV (BIP‑65/112), Miniscript.
- UTXO protection: Sparrow/Xverse coin‑control & inscription freezing; Runes now ~35%
  of Bitcoin metadata txs.
- Lightning agent payments: L402 (Lightning Labs), macaroons + invoices, Cloudflare
  HTTP‑402 volume, x402 vs L402 comparison.
