# Daxib

**The Bitcoin wallet for AI.** An agent-first Bitcoin CLI wallet in Go, with a
built-in MCP server. Non-interactive flags/env/stdin, `--json` everywhere,
deterministic exit codes, sealed spend-limit guardrails, and a
one-core/two-frontends architecture so the CLI and the MCP server traverse the
*exact same* wallet logic — and the *exact same* guardrails.

Daxib is the Bitcoin sibling of [**daxie**](https://github.com/daxchain-io/daxie),
"the Ethereum wallet for AI." Same security spine — **two passphrases**, an
**Ed25519-sealed policy an agent cannot raise**, one signing chokepoint — re-grounded
on Bitcoin's UTXO model, and extended with three things Bitcoin gives us that Ethereum
cannot.

> **Status: planning / pre-alpha.** Nothing is built yet. The design is being mapped
> in [docs/PLAN.md](docs/PLAN.md). The CLI surface, JSON schemas, and security model
> below are *proposed*, not frozen.

---

## What is Daxib?

Most Bitcoin tooling assumes a human at a terminal signing each spend. Daxib inverts
that: it is built for an **autonomous agent** to hold a wallet and move sats *within
operator-set limits it cannot raise*.

- **One core, two frontends.** A single core package owns every use case (coin-select
  → build → policy → sign → broadcast → wait). The **CLI** and the **MCP server** are
  thin adapters over that core. Whatever the CLI can do, an agent can do over MCP —
  and *neither* can bypass the guardrails, because they live *below* both frontends.
- **Two passphrases, two privilege levels.** The **keystore passphrase** unlocks
  signing (the agent may hold it). The **admin passphrase** authorizes policy changes
  (the agent *never* holds it). A fully prompt-hijacked agent can spend up to the
  limits — it cannot change them, change the allowlist, or read a key out.

## What daxib does (v1)

The north star is *"daxie but for Bitcoin"* — the fun, capable, autonomous agent
wallet first. An AI agent gets a real Bitcoin wallet it can drive on its own, within
operator-set limits:

- **Native Bitcoin essentials.** UTXO coin control, Taproot/SegWit addresses,
  **sat/vByte fee policy** (so an unsupervised agent can't torch the treasury on fees),
  **RBF/CPFP** fee bumping, and **BIP-322** message signing.
- **PSBT (BIP-174/370) interop.** Build, decode, combine, and finalize partially
  signed transactions — clean interop with hardware wallets and other tooling.
- **The same guardrails as daxie.** Two passphrases, an Ed25519-sealed policy the agent
  can't raise, rolling spend limits, an allowlist, and a deliberately narrowed MCP
  surface.

### Forward path (not v1)

Bitcoin's primitives give daxib a clean, no-refactor route to harden custody once the
wallet holds real value — documented honestly rather than overbuilt up front:

- **Runes, Ordinals & inscriptions** — let the agent hold and move Bitcoin tokens and
  NFTs, with asset protection so coin selection never burns a rare sat as a fee.
- **Watch-only + external PSBT signer** — no private keys on the agent host at all.
- **Miniscript / Taproot co-sign + timelock vaults** — guardrails enforced by Bitcoin
  consensus, not just by our software.
- **Lightning + L402** — instant sub-cent machine-to-machine micropayments.

## Architecture (proposed)

```text
   operator domain  ───────────────────────────────────  agent domain (one uid)
   admin passphrase                                       keystore passphrase
   policy mutations         policy-anchor.json            daxib mcp serve / daxib <cmd>
   key export / backup     (verify key — read-only) ────► one core (coin-select→policy→sign)
        │                                                        │
        └── never crosses this line writably                    └─► signed tx ─► backend (broadcast)
```

The agent can sign **within policy** and read everything. It cannot raise its own
limits, change the allowlist, change what an alias means, or read a key out — those
need the admin passphrase, which lives only in the operator domain. (Same model as
daxie v1; the watch-only/co-sign hardening is a forward path, not v1.)

## Documentation

| Doc | What |
|---|---|
| [docs/PLAN.md](docs/PLAN.md) | The planning artifact: daxie→daxib mapping, Bitcoin-unique design, command surface, security model, build order, open decisions |

See the sibling project [daxie](https://github.com/daxchain-io/daxie) for the mature
Ethereum implementation whose architecture daxib mirrors.

## License

Intended: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) (matching daxie).
