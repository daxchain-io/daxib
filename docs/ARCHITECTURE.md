# Architecture

Why daxib is shaped the way it is. This is the design rationale for contributors;
for *what* the commands do see [COMMANDS.md](COMMANDS.md), for the security
mechanics see [SECURITY.md](SECURITY.md), and for operating it see
[CONFIGURATION.md](CONFIGURATION.md). The roadmap lives in
[GitHub issues](https://github.com/daxchain-io/daxib/issues?q=is%3Aissue+is%3Aopen+label%3Aroadmap).

> Some in-code design citations reference section numbers (e.g. `§6`) from the
> original `docs/PLAN.md` — retired when v1.0 shipped, but preserved in git history.

## The thesis

Most Bitcoin tooling assumes a human at a terminal confirming each spend. daxib
inverts that: it is built for an **autonomous agent** to hold a wallet and move
sats *within operator-set limits it cannot raise*. Everything below serves that
one goal — make agent-driven custody safe enough to be useful.

daxib is the Bitcoin sibling of [**daxie**](https://github.com/daxchain-io/daxie)
("the Ethereum wallet for AI"). It reuses daxie's security spine and re-grounds it
on Bitcoin's UTXO model.

## One core, two frontends

The single most important structural decision. All business logic lives in **one
core** (`internal/service`); two thin frontends sit on top of it:

- the **CLI** (`internal/cli`) — Frontend 1,
- the **MCP server** (`internal/mcpserver`) — Frontend 2, the agent interface.

A frontend parses flags/env/stdin into a request struct, calls a service method,
and renders the result. It contains no business logic. The payoff: the CLI and the
MCP server traverse the *exact same* code and the *exact same* guardrails, so they
can never drift, and **neither can bypass a guardrail** because the guardrails live
*below* both of them, in the core.

Below the core are **provider leaves** (`internal/keys`, `backend`, `config`,
`contacts`, `bip322`, `psbt`, `policy`, `policyseal`, `journal`, `coinselect`) —
each a focused capability the core composes.

This layering is not a convention you have to remember; it is a **compile-time
lattice**. `internal/arch_test.go` and the depguard rules in `.golangci.yml` make
it a *failing test* for a frontend to import a provider, for a provider to import
the core, or for one frontend to import the other. Business logic physically cannot
leak upward into a frontend, and a frontend physically cannot reach a key or the
policy engine directly. (When you add a provider leaf, the lattice already has a
slot reserved for it — see the `psbt` entry that predated the PSBT noun.)

## State classes

daxib separates its on-disk state into four classes, each independently
overridable, so it slots into hostile environments (read-only config mounts,
ephemeral state, a shared keystore):

| Class | Holds | Default | Override |
|---|---|---|---|
| config | `config.toml`, the sealed policy anchor | `~/.daxib` | `--config` / `DAXIB_CONFIG` |
| keystore | encrypted wallet blobs + the verifier | `~/.daxib/keystore` | `--keystore` / `DAXIB_KEYSTORE` |
| state | the tx journal + locks | `~/.daxib/state` | `--state-dir` / `DAXIB_STATE_DIR` |
| cache | derived, disposable | (under state) | — |

By default everything lives under a single discoverable `~/.daxib/` home — a
deliberate divergence from daxie's `~/.config/daxie`, so a whole wallet is one
easy-to-back-up directory.

## The guardrail spine (the reason daxib exists)

The crown jewels carried over from daxie, re-grounded on Bitcoin. The *mechanics*
are in [SECURITY.md](SECURITY.md); the *rationale* is here.

- **Two passphrases, two trust domains.** The *keystore* passphrase unlocks signing
  (the agent may hold it); the *admin* passphrase authorizes policy changes (the
  operator holds it, the agent never does). Splitting them means a fully
  prompt-hijacked agent can spend *up to* the limits but cannot *change* them.
- **A sealed policy, enforced at one chokepoint.** Spend limits (per-tx / per-day /
  max fee-rate) and allow/deny lists are carried in an **Ed25519-sealed** body
  pinned by a config-class anchor; the agent host holds only the verify key.
  Enforcement happens in the **one signing chokepoint** — every path that reaches a
  private key (`tx send`, RBF `tx speedup`/`cancel`, and `psbt sign`) calls the
  policy engine *before* a single byte is signed. There is exactly one door, and
  it is guarded. The lattice is what *guarantees* there is only one door: a
  frontend cannot reach `keys` except through the core.
- **Fail closed.** A malformed limit, an unverifiable seal, an unparseable counter,
  a possibly-live transaction — every ambiguous case denies or over-counts rather
  than opening the gate.

## The Bitcoin-native design

Where Bitcoin forced genuinely different choices from daxie's account model:

- **UTXO model + coin selection.** No account balance — a wallet *is* a set of
  unspent outputs. `internal/coinselect` (BnB + a fallback, accurate P2WPKH vsize)
  picks inputs and computes change; this is the front half of every spend and the
  thing the sealed fee-rate cap protects (an unsupervised agent must not torch the
  treasury on fees).
- **Network-agnostic wallets.** A BIP-39 seed spans every network, so by default a
  daxib wallet does too: it stores both BIP-44 coin-type account xpubs (mainnet =
  0, all test nets = 1) and derives addresses for whatever network is active
  (`bc1` / `tb1` / `bcrt1`). `--bind` opts into a wallet locked to one network with
  a hard guard. Crucially there is **no silent network default** — every
  network-using op requires `--network` / `DAXIB_NETWORK` / a persisted default, so
  an agent can never silently act on mainnet.
- **PSBT as the interop + custody seam.** P2WPKH/BIP-84 only, but the signing path
  is structured around BIP-174 PSBTs (`internal/psbt`). `psbt sign` runs the same
  policy chokepoint as `tx send` and signs only wallet-owned inputs, so PSBT is
  interop, not a bypass. This is also the building block for the strongest forward
  posture — **watch-only + an external signer**, where no private key lives on the
  agent host at all (see the roadmap).

## The daxie → daxib mapping

- **Carried over wholesale** (the ~70% that is the real value): the one-core /
  two-frontends architecture, the two-passphrase model, the sealed-policy engine +
  anchor, the durable journal + reconciliation, the exit-code contract, the signed
  supply chain, and the agent/MCP surface.
- **Dropped** (Ethereum-only, no base-layer analog): nonces, gas/EIP-1559, ERC-20
  token plumbing, EVM calldata.
- **Net-new, uniquely Bitcoin:** the UTXO/coin-selection engine, P2WPKH/BIP-84
  derivation, network-agnostic wallets, RBF, BIP-322 message signing, PSBT, and the
  Core-vs-Esplora backend seam.

## Conventions

- **Typed errors, deterministic exits.** Every failure is a typed `domain` error
  with a dotted code (`policy.denied.fee_rate`) that maps to a stable process exit
  code (0–12). Agents branch on the exit code; humans read the message. See the
  exit-code table in [COMMANDS.md](COMMANDS.md).
- **Non-interactive by construction.** Every command has a `--json` form, a
  non-interactive secret channel (`DAXIB_PASSPHRASE[_FILE]`, …), and no hidden TTY
  requirement — the wallet is meant to be driven by a program.
- **Verify the supply chain.** Releases are cosign-signed (keyless OIDC + Rekor)
  with SBOMs and SLSA provenance; see [SECURITY.md](SECURITY.md#supply-chain-verifying-a-release).
