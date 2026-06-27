# Security model

daxib is an agent-first Bitcoin wallet: it is built to hand an autonomous agent the
keys and let it spend on its own, within limits an operator sets and the agent
cannot raise. That design goal — *autonomous spending you can still bound* — is what
this document is about. It states the threat model honestly, describes exactly which
mechanisms defend what, and names the residual risk plainly rather than hiding it.

The objective, in one sentence:

> A fully prompt-hijacked agent that holds the keystore passphrase must not be able
> to extract key material, spend beyond operator-set policy, or change that policy —
> while a thief with the disk but no passphrase gets nothing.

## The two secrets

daxib splits its trust into **two independent passphrases**. They are not the same
secret, they are not interchangeable, and they are derived with **distinct salts and
distinct KDF parameters**, so holding one buys nothing toward forging the other.

| Secret | Buys you | Who holds it | Env / flag channel |
|---|---|---|---|
| **Keystore passphrase** | unlocks signing — decrypts the seed and signs transactions | the agent may hold it (autonomous signing) | `DAXIB_PASSPHRASE[_FILE]`, `--passphrase-stdin/-file` |
| **Admin passphrase** | authorizes policy mutations — derives the key that seals the spend policy | the operator only; **the agent never holds it** | `DAXIB_ADMIN_PASSPHRASE[_FILE]`, `--admin-passphrase-stdin/-file` |

The split is the spine of the whole design. The agent can sign all day with the
keystore passphrase, but every signature is checked against a policy it cannot
re-seal — because re-sealing needs the admin passphrase, which lives somewhere the
agent cannot reach.

These are genuinely separate KDF domains:

- The **keystore** runs `scrypt(passphrase, salt, N=2^18, r=8, p=1)` to a 32-byte
  key, with a fresh random 32-byte salt per encrypted file.
- The **admin/policy** seal runs `scrypt(adminPass, salt, N=2^17, r=8, p=1)` then an
  HKDF-SHA256 expansion, under its own fresh 32-byte salt.

Different costs, different salts, different output use (AES key vs. Ed25519 seed),
and the HKDF info string (`daxib/policy/sig-seed/v1`) domain-separates the policy
seed from every other key derivation in the binary. A compromised agent that has
extracted the keystore passphrase gains no head start on forging a policy seal.

## The keystore: encryption at rest

Each keystore secret — the verifier blob and every wallet seed blob — is encrypted
independently in daxib's own on-disk envelope (it is deliberately **not**
geth-V3-compatible):

```text
scrypt(passphrase, salt, N=2^18, r=8, p=1) -> 32-byte key
aes.NewCipher(key)                         -> AES-256 block cipher
cipher.NewGCM(block)                       -> AES-256-GCM AEAD
gcm.Seal(nonce, plaintext, ...)            -> ciphertext authenticated by the GCM tag
```

AES-256-GCM authenticates the ciphertext with its own tag, so there is no separate
MAC to mis-order. A wrong passphrase, a flipped bit, or a truncated file all fail the
GCM tag check identically and map to `keystore.bad_passphrase` (exit 4) — daxib never
distinguishes "wrong passphrase" from "tampered file", because under an AEAD they are
the same event.

Hardening choices worth naming:

- **A verifier blob proves the passphrase before any key material is touched.** The
  manifest (`keystore.json`) carries 32 random bytes sealed under the keystore
  passphrase. Every operation that adds key material decrypts the verifier first, so
  a wrong passphrase fails fast against the verifier rather than against a real seed.
- **KDF cost parameters are validated before scrypt runs.** On open, daxib rejects
  any envelope whose `r`, `p`, `dklen`, or `N` is outside the fixed allowed set
  (`N` must be the standard `2^18` or the test-only `2^12`) **before** invoking
  scrypt, as `state.corrupt`. A tampered file cannot drive scrypt with attacker-chosen
  work (a CPU/memory bomb) — this is a deliberate divergence from geth's uncapped
  decrypt path.
- **A light-cost downgrade cannot be forced by an env var.** The `DAXIB_KDF_LIGHT`
  test escape hatch is recorded as a flag in the manifest at creation; a production
  keystore (created without it) always uses `N=2^18` even if the env var is later set.
- **File permissions are a tripwire.** Keystore files are written `0600` (dirs
  `0700`), and insecure permissions are surfaced as an integrity error
  (`keystore.perms_insecure`, exit 12) rather than silently tolerated.

## The sealed policy: how limits resist a compromised agent

The spend policy (per-tx cap, per-day rolling-24h cap, max fee-rate, allow/deny
lists, per-network overrides) is not just a config file the agent could rewrite. It
is **cryptographically sealed**, and the seal can only be forged by whoever holds the
admin passphrase.

### The seal (scrypt -> HKDF -> Ed25519)

```text
salt     = 32 random bytes (generated at first `policy set`)
K_master = scrypt(adminPass, salt, N=2^17, r=8, p=1, dkLen=32)
K_seed   = HKDF-SHA256(K_master, info="daxib/policy/sig-seed/v1", L=32)
(sk, pk) = ed25519.NewKeyFromSeed(K_seed)
sig      = ed25519.Sign(sk, "daxib/policy/v1\n" || policyBody)
```

This is an **asymmetric** primitive on purpose. A symmetric MAC was rejected:
any MAC key the agent can read in order to *verify* the policy is a key a compromised
agent could re-seal a tampered policy with. With Ed25519, verifying and forging are
different keys:

- The **secret key** signs the policy body. It only ever exists transiently, derived
  from the admin passphrase at the moment of a mutation, and is zeroed immediately
  after signing.
- The **verify (public) key** is pinned in a machine-only anchor. The agent host
  holds *only* this verify key. It can check the seal on every signing operation, but
  it can never produce a new one.

The signed subject is `"daxib/policy/v1\n" || body` — a domain-separated prefix, so a
raw Ed25519 verify of a bare body cannot pass — and the seal covers the **exact**
canonical body bytes written by the ordered writer, never a re-marshaled projection.

### The pinned anchor and the env/flag carve-out

The trust root lives in `policy-anchor.json` inside the config directory. It holds
the verify key, the admin KDF salt and pinned scrypt params, and a monotonic
`nonce_watermark` (the anti-rollback floor). Two properties make it resistant to an
agent that controls its own environment:

- **It is read directly by file path, never through a TOML key, an env var, or a
  flag.** There is no `DAXIB_*` variable and no `--flag` that names or relocates the
  anchor file; the path is a fixed join of the resolved config directory and the
  constant filename. This is the carve-out that matters: **`DAXIB_POLICY_*`-style
  environment cannot influence the sealed policy or the pinned verify key.** A
  compromised agent cannot inject a self-generated verify key from its own
  environment and pair it with a self-forged `policy.json` to "outvote" the admin
  passphrase.
- **The anchor and params are pinned, not inferred.** A present binary verifies a
  file written by any other binary regardless of compile-time defaults, and a
  future-version anchor with unknown fields fails closed (`DisallowUnknownFields`)
  rather than being silently truncated.

### Enforcement in the one signing chokepoint

There is exactly **one** path from "an operation wants to move funds" to "the
keystore signs", and the policy check sits in it, **before** the signature exists.
In the send pipeline the transaction is fully built — recipient, amount, fee,
fee-rate, change all known — and then, *before* `SignInputs` is called, the engine:

1. Loads `policy.json` and **verifies its seal under the pinned anchor**. A bad
   signature, a missing policy under a pinned anchor, a policy present with no anchor,
   a nonce below the watermark (rollback), or an unknown body field all fail closed
   (`policy.seal_violation`, exit 8). Signing halts.
2. Runs the **pure evaluation** in precedence order: denylist > allowlist gate >
   per-tx cap > rolling-24h day cap (fee included) > fee-rate cap. The first
   violation wins. A denial is `policy.denied.*` (exit 3), or the fee-rate cap
   denial which is exit 7 (retryable — the fee market moves).
3. On allow, **durably reserves** the spend in the per-network rolling-24h counter
   under a cross-process lock — written to disk *before* any signature exists.

Because the reservation is durable before signing, a crash or a self-SIGKILL after
the check can only ever *under*-spend the budget, never escape it. The same
`policy.Reserve` lives inside the MCP `send` / `tx_speedup` / `tx_cancel` handlers,
so the guardrails apply identically whether the spend was initiated from the CLI or
by an agent over MCP — there is no second, unchecked signing path.

A few details that make specific evasions not work:

- **The allowlist `include_self` gate matches a sealed snapshot, not the live
  keystore.** A prompt-compromised agent cannot import an attacker-controlled key to
  mint itself an "own" address that passes the allowlist; `include_self` compares
  against the `self_addresses` snapshot that was sealed into the policy, plus the
  transaction's own change address.
- **A present-but-unparseable limit fails closed, not open.** A corrupt or garbage
  numeric limit is treated as a zero ceiling (denying every positive spend), never
  as "no limit". The seal should keep a bad value from ever reaching evaluation; this
  is defense in depth.
- **The rolling-24h counter survives restarts and reconciles crashes.** Reservations
  move reserved -> committed (broadcast accepted) or reserved -> released (pre-sign
  failure); a committed row is never auto-released (over-counting is the safe
  direction). Orphans left by a crash are reconciled at startup against the journal.

### Mutations are admin-gated and authenticated against the anchor

Every policy mutation — `policy set` (the first one bootstraps the anchor),
`policy allow`, `policy deny`, `policy reset`, `policy release` — requires the admin
passphrase. The engine re-derives the key family from the admin passphrase and the
anchor salt and **constant-time-compares** the derived verify key to the pinned one
before doing anything. A wrong passphrase is `policy.admin_auth` (exit 4), distinct
from a seal violation.

This means even a destructive agent cannot reset its way around the limits:
`policy reset` re-seals a fresh default body under the **existing** key family and
authenticates against the **anchor**, so an agent that trashed `policy.json` cannot
re-seal it under a passphrase of its own choosing — its passphrase never derives the
pinned key. Each mutation bumps the body nonce past the watermark, so a rolled-back
older policy fails the anti-rollback check.

None of these mutations are exposed over MCP (see below).

## Crash-safe rotations: recovery never wipes the guardrails

Both passphrases can be rotated, and both rotations are designed so that a crash at
any point leaves a coherent, still-enforced state — never an opened-up one.

### Keystore passphrase (`keystore change-passphrase`)

Re-encrypts the verifier and every wallet blob from the old passphrase to the new
one as a **stage -> mark -> swap** protocol: each re-encryption is written as
`<file>.new` (fresh salts/nonces), a commit marker is dropped, then each `.new` is
renamed onto its target and the marker deleted. The next `keys.Open` heals an
interrupted rotation under the exclusive lock: **roll forward** if the commit marker
is present, **roll back** the orphaned `.new` files otherwise. A crash leaves either
the all-old or the all-new keystore, never a mix. This command is CLI / operator-only
and has no MCP tool.

### Admin passphrase (`policy change-admin-passphrase`)

Rotating the admin passphrase means re-deriving the seal key under a new passphrase
and re-sealing the policy — a single-shot version of which could, on a crash, leave
`policy.json` sealed under the new key while the on-disk anchor still pinned the old
one, making the guardrails unverifiable (fail-**open**). daxib instead uses a
**three-phase staged dual-key rotation**:

- **Stage** — land a dual-key anchor `{verify_key: OLD, verify_key_next: NEW,
  staged_salt}`. `policy.json` is still sealed under OLD and still verifies (the
  signing path accepts either pinned key during a rotation).
- **Reseal** — re-seal `policy.json` under the NEW key (nonce bumped). It now
  verifies under `verify_key_next`; the anchor is unchanged.
- **Promote** — land the final single-key anchor `{verify_key: NEW}` and clear the
  staged fields.

At **every** crash point the (anchor, `policy.json`) pair verifies under *some* key
the anchor pins, so the guardrails stay intact and the limits are never wiped.
Recovery at startup converges a half-finished rotation by inspecting which key
`policy.json` verifies under: roll **forward** (promote) if it is already resealed
under NEW, roll **back** (drop the staged key) otherwise. If it verifies under
neither key, recovery fails closed and leaves the anchor untouched rather than ever
widening the trust root on a corrupt body.

## The MCP surface: a deliberately narrow boundary

daxib's MCP server is the agent's interface to the same core. Its surface is narrowed
on purpose, and the boundary is enforced by **absence** — there simply is no handler
and no registration for the forbidden operations, and a test asserts the registered
set stays disjoint from the excluded set:

- **Exposed:** reads (`balance`, `utxo_list`, `wallet_list`, `wallet_show`,
  `address_list`, `fee`, `tx_status`, `tx_wait`, `tx_list`), the read-only policy
  views (`policy_show`, `policy_check`), pure utilities (`verify`, `convert`), the
  receive affordance (`address_new`), keystore-gated message signing (`sign_message`,
  moves no funds), and the fund movers (`send`, `tx_speedup`, `tx_cancel`) — each of
  which routes through the same policy-gated service call the CLI uses.
- **Not exposed (no tool exists):** every policy mutation (`policy_set`,
  `policy_allow`, `policy_deny`, `policy_reset`, `policy_change_admin_passphrase`,
  `policy_pin`, `policy_counters`, `policy_verify`), wallet `create` / `import` /
  `export`, `keystore_change_passphrase`, backend mutations, and network mutations.

In one sentence: the MCP surface can **move funds within policy and read
everything**, but it cannot change who holds the keys, change what the keys may do,
export a key, or repoint the backend.

## Threat model: what is and is not defended

### Defended

- **Disk theft without the passphrase.** Seeds are AES-256-GCM encrypted under
  scrypt(`N=2^18`). A stolen keystore without the keystore passphrase yields nothing.
- **A prompt-hijacked agent spending beyond limits.** The sealed policy is enforced
  in the one signing chokepoint before any signature exists; a hijacked agent can
  spend only *up to* the sealed per-tx, per-day, and fee-rate caps, only to
  non-denied (and, if the allowlist is on, allowlisted) destinations.
- **A hijacked agent raising its own limits.** Mutating the policy needs the admin
  passphrase, which the agent does not hold; the anchor is unreachable through any
  env var or flag; and the seal cannot be forged from the verify key alone.
- **A hijacked agent rolling back to an older, looser policy.** The monotonic nonce
  watermark rejects an older sealed body.
- **A hijacked agent self-minting allowlisted destinations.** `include_self` matches
  a sealed snapshot, not the live keystore.
- **Tampered or corrupt policy / keystore files.** Both fail closed — a broken seal,
  an unknown anchor field, a bad GCM tag, or out-of-range KDF params all halt the
  operation rather than degrading silently.
- **The MCP (agent) channel reaching administrative operations.** Key export,
  wallet/import, policy mutation, passphrase rotation, and backend/network changes
  are absent from the tool surface.

### Not defended (honest residual)

daxib v1 ships **one custody posture: the hot keystore** (deliberately matching its
Ethereum sibling daxie). Custody is an encrypted local keystore inside **one OS trust
domain — the agent's uid.** That single fact is the boundary of what software-in-one-
process can defend, and it is stated, not hidden:

- **A fully prompt-hijacked agent that holds the keystore passphrase can spend up to
  the sealed limits.** Within the per-tx / per-day / fee-rate caps and the allow/deny
  rules, autonomous spending is the *intended* behavior. The guardrails bound the
  blast radius; they do not reduce it to zero.
- **An attacker who fully compromises the agent's uid can read the keystore file and
  a co-resident keystore passphrase, and decrypt the seed offline.** No in-process
  design stops that within a single trust domain. What such an attacker still cannot
  do *through daxib* is **raise the sealed limits or read a key out via the policy /
  MCP path** — the admin passphrase and the pinned anchor are not theirs to forge —
  but offline key extraction given both the file and the passphrase is the
  unavoidable residual of a hot keystore.
- **Same-domain counter tampering is tamper-evident, not tamper-proof.** Within one
  trust domain the rolling-24h counters can be cross-audited (`policy verify`,
  `policy counters`) but not made unforgeable.
- **Backend trust.** An Electrum/Esplora server can lie by omission about UTXOs or
  fees; running your own Bitcoin Core node is the trust-minimized option.

### The stronger postures are roadmap, not v1

The Bitcoin-native ways to *structurally* close the offline-decrypt residual exist,
and daxib's internal tx-building + BIP-143 signing path is meant to make them
low-refactor additions (a `psbt` noun is the first step) — but they are **not in
this release**:

- **Watch-only + external PSBT signer** — no private keys on the agent host at all;
  the agent builds PSBTs and an out-of-band signer signs. This closes the
  host-compromise residual structurally (there is nothing on the box to decrypt).
- **Miniscript / Taproot co-sign + timelock vaults** — guardrails Bitcoin
  *consensus* enforces, where a fully host-compromised agent still produces only a
  half-signed transaction and cannot move funds alone.

These get real once daxib holds meaningful value; v1's job is the working autonomous
wallet with the sealed software guardrails above.

## Supply chain: verifying a release

The guardrails above protect a *running* wallet. They are worth nothing if the
binary you ran isn't the one this project built — so every release is signed, and
you can (and should) verify it before trusting it.

### What is published and signed

Each tagged release carries:

- **Archives** for darwin / linux / windows × amd64 / arm64, plus `checksums.txt`
  (the SHA256 of every archive).
- **A cosign keyless signature** over `checksums.txt`, as a Sigstore bundle
  (`checksums.txt.sigstore.json`) recorded in the public Rekor transparency log.
  There is **no long-lived signing key** to steal: the signature is bound to an
  ephemeral certificate issued to *this repo's `release.yml` workflow running on a
  `vX.Y.Z` tag*, via GitHub's OIDC identity.
- **SBOMs** — a syft SBOM per archive (`*.sbom.json`).
- **SLSA provenance** — a build-provenance attestation for the release assets.
- **A multi-arch OCI image** at `ghcr.io/daxchain-io/images/daxib` (distroless,
  non-root), itself cosign-signed by the same workflow identity.

### Verify an archive

```sh
# 1. Verify the signature on checksums.txt. The identity flags are REQUIRED — without
#    them, cosign accepts ANY valid Sigstore signature, which proves nothing about who
#    produced this file. They pin it to daxib's release workflow on a version tag.
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/daxchain-io/daxib/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

# 2. With checksums.txt now trusted, check the archive you downloaded against it
#    (Linux: sha256sum; macOS: shasum -a 256):
sha256sum --check --ignore-missing checksums.txt
```

A failure on step 1 means the checksums file was not signed by daxib's release
workflow — **do not trust the download**. A failure on step 2 means your archive
does not match the signed checksum (corrupted or tampered in transit).

### Verify the container image

```sh
cosign verify ghcr.io/daxchain-io/images/daxib:1.0.0 \
  --certificate-identity-regexp '^https://github.com/daxchain-io/daxib/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

### What does it for you

The `curl | sh` installer runs exactly this signature check when invoked with
`--verify-signature` (and opportunistically when `cosign` is on `PATH`), and the
Homebrew cask verifies the SHA256 of the archive it installs. The identity +
issuer above are the same values `scripts/install.sh` pins, so a manual check and
the installer agree.

## Reference: the security-relevant exit codes

| Exit | Name | Meaning |
|---|---|---|
| `3` | `POLICY_DENIED` | a guardrail refusal before signing (per-tx / per-day cap, allowlist, denylist) — codes `policy.denied.tx_limit` / `day_limit` / `not_allowlisted` / `denylisted` |
| `4` | `AUTH` | wrong/missing keystore passphrase, undecryptable keystore, or wrong admin passphrase (`policy.admin_auth`) |
| `7` | `FEE_POLICY_DENIED` | computed fee-rate exceeds the max-fee-rate cap (retryable — the fee market moves) |
| `8` | `TIMEOUT_PENDING` | the seal / rollback class: `policy.seal_violation` and friends — all signing halted |
| `12` | `INTEGRITY` | a tamper/misconfig tripwire — insecure keystore perms, a vanished reservation, a backend whose network disagrees with the declared one |
