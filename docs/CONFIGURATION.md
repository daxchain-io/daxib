# Configuring and operating daxib

This guide covers everything about *running* daxib: where it keeps its files, how
to point those files somewhere else, the full `DAXIB_*` environment surface, how
the active network is chosen, the operator config keys, and how to wire up a
Bitcoin backend (Core/bitcoind RPC or Esplora).

daxib is built to be driven by agents and scripts as readily as by a human, so
every operating knob has three ways in: a flag, an environment variable, and (for
the durable ones) a value persisted in `config.toml`. They resolve in a clear
order, and nothing important happens by silent default.

## On-disk layout

By default daxib keeps everything in a single, easy-to-back-up dotfolder under
your home directory: `~/.daxib`. One tree, the whole wallet — deliberately
diverging from the platform XDG/AppData split in favor of one discoverable
directory.

```text
~/.daxib/
├── config.toml          # backends + persisted defaults (the config class)
├── policy-anchor.json    # sealed policy trust root (when a policy is sealed)
├── keystore/             # encrypted wallet blobs + verifier (the keystore class)
└── state/                # tx journal + send/journal locks (the state class)
```

There are four state classes, and each can be relocated independently:

| Class    | Default path           | Holds                                                          |
| -------- | ---------------------- | ------------------------------------------------------------- |
| Config   | `~/.daxib`             | `config.toml` (backends, persisted active-network default)    |
| Policy   | `~/.daxib`             | `policy-anchor.json`, the sealed spend-policy trust root      |
| Keystore | `~/.daxib/keystore`    | encrypted mnemonic/key blobs and the keystore verifier        |
| State    | `~/.daxib/state`       | the transaction journal and the send/journal locks            |

The config and policy classes share one directory: `--config` / `DAXIB_CONFIG`
denote that *directory* (not a single file), and the policy anchor lives beside
`config.toml` inside it. The policy anchor is read directly by file path — it is
deliberately **not** addressable through any `DAXIB_*` variable of its own, so a
compromised environment cannot redirect the trust root.

## Relocating the directories

Each class has a flag and a matching environment variable. The flag wins over the
variable, which wins over the `~/.daxib` default.

| Class    | Flag          | Environment variable | Default            |
| -------- | ------------- | -------------------- | ------------------ |
| Config   | `--config`    | `DAXIB_CONFIG`       | `~/.daxib`         |
| Keystore | `--keystore`  | `DAXIB_KEYSTORE`     | `~/.daxib/keystore` |
| State    | `--state-dir` | `DAXIB_STATE_DIR`    | `~/.daxib/state`   |

`--config` / `DAXIB_CONFIG` name the config **directory**, not the `config.toml`
file — daxib joins `config.toml` inside it. If the home directory cannot be
determined and no override is given, daxib falls back to a relative `.daxib`.

These are global flags: they appear on every command and can be combined freely,
for example to run a fully self-contained instance out of one tree:

```sh
daxib --config /srv/daxib --keystore /srv/daxib/keystore \
      --state-dir /srv/daxib/state network show
```

## Environment variables

The complete `DAXIB_*` surface. Variables marked *secret channel* never appear as
a flag value — they carry passphrases and mnemonics only through a file path or
stdin, never on the command line.

### Paths

| Variable          | Effect                                                       |
| ----------------- | ----------------------------------------------------------- |
| `DAXIB_CONFIG`    | config directory (holds `config.toml` + the policy anchor)  |
| `DAXIB_KEYSTORE`  | keystore directory                                          |
| `DAXIB_STATE_DIR` | mutable state directory (tx journal + locks)                |

### Selection

| Variable          | Effect                                                              |
| ----------------- | ------------------------------------------------------------------ |
| `DAXIB_NETWORK`   | active network (`mainnet`/`testnet`/`testnet4`/`signet`/`regtest`) |
| `DAXIB_WALLET`    | active wallet name (the default for commands that take `--wallet`) |
| `DAXIB_BACKEND`   | active backend endpoint name (overrides the network's default)     |

### Keystore passphrase (the signing secret — an agent may hold it)

The keystore passphrase unlocks signing. It resolves by the precedence
**stdin flag > `--*-file` > `*_FILE` env > direct env > interactive prompt**
(prompt only at a TTY; otherwise daxib returns a deterministic error rather than
hanging). The `*_FILE` channel strips one trailing newline so a `printf` or a
Kubernetes Secret file works cleanly; the direct env value is used verbatim.

| Variable                       | Effect                                                       |
| ------------------------------ | ------------------------------------------------------------ |
| `DAXIB_PASSPHRASE`             | keystore passphrase, value (the documented least-safe form)  |
| `DAXIB_PASSPHRASE_FILE`        | path to a file holding the keystore passphrase (recommended) |
| `DAXIB_PASSPHRASE_CONFIRM`     | first-init only: confirm the new passphrase (value)          |
| `DAXIB_PASSPHRASE_CONFIRM_FILE` | first-init only: confirm the new passphrase (file path)     |

Rotating the keystore passphrase (`daxib keystore change-passphrase`) reads the
**old** passphrase through the channels above and the **new** one through its own:

| Variable                            | Effect                                  |
| ----------------------------------- | --------------------------------------- |
| `DAXIB_NEW_PASSPHRASE`              | new keystore passphrase (value)         |
| `DAXIB_NEW_PASSPHRASE_FILE`        | new keystore passphrase (file path)     |
| `DAXIB_NEW_PASSPHRASE_CONFIRM`     | confirm the new keystore passphrase     |
| `DAXIB_NEW_PASSPHRASE_CONFIRM_FILE` | confirm the new keystore passphrase (file) |

### Admin passphrase (policy mutations — the agent never holds this)

The admin passphrase is independent of the keystore passphrase, with its own
flags and variables. It authorizes spend-policy changes; keep it out of any
environment an autonomous agent can read.

| Variable                         | Effect                                            |
| -------------------------------- | ------------------------------------------------- |
| `DAXIB_ADMIN_PASSPHRASE`         | policy admin passphrase (value)                   |
| `DAXIB_ADMIN_PASSPHRASE_FILE`    | policy admin passphrase (file path)               |
| `DAXIB_ADMIN_NEW_PASSPHRASE`     | new admin passphrase, for `change-admin-passphrase` |
| `DAXIB_ADMIN_NEW_PASSPHRASE_FILE` | new admin passphrase (file path)                 |

### Other

| Variable               | Effect                                                                |
| ---------------------- | -------------------------------------------------------------------- |
| `DAXIB_KDF_LIGHT`      | use the cheap test scrypt cost on **first keystore init only**       |
| `DAXIB_SKIP_PERM_CHECK` | skip the `0600` permission check on secret files (use sparingly)    |

`DAXIB_KDF_LIGHT` is a test convenience: when set, a brand-new keystore is created
with a low scrypt cost so test runs stay fast, and the manifest records that it
was made light. A production keystore (created without the variable) can **never**
be downgraded — setting `DAXIB_KDF_LIGHT` later has no effect on it, because the
cost is read from the manifest, not the environment. Do not use it for a keystore
that holds real funds.

## Networks and how the active network resolves

daxib supports five Bitcoin networks. None is ever chosen silently — there is no
hidden default to mainnet.

```sh
daxib network list
```

```text
NETWORK   COIN_TYPE  ACTIVE
mainnet   0
testnet   1
testnet4  1
signet    1
regtest   1          *
```

The active network is resolved by a three-rung ladder, and a network-requiring
command with nothing selected fails with `usage.network_required` (exit code 2):

1. `--network <net>` flag
2. `DAXIB_NETWORK` environment variable
3. the persisted default in `config.toml` (`defaults.network`), set with
   `daxib network use <net>`

Inspect the outcome — and where it came from — with `network show`:

```sh
daxib network show          # e.g. "active network: signet (source: flag|env|config)"
daxib network use signet    # persist the default (rung 3)
daxib network use clear     # clear it (back to unresolved); `none` or "" also clear
```

`network show` and `network list` answer "what is the active network" and work
even when none is selected. `network use` writes into `config.toml`, so it needs a
config directory (`--config` / `DAXIB_CONFIG`, or the `~/.daxib` default).

### Wallets are network-agnostic by default

A wallet created with `daxib wallet create <name>` works on **every** network —
`--network` only decides which HRP a printed receive address uses. To lock a
wallet to a single network (refusing operations on any other), create it with
`--bind`, which binds it to the resolved active network at creation time.

## The `config` keys

`daxib config` reads and writes the small set of operator-tunable keys in
`config.toml`. The named `[backend.<name>]` endpoint objects are managed by the
`backend` noun (below), not listed here as scalar keys. Policy keys live in the
sealed anchor and are **rejected** by `config` — set them through `daxib policy`
with the admin passphrase.

```sh
daxib config list                                   # all keys + effective values + source
daxib config get defaults.network
daxib config set networks.signet.default-backend my-esplora
```

| Key                                  | Meaning                                                                                          |
| ------------------------------------ | ------------------------------------------------------------------------------------------------ |
| `defaults.network`                   | the persisted active-network default (resolution rung 3); one of the five networks, or `""` to clear |
| `networks.<network>.default-backend` | the endpoint dialed for `<network>` when no `--backend` / `DAXIB_BACKEND` override is given       |

Notes:

- `config set defaults.network <net>` is the same write as `network use <net>`.
- Setting `networks.<net>.default-backend` to a non-empty value requires that the
  named endpoint **exists** and is bound to `<net>` (the same guard `backend use`
  enforces); an empty value clears the default.
- `config get` on an unknown key is `ref.not_found` (exit 10); `config set` on a
  `policy.*` key is rejected (exit 2); a read-only config mount fails with
  `config.read_only` (exit 10).

## Backends

A backend is a named connection to a Bitcoin node, bound to one network, stored in
`config.toml`. daxib speaks two backend types: a Bitcoin Core (bitcoind) JSON-RPC
node and an Esplora REST server.

```sh
daxib backend list                 # masked URLs, network, type, default marker
daxib backend test [name]          # dial it, report tip height + latency
daxib backend use <name>           # make it the default for its network
daxib backend remove <name>        # remove it (clears any default pointing at it)
```

`backend test` with no name dials the active network's default; a dead endpoint
exits 6 (`backend.unreachable`).

### Core / bitcoind RPC

```sh
# username/password auth
daxib backend add core-main --network mainnet --type core \
  --url http://127.0.0.1:8332 \
  --rpcuser '${env:BTC_RPC_USER}' \
  --rpcpassword '${env:BTC_RPC_PASS}'

# cookie-file auth (bitcoind rotates the cookie on restart; daxib reads it fresh)
daxib backend add core-main --network mainnet --type core \
  --url http://127.0.0.1:8332 \
  --rpccookie ~/.bitcoin/.cookie
```

Authenticate with either `--rpcuser`/`--rpcpassword` **or** `--rpccookie` (a path
to bitcoind's `.cookie` file). Provide secrets as `${env:VAR}` or `${file:/path}`
references, not literals — see [Secret references](#secret-references) below.

> **Run bitcoind with `txindex=1`.** daxib is stateless: it never creates or loads
> a bitcoind wallet, and reads UTXOs with `scantxoutset`. To observe confirmations
> of its **own** sends, `tx status` calls `getrawtransaction`, which on a no-wallet
> node can only find a confirmed, non-wallet transaction when the node has a
> transaction index. Without `txindex=1`, `tx status` cannot see the confirmation
> of a transaction daxib broadcast. Set `txindex=1` in `bitcoin.conf` (a one-time
> reindex) on any Core backend daxib sends from.
>
> **Hosted Bitcoin APIs (e.g. Alchemy) disable `scantxoutset`.** daxib's Core path
> derives balances/UTXOs from `scantxoutset`, which hosted providers turn off. For
> a remote node, prefer an **Esplora** backend instead.

### Esplora

```sh
daxib backend add esplora-signet --network signet --type esplora \
  --url https://blockstream.info/signet/api
```

Esplora needs only a `--url` (the REST base) — no RPC auth. It is the
recommended choice for a remote or hosted node, since it does not depend on the
`scantxoutset` RPC that hosted providers disable. If the base URL itself carries a
credential (an API key in the path/query), use a `${env:}` / `${file:}` reference
for that segment.

### Secret references

Endpoint secrets (the URL, `--rpcuser`, `--rpcpassword`) should be **references**,
stored raw and resolved only at dial time — never persisted in resolved form:

| Form           | Resolves to                                                          |
| -------------- | ------------------------------------------------------------------- |
| `${env:NAME}`  | the value of environment variable `NAME` (unset/empty → error)      |
| `${file:/abs}` | the file contents, one trailing newline stripped, permissions checked |
| `${file:~/x}`  | `~` expands to your home directory, then as `${file:}`              |
| `$${`          | a literal `${` (the escape)                                         |

`backend list` masks resolved/literal secrets in its output, and error messages
redact any literal credential embedded in a URL. A reference (`${env:…}` /
`${file:…}`) is shown verbatim — it names *which* variable or file is used, which
is not itself the secret. Passing a literal `--rpcpassword` is allowed but warned
against; prefer a reference.

## Quick start

A minimal signet setup, end to end:

```sh
export DAXIB_NETWORK=signet
export DAXIB_PASSPHRASE_FILE=~/.daxib/pass.txt   # 0600

daxib network use signet                          # persist the default
daxib backend add esplora-signet --type esplora \
  --url https://blockstream.info/signet/api
daxib backend use esplora-signet
daxib backend test                                # confirm reachability
daxib wallet create main                          # records the mnemonic ONCE
```

From here, `daxib backend list`, `daxib config list`, and `daxib network show`
tell you exactly how the wallet is wired.
