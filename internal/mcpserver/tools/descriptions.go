package tools

// descriptions.go holds the agent-facing tool descriptions (docs/PLAN.md §6.3) —
// written for a model DECIDING WHICH TOOL TO CALL, not for a human reading docs.
// They are the human-authored half of the §6.7 golden test (the schemas are
// inferred; the descriptions are pinned), so a description change is a reviewed
// diff.
//
// Two descriptions carry load-bearing safety guarantees a model must read before
// it acts:
//   - send carries the spend-equivalent + policy-checked guarantee (the one money
//     mover; policy.Reserve runs INSIDE the service method before any byte is
//     signed).
//   - address_new is the receive affordance — the agent's legitimate path to a
//     fresh invoice address, mirroring how daxie exposes receive's new-address but
//     NOT raw account derivation.
//
// The rest follow the §6.2 conventions: amounts are decimal BTC or integer-sat
// strings (never floats — a satoshi count must round-trip exactly); to/recipient
// accept a bech32/base58 Bitcoin address; wallet is optional everywhere (empty =
// the default wallet); network is the active --network (a wallet is bound to one).

// ── read/list (no signing, no policy) ────────────────────────────────────────

const descBalance = "Read a wallet's confirmed + unconfirmed balance on the active network. Derives the wallet's gap-window address set from its stored xpub (no passphrase), queries the backend's UTXOs, and aggregates them. Returns satoshis (int64) plus an exact BTC decimal string, the UTXO count, and the chain tip. Set 'utxos':true to enumerate the individual coins. 'wallet' is optional (omit for the default wallet). Read-only."

const descUTXOList = "List a wallet's unspent transaction outputs (coins) on the active network: each coin's outpoint (txid:vout), address, value in sats + BTC, and confirmation depth, plus the total. Use this to inspect coin control before a send. 'wallet' is optional. Read-only."

const descWalletList = "List the HD wallets in the keystore: names, ids, network, address counts, creation dates, and which is the default. Returns NON-SECRET grouping metadata only — never a mnemonic, seed, or key. Read-only."

const descWalletShow = "Show one HD wallet by name: its id, network, BIP-84 derivation path prefix, account xpub, next receive/change index, and address count. NON-SECRET metadata only — never a mnemonic or seed. Read-only."

const descAddressList = "List a wallet's materialized addresses on the active network: each address's ref (wallet/branch/index), branch (0 receive, 1 change), index, the bech32 address, and creation time. 'wallet' is optional. Read-only."

const descFee = "Read the backend's current fee-rate estimates (sat/vByte) at three speeds — slow/normal/fast — plus the per-target table and the 1 sat/vB relay floor. 'speed' marks which tier is the headline recommendation (default normal). Use this to choose a fee before a send. Read-only."

const descTxStatus = "Look up a transaction's current status by txid: signed, broadcast, pending, confirmed, or failed. Folds the local journal record with a single live backend re-check (and promotes a journaled tx to confirmed when the chain confirms it); never broadcasts. A txid that is neither journaled nor on-chain is a clean ref.not_found error. Read-only."

const descTxWait = "Block until a transaction reaches its confirmation target, streaming progress. Rebroadcasts a still-signed journal record first (the lost-broadcast window), then polls. 'confirmations' overrides the default target (1); 'timeout' (Go duration, e.g. '30m') bounds the wait. At the deadline it returns status:'timeout' as a tool error (code tx.wait_timeout) PLUS the structured result with a resume command — re-call to resume. Read-only (it waits on an existing tx; it never signs)."

const descTxList = "List this wallet's transactions from the local journal, newest first: journal id, txid, status, recipient, amount, fee, vsize, confirmations, and timestamp. Filter by 'wallet' and cap with 'limit' (0 = no limit). The journal is the durable history. Read-only."

const descPolicyShow = "Read the active signing policy: whether guardrails are sealed, the default and per-network spend limits (max-tx, max-day, max-fee-rate), the destination allowlist and denylist, and the sealed self-address count. Use this to pre-flight whether a transfer is in-policy before you try it. READ-ONLY — there is NO tool to change the policy (mutations are admin-passphrase-gated and operator-only). Read-only."

const descPolicyCheck = "Dry-run evaluate a hypothetical send against the active policy WITHOUT reserving budget or signing anything: would this recipient + amount be allowed? Returns allowed:true, or allowed:false with the dotted denial code (policy.denied.*) and reason. 'to' and 'amount' are required; 'fee_rate'/'fee_sat' refine the estimate. Read-only (no reservation is written)."

// ── funds-moving / mutation tools ────────────────────────────────────────────

// descSend carries the spend-equivalent + policy-checked guarantee (§6.3/§6.4).
const descSend = "Sign and broadcast a Bitcoin transfer. Coin-selects from the wallet's confirmed UTXOs, then POLICY-CHECKS the spend (per-tx limit, rolling-24h limit, fee-rate cap, destination allowlist) BEFORE a single byte is signed — a denied or over-limit send produces no signature and moves no funds. 'to' is a Bitcoin address for the active network; 'amount' is a decimal BTC string or an integer-sat string (never a float you computed); 'fee_rate' (sat/vByte) overrides the 'speed' tier. Set 'dry_run':true to preview without broadcasting. Waits for confirmation by default over MCP. Returns the txid, fee, and lifecycle status."

// descAddressNew is the receive affordance (§6.1): the agent's legitimate path to
// a fresh invoice address.
const descAddressNew = "Derive and record the NEXT receive address for a wallet (a fresh invoice address to hand a counterparty). Derivation is from the stored xpub — no passphrase, no signing. Set 'change':true for an internal change address instead (rarely needed). Returns the ref (wallet/branch/index), the bech32 address, and the full BIP-84 path. This is the agent's sanctioned way to get a new address; raw key derivation and wallet creation are NOT exposed."
