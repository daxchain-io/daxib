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
// the default wallet); network is the active --network. A wallet is network-
// agnostic by default (one wallet works on every network); a wallet created with
// --bind is locked to a single network and refuses ops on any other.

// ── read/list (no signing, no policy) ────────────────────────────────────────

const descBalance = "Read a wallet's confirmed + unconfirmed balance on the active network. Derives the wallet's gap-window address set from its stored xpub (no passphrase), queries the backend's UTXOs, and aggregates them. Returns satoshis (int64) plus an exact BTC decimal string, the UTXO count, and the chain tip. Set 'utxos':true to enumerate the individual coins. 'wallet' is optional (omit for the default wallet). Read-only."

const descUTXOList = "List a wallet's unspent transaction outputs (coins) on the active network: each coin's outpoint (txid:vout), address, value in sats + BTC, and confirmation depth, plus the total. Use this to inspect coin control before a send. 'wallet' is optional. Read-only."

const descWalletList = "List the HD wallets in the keystore: names, ids, scope (agnostic or bound:<network>), the effective network and its coin_type, address counts, creation dates, and which is the default. Returns NON-SECRET grouping metadata only — never a mnemonic, seed, or key. Read-only."

const descWalletShow = "Show one HD wallet by name: its id, scope (agnostic or bound), the effective network and coin_type, BIP-84 derivation path prefix, account xpub, next receive/change index, and address count. An agnostic wallet renders against the active network; a bound wallet against its locked network. NON-SECRET metadata only — never a mnemonic or seed. Read-only."

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

// ── RBF replacements (policy-gated, like send) ───────────────────────────────

// descTxSpeedup is the speedup RBF replacement (GAP-2): policy-gated exactly like
// send (the replacement is coin-selected → policy.Reserve → signed → broadcast).
const descTxSpeedup = "Replace an unconfirmed, RBF-signaling send with a higher-fee transaction paying the SAME recipient (Bitcoin BIP-125 fee bump). The replacement is POLICY-CHECKED before signing exactly like a fresh send — only the additional fee is charged against the rolling-24h limit, but the fee-rate cap and destination rules still apply. 'txid' is the original (still-unconfirmed) transaction; 'fee_rate' (sat/vByte) overrides the default bump (the backend fast tier, never below the original + 1). Waits for confirmation by default over MCP. Returns the replacement txid (replaces_txid names the original) and status. A target already confirmed/replaced is a tx_conflict error."

// descTxCancel is the cancel RBF replacement (GAP-2): redirects the funds to the
// wallet itself, voiding the payment; policy-gated like send.
const descTxCancel = "Cancel an unconfirmed, RBF-signaling send by replacing it with a higher-fee transaction that redirects ALL funds to a fresh wallet-owned change address, voiding the original payment (Bitcoin BIP-125). The replacement is POLICY-CHECKED before signing like any send (paying yourself always satisfies the destination rules; the fee-rate cap still applies). 'txid' is the original (still-unconfirmed) transaction; 'fee_rate' (sat/vByte) overrides the default bump (the backend fast tier, never below the original + 1). Waits for confirmation by default over MCP. Returns the replacement txid (replaces_txid names the voided original) and status. A target already confirmed/replaced is a tx_conflict error."

// ── BIP-322 message sign / verify ────────────────────────────────────────────

// descSignMessage is keystore-gated (it unlocks a key), like send. The keystore
// passphrase arrives out-of-band (the env channel), never as a tool argument.
const descSignMessage = "Sign an arbitrary message with a wallet address's key (Bitcoin BIP-322 'simple', for proving address ownership — NOT a fund movement). 'ref' is a bech32 address or a 'wallet/branch/index' derivation ref; 'message' is the text to sign. Unlocking the key needs the keystore passphrase, which is supplied to the server out-of-band (never a tool argument). Returns the signing address and the base64 BIP-322 witness signature. Signs nothing on-chain and moves no funds."

// ── PSBT (BIP-174) ────────────────────────────────────────────────────────────

// descPSBTDecode is read-only inspection.
const descPSBTDecode = "Inspect a Partially-Signed Bitcoin Transaction (BIP-174): its inputs (outpoint, value, which are MINE, which are signed), outputs (address, value, which are mine/change), total fee, fee-rate, vsize, and whether it is complete (every input finalized). Pass the base64 'psbt'. Read-only — touches no keystore and signs nothing."

// descPSBTSign carries the policy-checked guarantee — it is the PSBT analog of
// send (it unlocks a key AND authorizes a spend via the policy reservation).
const descPSBTSign = "Sign this wallet's owned inputs of a PSBT (BIP-174). Detects owned inputs by script match (never a counterparty-supplied derivation), re-verifies their values against the backend, then POLICY-CHECKS the wallet's NET outflow (per-tx limit, rolling-24h limit, fee-rate cap, destination allowlist) BEFORE attaching any signature — a denied or over-limit sign produces NO signature. The keystore passphrase is supplied to the server out-of-band (never a tool argument). Returns the updated base64 'psbt' (NOT finalized — co-signers can still add signatures). This is policy-gated identically to send: an agent cannot raise its own limits through it."

// descPSBTBroadcast moves bytes onto the wire; its policy charge happened at sign.
const descPSBTBroadcast = "Finalize, extract, and BROADCAST a PSBT (BIP-174) onto the network. The spend was already policy-checked and reserved at sign time (this verb commits that reservation, cross-linked by txid — it does not re-charge the policy). Pass the base64 'psbt'; an incomplete PSBT (missing co-signer signatures) is a clean error. Waits for confirmation by default over MCP. Returns the broadcast txid and lifecycle status."

// descVerify is passphrase-free and pure (no keystore, no backend).
const descVerify = "Verify a Bitcoin BIP-322 'simple' message signature against an address (passphrase-free, no signing). 'address', 'message', and the base64 'signature' fully determine the result. A signature that decodes but does NOT match is NOT an error — it returns valid:false (branch on the field); only a malformed address or undecodable signature is an error. Read-only."

// descConvert is the pure sat<->BTC utility (no keystore, no backend, no policy).
const descConvert = "Convert a Bitcoin amount between satoshis and BTC, exactly (no floating point). 'amount' carries its unit as a suffix ('0.001btc', '150000sat') or is a bare BTC number; 'to' names the target unit (sat|sats|btc), or omit it to convert to the OTHER unit. Returns the canonical integer-sat value, the exact 8-dp BTC string, and the result in the requested unit. Pure utility — touches no wallet, no key, no backend."
