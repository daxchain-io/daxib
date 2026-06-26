// Package tools is the MCP tool surface of daxib's SECOND thin frontend
// (docs/PLAN.md §6.1/§6.2/§6.4). It is the executable proof of "guardrails apply
// identically to MCP-initiated signing": every tool handler is the same few lines
// around the same service call the CLI runs — bind the tool args into the SAME
// domain request struct the CLI binds, call the SAME service method, return the
// SAME result struct. There is ZERO business logic here, and there cannot be: the
// arch matrix denies this package the provider imports (policy/keys/backend/
// coinselect/journal/config/secret/policyseal/fsx) it would need to do anything a
// service method does not already do. mcpserver/tools imports service + domain + the
// MCP SDK + jsonschema-go ONLY.
//
// The tools are registered ONCE by Register, called from mcpserver.New(svc). Their
// input/output JSON schemas are INFERRED by jsonschema-go from the Go In/Out types —
// and the In type IS a domain request struct (the CLI binds the SAME struct), so
// CLI/MCP schema drift is impossible by construction (a golden test pins the inferred
// surface, §6.7). The agent-facing descriptions live in descriptions.go; the golden
// test pins those too.
//
// The deliberately-NOT-tools security boundary (§6.1) is REAL and complete: there is
// no handler — and no AddTool call — for any policy mutation, wallet create/import/
// export, backend mutation, keystore passphrase change, or network mutation. The
// boundary is enforced by ABSENCE (a prompt-injected agent cannot raise its own
// limits, exfiltrate a key, or repoint the backend through the tool channel) and
// recorded as a tested artifact: ToolNames lists exactly the present tools;
// ExcludedTools lists the operations that must never appear. server_test asserts the
// registered set equals ToolNames and is disjoint from ExcludedTools.
package tools

import (
	"github.com/daxchain-io/daxib/internal/service"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Register adds EXACTLY the §6.1 tools to srv, each bound to the same svc the CLI
// frontend uses. It is the ONE place every mcp.AddTool call lives (the handlers are
// grouped into pure.go/write.go/empty.go for readability, but the registration list
// — the agent-visible contract — is here). The order is the §6.1 table order so the
// list reads top-to-bottom like the design (the SDK lists tools sorted by name, so
// wire order is not load-bearing).
//
// Register touches no keystore and no network — building the server is safe for
// `daxib mcp tools` introspection. svc may be nil for pure schema-introspection
// callers (registration binds svc into the handler closures but does not invoke it).
func Register(srv *mcp.Server, svc *service.Service) {
	// ── read/list (no signing, no policy reservation) ───────────────────────────
	addReadPlain(srv, "balance", descBalance, svc.Balance)
	addReadPlain(srv, "utxo_list", descUTXOList, svc.UTXOList)
	addReadPlain(srv, "wallet_list", descWalletList, svc.WalletList)
	addReadPlain(srv, "wallet_show", descWalletShow, svc.WalletShow)
	addReadPlain(srv, "address_list", descAddressList, svc.AddressList)
	addReadPlain(srv, "fee", descFee, svc.Fee)

	// ── tx reads (status folds the journal; wait long-polls + dual-signals) ─────
	addTxStatus(srv, "tx_status", descTxStatus, svc.TxStatus)
	addTxWait(srv, "tx_wait", descTxWait, svc.WaitTx)
	addReadPlain(srv, "tx_list", descTxList, svc.ListTxs)

	// ── policy reads (the ONLY policy verbs on the surface; both READ-ONLY) ─────
	addPolicyShow(srv, "policy_show", descPolicyShow, svc.PolicyShow)
	addPolicyCheck(srv, "policy_check", descPolicyCheck, svc.PolicyCheck)

	// ── funds-moving / mutation (route through the SAME policy-bound methods) ───
	addSend(srv, "send", descSend, svc.SendTx)                        // the one money mover (§6.4 central guarantee)
	addAddressNew(srv, "address_new", descAddressNew, svc.AddressNew) // the receive affordance
}

// ToolNames is the canonical roster of the §6.1 tools, in table order. It is the
// tested artifact the count/exclusion test diffs against the actually-registered
// set: Register MUST register exactly these names, no more, no fewer.
var ToolNames = []string{
	"balance",      // 1  read
	"utxo_list",    // 2  read
	"wallet_list",  // 3  read
	"wallet_show",  // 4  read
	"address_list", // 5  read
	"fee",          // 6  read
	"tx_status",    // 7  read
	"tx_wait",      // 8  read (long-poll, dual-signal timeout)
	"tx_list",      // 9  read
	"policy_show",  // 10 read-only
	"policy_check", // 11 read-only (dry-run)
	"send",         // 12 SIGN (the one money mover)
	"address_new",  // 13 mutation (derive next receive address; no signing)
}

// SigningTools is the canonical set of the tools that move funds — the one money
// mover. send routes through the SAME svc.SendTx that holds the only path to the
// keystore signer, with policy.Reserve INSIDE it (§6.4) — so MCP is policy-gated
// identically to the CLI. address_new derives an address but never signs, so it is
// NOT in this set.
var SigningTools = []string{
	"send",
}

// ExcludedTools is the recorded, non-regressable deliberately-NOT-tools boundary
// (§6.1): a representative denylist of operation names that MUST NEVER be registered
// as MCP tools in v1. The boundary is enforced by ABSENCE — there is no handler for
// any of these — and this list makes the boundary a TESTED artifact: server_test
// asserts the registered tool set is DISJOINT from this set, so a future edit that
// adds (say) a wallet_export tool fails the build.
//
// The one sentence (§6.1): the MCP surface can move funds WITHIN policy and read
// everything, but it cannot change who holds the keys, change what the keys may do,
// export a key, or repoint the backend. Every name below is one of those forbidden
// capabilities. policy_show / policy_check (read-only) ARE exposed — they are NOT in
// this list.
var ExcludedTools = []string{
	// All policy MUTATIONS — admin-passphrase-gated, the agent never holds it.
	"policy_set",
	"policy_allow",
	"policy_deny",
	"policy_reset",
	"policy_verify",                  // a read, but exposed only on the CLI (canary is operator tooling)
	"policy_change_admin_passphrase", //nolint:gosec // G101: a tool-name string, not a credential
	"policy_pin",
	"policy_counters",
	// Wallet/key CREATE, IMPORT, EXPORT — secret-emitting / attacker-key-planting /
	// key-exfiltration ops. No mnemonic or seed crosses the tool channel, ever, in v1.
	"wallet_create",
	"wallet_import",
	"wallet_export",
	// Backend MUTATIONS — repointing the node is an operator act (a malicious backend
	// could feed forged balances/UTXOs to a compromised agent).
	"backend_add",
	"backend_use",
	"backend_remove",
	"backend_test",
	// Keystore passphrase rotation — administration is CLI-only.
	"keystore_change_passphrase", //nolint:gosec // G101: a tool-name string, not a credential
	// Network mutation — the active network is a launch-time choice, not a tool.
	"network_add",
	"network_use",
	"network_remove",
	// Self-referential / shell-only.
	"mcp_serve",
	"mcp_tools",
	"version",
	"completion",
	"config",
}
