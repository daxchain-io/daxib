// Package mcpserver is Frontend 2: the built-in MCP server. Like the CLI it is a
// THIN host that imports service + domain (+ version) ONLY and therefore
// physically CANNOT contain business logic — every tool routes through the SAME
// svc.* method the CLI calls, the only path to the signing chokepoint, with the
// policy/seal/allowlist checks INSIDE it (docs/PLAN.md §1, §6). A prompt-injected
// agent cannot raise its own limits, export a key, or skip a policy check through
// the tool channel.
//
// M1 is the compiling skeleton: this package is an empty-but-real placeholder so
// the one-core/two-frontends import lattice (internal/arch_test.go) has a second
// frontend to bind and enforce the "cli and mcpserver must not import each other"
// rule against. The transport-agnostic Server, the narrowed tool surface, and the
// "what is NOT a tool" exclusion list land in a later milestone (docs/PLAN.md §8).
package mcpserver
