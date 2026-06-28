package domain

// Principal is the WHO behind a call — the attribution that becomes the journal
// Source. It is the "Principal seam" (issue #11): threaded immediately after ctx
// on every exported service method so the planned HTTP daemon (issue #12,
// transport_http.go) can fill it from a bearer token as a value change, not a
// refactor. In v1 the CLI frontend sets {Kind:"local", Label:"cli"} and the MCP
// frontend sets Label:"mcp". The core never invents a Principal — the frontend
// supplies it (there is no ID field in v1; daxib parity with daxie).
type Principal struct {
	Kind  string `json:"kind"`  // "local" in v1
	Label string `json:"label"` // "cli" | "mcp" — journal Source attribution
}

// LocalCLI is the Principal the Cobra (CLI) frontend uses for every command.
func LocalCLI() Principal { return Principal{Kind: "local", Label: "cli"} }

// LocalMCP is the Principal the MCP frontend uses for every tool call. With it,
// an MCP-initiated send/sign is attributed Source:"mcp" in the audit journal
// (not the old hardcoded "cli").
func LocalMCP() Principal { return Principal{Kind: "local", Label: "mcp"} }
