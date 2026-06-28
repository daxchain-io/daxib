package domain

import "testing"

// TestLocalCLI pins the CLI Principal: {local, cli} — the attribution that becomes
// journal Source "cli".
func TestLocalCLI(t *testing.T) {
	p := LocalCLI()
	if p.Kind != "local" || p.Label != "cli" {
		t.Fatalf("LocalCLI() = %+v, want {Kind:local Label:cli}", p)
	}
}

// TestLocalMCP pins the MCP Principal: {local, mcp} — the attribution that becomes
// journal Source "mcp" (the heart of the Phase A bug fix).
func TestLocalMCP(t *testing.T) {
	p := LocalMCP()
	if p.Kind != "local" || p.Label != "mcp" {
		t.Fatalf("LocalMCP() = %+v, want {Kind:local Label:mcp}", p)
	}
}
