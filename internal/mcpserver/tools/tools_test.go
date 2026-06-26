package tools

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// tools_test.go pins the §6.2 schema-inference contract from the tools package itself:
// every tool's INPUT schema is inferred from a domain request struct, so the schema
// validates exactly the JSON the CLI marshals from the SAME struct — CLI/MCP drift is
// structurally impossible. It drives Register directly (Register(srv, svc)) so the
// tools package is exercised in isolation. No live service is dialed: tools/list and
// schema resolution are purely type-driven.

// buildToolSchemas registers all tools onto a fresh server, lists them via an in-memory
// client, and returns name → inferred input schema (as the client receives it).
func buildToolSchemas(t *testing.T) map[string]*jsonschema.Schema {
	t.Helper()
	ctx := context.Background()

	srv := mcp.NewServer(&mcp.Implementation{Name: "tools-test", Version: "0.0.0"}, nil)
	Register(srv, nil) // type-driven registration; no handler runs during tools/list

	clientT, serverT := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, serverT, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "tools-test-client", Version: "0.0.0"}, nil)
	cs, err := client.Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	out := make(map[string]*jsonschema.Schema, len(res.Tools))
	for _, tl := range res.Tools {
		raw, err := json.Marshal(tl.InputSchema)
		if err != nil {
			t.Fatalf("%s: marshal input schema: %v", tl.Name, err)
		}
		var sch jsonschema.Schema
		if err := json.Unmarshal(raw, &sch); err != nil {
			t.Fatalf("%s: input schema is not a JSON schema: %v", tl.Name, err)
		}
		out[tl.Name] = &sch
	}
	return out
}

// validateAgainst resolves the named tool's input schema and validates the JSON that
// marshaling the given populated domain request struct produces — proving the inferred
// schema accepts exactly the CLI's wire shape for that struct (§6.2).
func validateAgainst(t *testing.T, schemas map[string]*jsonschema.Schema, tool string, req any) {
	t.Helper()
	sch, ok := schemas[tool]
	if !ok {
		t.Fatalf("tool %q not registered", tool)
	}
	resolved, err := sch.Resolve(nil)
	if err != nil {
		t.Fatalf("%s: resolve schema: %v", tool, err)
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("%s: marshal request: %v", tool, err)
	}
	var instance any
	if err := json.Unmarshal(b, &instance); err != nil {
		t.Fatalf("%s: unmarshal request: %v", tool, err)
	}
	if err := resolved.Validate(instance); err != nil {
		t.Errorf("%s: the inferred input schema REJECTED the JSON the CLI marshals from %T:\n  json: %s\n  err: %v\nThis means the MCP schema drifted from the domain struct the CLI binds (§6.2).", tool, req, b, err)
	}
}

// TestInputSchemasAcceptCLIWire is the schema↔marshaling contract for the parity-
// critical tools: a populated domain request struct (exactly what the CLI builds from
// flags) marshals to JSON the inferred MCP input schema accepts. Covers the money mover
// (send/SendRequest, INCLUDING the wait Duration), the long-poll (tx_wait/WaitRequest
// with a Duration timeout), and reads (balance, tx_status, policy_check).
//
// The confirmation flag (SendRequest.Yes) carries json:"-", so the marshaled JSON never
// carries it and the schema never declares it — exactly the design contract (§6.2). The
// `wait` field is validated in full: the value-type schema correction
// (mcpserver/tools/schema.go) types domain.Duration as the string it marshals to, so the
// wait-bearing tools' `wait.timeout` schema matches the CLI's wire form.
func TestInputSchemasAcceptCLIWire(t *testing.T) {
	schemas := buildToolSchemas(t)

	// The send tool: validate every field INCLUDING the `wait` Duration, which the
	// value-type correction now types as a string matching the CLI wire form. Yes is
	// json:"-" (never marshaled), so it neither appears in the JSON nor needs the schema.
	validateAgainst(t, schemas, "send", domain.SendRequest{
		Wallet: "treasury", To: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
		Amount: "0.5", FeeRate: "10", Yes: true,
		Wait: domain.WaitOpts{Enabled: true, Timeout: domain.Duration{D: 5 * time.Minute}},
	})
	// The minimal `send` an agent should be able to call: ONLY to + amount.
	validateAgainst(t, schemas, "send", domain.SendRequest{
		To: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", Amount: "0.01",
	})
	// tx_wait carries the Duration timeout end-to-end.
	confs := int64(3)
	validateAgainst(t, schemas, "tx_wait", domain.WaitRequest{
		Txid: "abc", Confirmations: &confs, Timeout: domain.Duration{D: 30 * time.Minute},
	})

	// Reads: full struct validation.
	validateAgainst(t, schemas, "balance", domain.BalanceRequest{Wallet: "treasury", UTXOs: true})
	validateAgainst(t, schemas, "tx_status", domain.TxStatusRequest{Txid: "abc"})
	validateAgainst(t, schemas, "tx_list", domain.TxListRequest{Wallet: "treasury", Limit: 10})
	validateAgainst(t, schemas, "address_new", domain.AddressNewRequest{Wallet: "treasury"})
	validateAgainst(t, schemas, "policy_check", PolicyCheckArgs{
		To: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", Amount: "0.01", FeeRate: 10,
	})
}

// TestWaitTimeoutSchemaIsString is the regression guard for the domain.Duration schema:
// Duration is a struct {D time.Duration} whose MarshalJSON emits a STRING ("5m0s") — so
// the wire form an agent must send is a string. The MCP SDK's bare inference would type
// it as an OBJECT, which would make `wait.timeout` uncallable. The value-type correction
// (mcpserver/tools/schema.go) maps domain.Duration to {type:"string"}; this pins it.
func TestWaitTimeoutSchemaIsString(t *testing.T) {
	schemas := buildToolSchemas(t)

	// send.wait.timeout
	send := schemas["send"]
	wait := send.Properties["wait"]
	if wait == nil {
		t.Fatal("send has no `wait` property; the schema shape changed unexpectedly")
	}
	timeout := wait.Properties["timeout"]
	if timeout == nil {
		t.Fatal("send.wait has no `timeout` property; the schema shape changed unexpectedly")
	}
	if timeout.Type != "string" {
		t.Errorf("send.wait.timeout schema type = %q, want \"string\" — the domain.Duration value-type "+
			"correction in internal/mcpserver/tools/schema.go is missing or broken.", timeout.Type)
	}

	// tx_wait.timeout (a top-level Duration field).
	wt := schemas["tx_wait"].Properties["timeout"]
	if wt == nil {
		t.Fatal("tx_wait has no `timeout` property")
	}
	if wt.Type != "string" {
		t.Errorf("tx_wait.timeout schema type = %q, want \"string\"", wt.Type)
	}
}

// TestEverySchemaResolves is a smoke check that EVERY registered tool's inferred input
// schema is a valid, resolvable JSON schema (so the SDK can validate calls and
// `daxib mcp tools` can render it).
func TestEverySchemaResolves(t *testing.T) {
	schemas := buildToolSchemas(t)
	if len(schemas) != len(ToolNames) {
		t.Fatalf("Register produced %d tool schemas, want %d (§6.1)", len(schemas), len(ToolNames))
	}
	for name, sch := range schemas {
		if _, err := sch.Resolve(nil); err != nil {
			t.Errorf("tool %q: inferred input schema does not resolve: %v", name, err)
		}
	}
}

// TestConfirmFieldNeverOnSchema pins the §6.2/§6.4 contract that the confirmation flag
// is INVISIBLE over MCP: SendRequest.Yes carries json:"-", so the SDK never infers it
// into the schema (the --yes confirmation is wired constant-true server-side by
// sendCeremony). The send tool's input schema must carry neither `yes` nor `confirm`.
func TestConfirmFieldNeverOnSchema(t *testing.T) {
	schemas := buildToolSchemas(t)
	sch := schemas["send"]
	if sch == nil {
		t.Fatal("send tool not registered")
	}
	for _, leaked := range []string{"confirm", "yes", "Yes"} {
		if _, ok := sch.Properties[leaked]; ok {
			t.Errorf("send: schema exposes %q — the confirmation flag is a CLI-interaction concern (json:\"-\") and must NEVER reach the MCP surface (§6.2/§6.4)", leaked)
		}
		for _, r := range sch.Required {
			if r == leaked {
				t.Errorf("send: schema marks %q REQUIRED — an agent must not be forced to pass a server-overwritten confirmation flag", leaked)
			}
		}
	}
}

// TestSendRequiresOnlyToAndAmount pins the send required set: an agent must supply a
// recipient and an amount, and NOTHING else (wallet/fee_rate/speed/dry_run/wait are all
// optional). A required `yes`/`confirm` would be the regression this guards.
func TestSendRequiresOnlyToAndAmount(t *testing.T) {
	schemas := buildToolSchemas(t)
	sch := schemas["send"]
	if sch == nil {
		t.Fatal("send tool not registered")
	}
	got := map[string]bool{}
	for _, r := range sch.Required {
		got[r] = true
	}
	want := map[string]bool{"to": true, "amount": true}
	if len(got) != len(want) {
		t.Errorf("send required set = %v, want exactly [amount to]", sch.Required)
	}
	for k := range want {
		if !got[k] {
			t.Errorf("send must require %q", k)
		}
	}
}
