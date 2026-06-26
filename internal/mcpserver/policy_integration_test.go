package mcpserver_test

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/wire"

	"github.com/daxchain-io/daxib/internal/backend"
	fakebackend "github.com/daxchain-io/daxib/internal/backend/fake"
	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/mcpserver"
	"github.com/daxchain-io/daxib/internal/service"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// policy_integration_test.go is THE central M6 guarantee made executable: it drives a
// `send` through the OTHER frontend (the MCP server, over an in-memory MCP pipe the
// way `daxib mcp serve` serves over stdio) against the SAME *service.Service the CLI
// drives, and proves guardrails bind MCP IDENTICALLY (docs/PLAN.md §6.4):
//
//   - a within-limit `send` over MCP broadcasts (the money mover works over MCP);
//   - an over-limit `send` over MCP returns the SAME policy.denied.* tool-error the
//     CLI gets (exit-3 family), with NOTHING signed or broadcast;
//   - a `balance` read round-trips a structured result.
//
// The policy is sealed BEFORE the server builds, so the running server loads it on the
// SAME authorize path the CLI shares — mcpserver cannot import policy/keys, so it has
// no way to skip the check. This test lives in package mcpserver_test (an external test
// package) so it can legally import service + the fake backend like any client would.

// canonical test vectors (mirroring internal/service test scaffolding).
const (
	canonicalMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	canonicalReceive0 = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
	vectorRecipient   = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
)

// newMCPTestService builds a real service over a fake backend with the admin + keystore
// passphrase env wired so the test can seal a policy and sign. It imports the canonical
// wallet and selects the fake backend — exactly the wiring the service policy tests use,
// reproduced here so the MCP frontend can drive it.
func newMCPTestService(t *testing.T, fake *fakebackend.Client) (*service.Service, func()) {
	t.Helper()
	keystoreDir := t.TempDir()
	configDir := t.TempDir()
	stateDir := t.TempDir()
	env := map[string]string{
		"DAXIB_KEYSTORE":           keystoreDir,
		"DAXIB_KDF_LIGHT":          "1",
		"DAXIB_PASSPHRASE":         "test-pass-12345678",
		"DAXIB_PASSPHRASE_CONFIRM": "test-pass-12345678",
		"DAXIB_ADMIN_PASSPHRASE":   "admin-secret-xyz",
	}
	svc, err := service.Open(context.Background(), service.Options{
		Keystore: keystoreDir,
		Config:   configDir,
		State:    stateDir,
		Network:  "mainnet",
		KDFLight: true,
		Dial: func(_ context.Context, _ backend.Options) (backend.Client, error) {
			return fake, nil
		},
		Secret: service.SecretIO{
			Stdin:     strings.NewReader(canonicalMnemonic),
			LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok },
			IsTTY:     func() bool { return false },
			Prompt:    func(string) ([]byte, error) { return nil, context.Canceled },
		},
	})
	if err != nil {
		t.Fatalf("service.Open: %v", err)
	}
	if _, _, err := svc.BackendAdd(context.Background(), domain.BackendAddRequest{
		Name: "fake-x", Network: "mainnet", Type: domain.BackendEsplora, URL: "http://fake",
	}); err != nil {
		t.Fatalf("BackendAdd: %v", err)
	}
	if _, err := svc.BackendUse(context.Background(), domain.BackendUseRequest{Name: "fake-x"}); err != nil {
		t.Fatalf("BackendUse: %v", err)
	}
	if _, err := svc.WalletImport(context.Background(),
		domain.WalletImportRequest{Name: "vec", Network: "mainnet"},
		service.WalletImportInput{MnemonicStdin: true}); err != nil {
		t.Fatalf("WalletImport: %v", err)
	}
	return svc, func() { _ = svc.Close() }
}

// programUTXO seeds a confirmed UTXO on the fake for an address.
func programUTXO(fake *fakebackend.Client, addr, txid string, vout uint32, value int64) {
	fake.UTXOsByAddr[addr] = append(fake.UTXOsByAddr[addr], domain.UTXO{
		Txid: txid, Vout: vout, Address: addr, ValueSat: value, Height: 800000, Confirmations: 6,
	})
}

// countingBroadcast records whether Broadcast was ever called and returns a real txid.
func countingBroadcast(fake *fakebackend.Client, calls *int) {
	var mu sync.Mutex
	fake.BroadcastFn = func(_ context.Context, raw []byte) (string, error) {
		mu.Lock()
		*calls++
		mu.Unlock()
		tx := wire.NewMsgTx(2)
		if err := tx.Deserialize(strings.NewReader(string(raw))); err != nil {
			return "", err
		}
		return tx.TxHash().String(), nil
	}
}

// mcpSession connects an in-memory MCP client to a server built over svc — the SAME
// assembly `daxib mcp serve` uses (mcpserver.New), driving real tools/call requests
// with no OS process.
func mcpSession(t *testing.T, svc *service.Service) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	srv := mcpserver.New(svc)
	clientT, serverT := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, serverT, nil); err != nil {
		t.Fatalf("mcp server connect: %v", err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "policy-integration", Version: "0.0.0"}, nil)
	cs, err := client.Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("mcp client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// callTool issues a tools/call and returns the result. A transport/protocol fault —
// including a tool-output schema-validation failure — is a FATAL test error (the
// value-returning tools carry domain.Duration / map[int]int64, which schema.go types as
// their wire form so the SDK validates a real result rather than rejecting it). A
// tool-level outcome (IsError + content, e.g. a policy denial) is returned for
// inspection.
func callTool(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool %s: protocol error: %v", name, err)
	}
	return res
}

// toolErrorText concatenates a result's text content (where the SDK packs a tool
// error's domain.Error JSON envelope — byte-identical to the CLI --json error).
func toolErrorText(res *mcp.CallToolResult) string {
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}

// TestMCP_Balance_RoundTrip is the cheapest live round-trip: a `balance` read over MCP
// returns a structured result the agent can decode (no signing, no policy).
func TestMCP_Balance_RoundTrip(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	svc, done := newMCPTestService(t, fake)
	defer done()
	programUTXO(fake, canonicalReceive0, "11"+strings.Repeat("0", 62), 0, 150000)

	cs := mcpSession(t, svc)
	res := callTool(t, cs, "balance", map[string]any{"wallet": "vec"})
	if res.IsError {
		t.Fatalf("balance over MCP errored: %s", toolErrorText(res))
	}
	var out domain.BalanceResult
	mustDecode(t, res, &out)
	if out.ConfirmedSat != 150000 {
		t.Errorf("balance confirmed = %d sat, want 150000", out.ConfirmedSat)
	}
	if out.Wallet != "vec" {
		t.Errorf("balance wallet = %q, want vec", out.Wallet)
	}
}

// TestMCP_PolicyDeniesSend_NothingSigned is THE central guarantee (§6.4): with a sealed
// policy that DENIES the send (a per-tx cap below the amount), the SAME `send` over MCP
// returns the SAME policy.denied.* tool-error the CLI gets (exit-3 family), and NOTHING
// is broadcast. The exit code carried in the envelope IS the CLI's exit-3
// (ExitPolicyDenied) — guardrails bind MCP byte-identically.
func TestMCP_PolicyDeniesSend_NothingSigned(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	var broadcasts int
	countingBroadcast(fake, &broadcasts)

	svc, done := newMCPTestService(t, fake)
	defer done()

	// Seal a restrictive policy via the admin path (the agent never holds this).
	if _, err := svc.PolicySet(context.Background(), service.PolicySetInput{
		MaxTxSat: "100000", AllowlistOn: boolPtr(false),
	}); err != nil {
		t.Fatalf("PolicySet: %v", err)
	}
	programUTXO(fake, canonicalReceive0, "11"+strings.Repeat("0", 62), 0, 1_000_000)

	cs := mcpSession(t, svc)
	// Send 0.005 BTC (500_000 sat) — over the 100_000 cap. NO `yes`/`confirm` field:
	// the confirmation is invisible over MCP (json:"-", wired constant-true by
	// sendCeremony). The schema is additionalProperties:false, so passing it would be
	// rejected.
	res := callTool(t, cs, "send", map[string]any{
		"wallet":   "vec",
		"to":       vectorRecipient,
		"amount":   "0.005",
		"fee_rate": "10",
	})
	if !res.IsError {
		t.Fatalf("send over MCP was NOT denied by a sealed policy (guardrails must bind MCP identically, §6.4)")
	}

	env := toolErrorText(res)
	if !strings.Contains(env, "policy.denied") {
		t.Errorf("MCP send denial code is not policy.denied.*: %s", env)
	}
	// The envelope is byte-identical to the CLI --json error: decode it and assert the
	// exit code IS the CLI's exit-3 family.
	var envelope struct {
		Error domain.Error `json:"error"`
	}
	if err := json.Unmarshal([]byte(env), &envelope); err != nil {
		t.Fatalf("tool-error envelope is not the domain.Error JSON the CLI emits: %v\n%s", err, env)
	}
	if envelope.Error.Exit != domain.ExitPolicyDenied {
		t.Errorf("MCP send denial exit = %d, want %d (the SAME exit-3 the CLI maps policy.denied.* to)", envelope.Error.Exit, domain.ExitPolicyDenied)
	}

	// NOTHING was broadcast — the denial happened before signing.
	if broadcasts != 0 {
		t.Fatalf("a policy-denied MCP send must NOT broadcast; got %d broadcast calls", broadcasts)
	}
}

// TestMCP_PolicyAllowsSend_Broadcasts is the positive control: with a generous policy,
// the SAME `send` over MCP coin-selects, passes policy.Reserve, signs, and broadcasts —
// the money mover works end-to-end over Frontend 2.
func TestMCP_PolicyAllowsSend_Broadcasts(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	var broadcasts int
	countingBroadcast(fake, &broadcasts)

	svc, done := newMCPTestService(t, fake)
	defer done()

	if _, err := svc.PolicySet(context.Background(), service.PolicySetInput{
		MaxTxSat: "100000000", MaxDaySat: "100000000", AllowlistOn: boolPtr(false),
	}); err != nil {
		t.Fatalf("PolicySet: %v", err)
	}
	programUTXO(fake, canonicalReceive0, "11"+strings.Repeat("0", 62), 0, 1_000_000)
	// Over MCP the send WAITS for confirmation by default (sendCeremony sets
	// Wait.Enabled). Make the fake confirm instantly so the implicit wait completes
	// without polling the 30-minute default deadline.
	fake.TxStatusFn = func(_ context.Context, txid string) (domain.TxStatus, error) {
		return domain.TxStatus{Txid: txid, Confirmed: true, Confirmations: 1, BlockHeight: 800001}, nil
	}

	cs := mcpSession(t, svc)
	// A short explicit timeout bounds the call even if the confirm hook regresses.
	res := callTool(t, cs, "send", map[string]any{
		"wallet":   "vec",
		"to":       vectorRecipient,
		"amount":   "0.005",
		"fee_rate": "10",
		"wait":     map[string]any{"timeout": "10s"},
	})
	if res.IsError {
		t.Fatalf("within-limit send over MCP errored: %s", toolErrorText(res))
	}
	var out domain.TxResult
	mustDecode(t, res, &out)
	if out.Txid == "" {
		t.Fatal("a broadcast send carries no txid")
	}
	switch out.Status {
	case domain.TxStateBroadcast, domain.TxStateConfirmed, domain.TxStatePending:
		// any live status is acceptable; the point is it broadcast
	default:
		t.Errorf("send status = %q, want a live (broadcast/pending/confirmed) status", out.Status)
	}
	if broadcasts != 1 {
		t.Fatalf("within-limit MCP send should broadcast exactly once; got %d", broadcasts)
	}
}

// mustDecode decodes a successful tool result's structured content into out.
func mustDecode(t *testing.T, res *mcp.CallToolResult, out any) {
	t.Helper()
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatalf("decode structured content into %T: %v (%s)", out, err, b)
	}
}

func boolPtr(b bool) *bool { return &b }
