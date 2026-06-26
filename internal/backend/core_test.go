package backend

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/daxchain-io/daxib/internal/domain"
)

// secondsTimeout is the short per-request timeout the adapter tests use so an
// unreachable-endpoint test fails fast instead of waiting the 30s default.
const secondsTimeout = 2 * time.Second

// coreRPC is a minimal httptest JSON-RPC node speaking the bitcoind dialect: it
// dispatches on the method and answers with a recorded result (or a JSON-RPC error
// object). It records Basic-auth so auth attachment can be asserted.
type coreRPC struct {
	*httptest.Server
	results map[string]any // method -> result
	rpcErr  map[string]string
	gotUser string
	gotPass string
}

func newCoreRPC(t *testing.T, results map[string]any) *coreRPC {
	t.Helper()
	m := &coreRPC{results: results, rpcErr: map[string]string{}}
	m.Server = httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.Close)
	return m
}

func (m *coreRPC) handle(w http.ResponseWriter, r *http.Request) {
	if u, p, ok := r.BasicAuth(); ok {
		m.gotUser, m.gotPass = u, p
	}
	body, _ := io.ReadAll(r.Body)
	var req jsonRPCReq
	_ = json.Unmarshal(body, &req)

	w.Header().Set("Content-Type", "application/json")
	if msg, bad := m.rpcErr[req.Method]; bad {
		_ = json.NewEncoder(w).Encode(jsonRPCResp{Error: &jsonRPCError{Code: -1, Message: msg}})
		return
	}
	res, ok := m.results[req.Method]
	if !ok {
		_ = json.NewEncoder(w).Encode(jsonRPCResp{Error: &jsonRPCError{Code: -32601, Message: "method not found: " + req.Method}})
		return
	}
	raw, _ := json.Marshal(res)
	_ = json.NewEncoder(w).Encode(jsonRPCResp{Result: raw})
}

func dialCore(t *testing.T, node *coreRPC, o Options) Client {
	t.Helper()
	o.Type = domain.BackendCore
	o.URL = node.URL
	o.Network = domain.NetworkMainnet
	return newCoreClient(o, node.Client())
}

// TestCore_TipHeight proves getblockcount.
func TestCore_TipHeight(t *testing.T) {
	node := newCoreRPC(t, map[string]any{"getblockcount": 800000})
	c := dialCore(t, node, Options{})
	h, err := c.TipHeight(context.Background())
	if err != nil {
		t.Fatalf("TipHeight: %v", err)
	}
	if h != 800000 {
		t.Fatalf("TipHeight = %d, want 800000", h)
	}
}

// TestCore_UTXOs proves scantxoutset mapping: the exact (no-float) BTC->sat
// conversion, the confirming Height, and the tip-relative confirmations from the
// scan's reported height.
func TestCore_UTXOs(t *testing.T) {
	const addr = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
	scan := map[string]any{
		"success": true,
		"height":  800000,
		"unspents": []map[string]any{
			{"txid": "aa", "vout": 0, "amount": 0.00150000, "height": 799991, "desc": "addr(" + addr + ")#abcdefgh"},
		},
	}
	node := newCoreRPC(t, map[string]any{"scantxoutset": scan})
	c := dialCore(t, node, Options{})

	utxos, err := c.UTXOs(context.Background(), []string{addr})
	if err != nil {
		t.Fatalf("UTXOs: %v", err)
	}
	if len(utxos) != 1 {
		t.Fatalf("got %d UTXOs, want 1", len(utxos))
	}
	u := utxos[0]
	if u.ValueSat != 150000 {
		t.Errorf("ValueSat = %d, want 150000 (exact BTC->sat)", u.ValueSat)
	}
	if u.Address != addr {
		t.Errorf("Address = %q (from desc), want %q", u.Address, addr)
	}
	if u.Confirmations != 10 { // 800000 - 799991 + 1
		t.Errorf("Confirmations = %d, want 10", u.Confirmations)
	}
}

// TestCore_FeeEstimates proves estimatesmartfee BTC/kvB -> sat/vB folding.
func TestCore_FeeEstimates(t *testing.T) {
	node := newCoreRPC(t, map[string]any{
		"estimatesmartfee": map[string]any{"feerate": 0.00010000}, // 0.0001 BTC/kvB = 10 sat/vB
	})
	c := dialCore(t, node, Options{})
	est, err := c.FeeEstimates(context.Background())
	if err != nil {
		t.Fatalf("FeeEstimates: %v", err)
	}
	if est.Fast != 10 || est.Normal != 10 || est.Slow != 10 {
		t.Fatalf("fees = %+v, want all 10 sat/vB", est)
	}
}

// TestCore_Broadcast proves sendrawtransaction returns the txid.
func TestCore_Broadcast(t *testing.T) {
	node := newCoreRPC(t, map[string]any{"sendrawtransaction": "d34db33f"})
	c := dialCore(t, node, Options{})
	txid, err := c.Broadcast(context.Background(), []byte{0x00, 0xff})
	if err != nil {
		t.Fatalf("Broadcast: %v", err)
	}
	if txid != "d34db33f" {
		t.Fatalf("txid = %q, want d34db33f", txid)
	}
}

// TestCore_RPCError proves a JSON-RPC error object maps to backend.rpc_error.
func TestCore_RPCError(t *testing.T) {
	node := newCoreRPC(t, map[string]any{})
	node.rpcErr["getblockcount"] = "node is warming up"
	c := dialCore(t, node, Options{})
	_, err := c.TipHeight(context.Background())
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != domain.CodeBackendRPCError {
		t.Fatalf("err = %v, want backend.rpc_error", err)
	}
}

// TestCore_AuthAttaches proves rpcuser/rpcpassword reach the node as Basic auth.
func TestCore_AuthAttaches(t *testing.T) {
	node := newCoreRPC(t, map[string]any{"getblockcount": 1})
	c := dialCore(t, node, Options{RPCUser: "alice", RPCPassword: "s3cret"})
	if _, err := c.TipHeight(context.Background()); err != nil {
		t.Fatalf("TipHeight: %v", err)
	}
	if node.gotUser != "alice" || node.gotPass != "s3cret" {
		t.Fatalf("auth = %q:%q, want alice:s3cret", node.gotUser, node.gotPass)
	}
}

// TestCore_DialProbe proves Dial runs a TipHeight reachability probe and returns
// a usable client on success.
func TestCore_DialProbe(t *testing.T) {
	node := newCoreRPC(t, map[string]any{"getblockcount": 42})
	c, err := Dial(context.Background(), Options{Type: domain.BackendCore, URL: node.URL, Network: domain.NetworkMainnet, Timeout: secondsTimeout})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()
	h, _ := c.TipHeight(context.Background())
	if h != 42 {
		t.Fatalf("post-Dial TipHeight = %d, want 42", h)
	}
}
