package backend

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/daxchain-io/daxib/internal/domain"
)

// newEsploraServer stands up an httptest Esplora REST server with recorded
// fixtures for the M3 endpoints, returning the server and a backend.Client dialed
// at it (without the Dial reachability probe, so each method can be exercised in
// isolation).
func newEsploraServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, Client) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c := newEsploraClient(Options{Type: domain.BackendEsplora, URL: srv.URL, Network: domain.NetworkMainnet}, srv.Client())
	return srv, c
}

// TestEsplora_TipHeight proves the plain-text tip-height parse.
func TestEsplora_TipHeight(t *testing.T) {
	_, c := newEsploraServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/blocks/tip/height" {
			_, _ = io.WriteString(w, "800000\n")
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	})
	h, err := c.TipHeight(context.Background())
	if err != nil {
		t.Fatalf("TipHeight: %v", err)
	}
	if h != 800000 {
		t.Fatalf("TipHeight = %d, want 800000", h)
	}
}

// TestEsplora_UTXOs proves the confirmed/unconfirmed mapping and the
// tip-relative confirmation math against recorded /address/:addr/utxo JSON.
func TestEsplora_UTXOs(t *testing.T) {
	const addr = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
	const confirmedJSON = `[{"txid":"aa","vout":0,"value":150000,"status":{"confirmed":true,"block_height":799991}},
	    {"txid":"bb","vout":1,"value":5000,"status":{"confirmed":false}}]`

	_, c := newEsploraServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/blocks/tip/height":
			_, _ = io.WriteString(w, "800000")
		case "/address/" + addr + "/utxo":
			_, _ = io.WriteString(w, confirmedJSON)
		default:
			_, _ = io.WriteString(w, "[]")
		}
	})

	utxos, err := c.UTXOs(context.Background(), []string{addr})
	if err != nil {
		t.Fatalf("UTXOs: %v", err)
	}
	if len(utxos) != 2 {
		t.Fatalf("got %d UTXOs, want 2", len(utxos))
	}
	var conf, unconf int64
	for _, u := range utxos {
		if u.Address != addr {
			t.Errorf("UTXO address = %q, want %q", u.Address, addr)
		}
		if u.Confirmations > 0 {
			conf += u.ValueSat
			if u.Height != 799991 {
				t.Errorf("confirmed Height = %d, want 799991", u.Height)
			}
			if u.Confirmations != 10 { // 800000 - 799991 + 1
				t.Errorf("Confirmations = %d, want 10", u.Confirmations)
			}
		} else {
			unconf += u.ValueSat
			if u.Height != 0 {
				t.Errorf("unconfirmed Height = %d, want 0", u.Height)
			}
		}
	}
	if conf != 150000 {
		t.Errorf("confirmed total = %d, want 150000", conf)
	}
	if unconf != 5000 {
		t.Errorf("unconfirmed total = %d, want 5000", unconf)
	}
}

// TestEsplora_FeeEstimates proves the sat/vB rounding-up of the float fee table.
func TestEsplora_FeeEstimates(t *testing.T) {
	_, c := newEsploraServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fee-estimates" {
			_, _ = io.WriteString(w, `{"1":12.3,"3":6.0,"6":1.1}`)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	})
	est, err := c.FeeEstimates(context.Background())
	if err != nil {
		t.Fatalf("FeeEstimates: %v", err)
	}
	if est.Fast != 13 { // ceil(12.3)
		t.Errorf("Fast = %d, want 13", est.Fast)
	}
	if est.Normal != 6 {
		t.Errorf("Normal = %d, want 6", est.Normal)
	}
	if est.Slow != 2 { // ceil(1.1)
		t.Errorf("Slow = %d, want 2", est.Slow)
	}
}

// TestEsplora_Broadcast proves the POST /tx path echoes the txid.
func TestEsplora_Broadcast(t *testing.T) {
	const txid = " d34db33f"
	_, c := newEsploraServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/tx" {
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), "00ff") {
				http.Error(w, "bad body", http.StatusBadRequest)
				return
			}
			_, _ = io.WriteString(w, strings.TrimSpace(txid))
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	})
	got, err := c.Broadcast(context.Background(), []byte{0x00, 0xff})
	if err != nil {
		t.Fatalf("Broadcast: %v", err)
	}
	if got != strings.TrimSpace(txid) {
		t.Fatalf("Broadcast txid = %q, want %q", got, strings.TrimSpace(txid))
	}
}

// TestEsplora_TxStatus proves the /tx/:txid confirmation mapping.
func TestEsplora_TxStatus(t *testing.T) {
	_, c := newEsploraServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/blocks/tip/height":
			_, _ = io.WriteString(w, "800000")
		case "/tx/aa":
			_, _ = io.WriteString(w, `{"status":{"confirmed":true,"block_height":799995}}`)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	})
	st, err := c.TxStatus(context.Background(), "aa")
	if err != nil {
		t.Fatalf("TxStatus: %v", err)
	}
	if !st.Confirmed || st.Confirmations != 6 { // 800000 - 799995 + 1
		t.Fatalf("TxStatus = %+v, want confirmed with 6 confirmations", st)
	}
}

// TestEsplora_RPCError proves a non-2xx status maps to backend.rpc_error (exit 6).
func TestEsplora_RPCError(t *testing.T) {
	_, c := newEsploraServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	_, err := c.TipHeight(context.Background())
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != domain.CodeBackendRPCError {
		t.Fatalf("err = %v, want backend.rpc_error", err)
	}
	if de.Exit != domain.ExitNetwork {
		t.Fatalf("exit = %d, want %d (network)", de.Exit, domain.ExitNetwork)
	}
}

// TestEsplora_Unreachable proves a dead endpoint maps to backend.unreachable
// (exit 6, retryable) via Dial's reachability probe.
func TestEsplora_Unreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing listening now

	_, err := Dial(context.Background(), Options{Type: domain.BackendEsplora, URL: url, Network: domain.NetworkMainnet, Timeout: secondsTimeout})
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != domain.CodeBackendUnreachable {
		t.Fatalf("err = %v, want backend.unreachable", err)
	}
	if de.Exit != domain.ExitNetwork || !de.Retryable {
		t.Fatalf("want exit %d retryable; got exit %d retryable=%v", domain.ExitNetwork, de.Exit, de.Retryable)
	}
}
