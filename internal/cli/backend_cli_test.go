package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/daxchain-io/daxib/internal/domain"
)

const canonicalReceive0 = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"

// isolateConfig points DAXIB_CONFIG at a fresh temp DIRECTORY (the config state
// class) so the backend commands write to an isolated config.toml inside it.
func isolateConfig(t *testing.T) {
	t.Helper()
	t.Setenv("DAXIB_CONFIG", t.TempDir())
	t.Setenv("DAXIB_BACKEND", "")
}

// TestCLI_BackendLifecycle_JSON drives backend add -> list --json -> use -> test
// against an httptest Esplora through the real Cobra tree, then a balance.
func TestCLI_BackendLifecycle_JSON(t *testing.T) {
	isolateKeystore(t)
	isolateConfig(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/blocks/tip/height":
			_, _ = io.WriteString(w, "800000")
		case "/address/" + canonicalReceive0 + "/utxo":
			_, _ = io.WriteString(w, `[{"txid":"aa","vout":0,"value":150000,"status":{"confirmed":true,"block_height":799991}}]`)
		default:
			_, _ = io.WriteString(w, "[]")
		}
	}))
	defer srv.Close()

	// Import the canonical wallet.
	if _, errOut, code := execCLI(t, "wallet", "import", "vec", "--network", "mainnet", "--mnemonic-file", mnemonicFile(t)); code != 0 {
		t.Fatalf("wallet import exit %d: %s", code, errOut)
	}

	// backend add.
	if _, errOut, code := execCLI(t, "backend", "add", "esp", "--network", "mainnet", "--type", "esplora", "--url", srv.URL); code != 0 {
		t.Fatalf("backend add exit %d: %s", code, errOut)
	}

	// backend list --json.
	out, errOut, code := execCLI(t, "--json", "backend", "list")
	if code != 0 {
		t.Fatalf("backend list exit %d: %s", code, errOut)
	}
	var listRes domain.BackendListResult
	if err := json.Unmarshal([]byte(out), &listRes); err != nil {
		t.Fatalf("backend list --json not parseable: %v\n%s", err, out)
	}
	if len(listRes.Backends) != 1 || listRes.Backends[0].Name != "esp" {
		t.Fatalf("backend list = %+v, want one esp", listRes.Backends)
	}

	// backend use.
	if _, errOut, code := execCLI(t, "backend", "use", "esp"); code != 0 {
		t.Fatalf("backend use exit %d: %s", code, errOut)
	}

	// backend test --json.
	out, errOut, code = execCLI(t, "--json", "backend", "test", "esp")
	if code != 0 {
		t.Fatalf("backend test exit %d: %s", code, errOut)
	}
	var testRes domain.BackendTestResult
	if err := json.Unmarshal([]byte(out), &testRes); err != nil {
		t.Fatalf("backend test --json not parseable: %v\n%s", err, out)
	}
	if testRes.TipHeight != 800000 {
		t.Fatalf("backend test tip = %d, want 800000", testRes.TipHeight)
	}

	// balance --json reports the 150000-sat confirmed total.
	out, errOut, code = execCLI(t, "--json", "balance", "--wallet", "vec")
	if code != 0 {
		t.Fatalf("balance exit %d: %s", code, errOut)
	}
	var bal domain.BalanceResult
	if err := json.Unmarshal([]byte(out), &bal); err != nil {
		t.Fatalf("balance --json not parseable: %v\n%s", err, out)
	}
	if bal.ConfirmedSat != 150000 || bal.ConfirmedBTC != "0.00150000" {
		t.Fatalf("balance confirmed = %d (%s), want 150000 (0.00150000)", bal.ConfirmedSat, bal.ConfirmedBTC)
	}

	// utxo list --json shows the single coin.
	out, errOut, code = execCLI(t, "--json", "utxo", "list", "--wallet", "vec")
	if code != 0 {
		t.Fatalf("utxo list exit %d: %s", code, errOut)
	}
	var ul domain.UTXOListResult
	if err := json.Unmarshal([]byte(out), &ul); err != nil {
		t.Fatalf("utxo list --json not parseable: %v\n%s", err, out)
	}
	if len(ul.UTXOs) != 1 || ul.UTXOs[0].Outpoint != "aa:0" {
		t.Fatalf("utxo list = %+v, want one aa:0", ul.UTXOs)
	}
}

// TestCLI_BackendTest_Unreachable proves a dead backend exits 6 with a
// backend.unreachable envelope (the dial+error path with nothing listening).
func TestCLI_BackendTest_Unreachable(t *testing.T) {
	isolateKeystore(t)
	isolateConfig(t)

	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing listening

	if _, errOut, code := execCLI(t, "backend", "add", "dead", "--network", "mainnet", "--type", "esplora", "--url", url); code != 0 {
		t.Fatalf("backend add exit %d: %s", code, errOut)
	}

	out, errOut, code := execCLI(t, "--json", "backend", "test", "dead")
	if code != int(domain.ExitNetwork) {
		t.Fatalf("backend test exit = %d, want %d (network); stderr=%s stdout=%s", code, domain.ExitNetwork, errOut, out)
	}
	if !strings.Contains(errOut, "backend.unreachable") {
		t.Fatalf("stderr = %q, want a backend.unreachable envelope", errOut)
	}
}
