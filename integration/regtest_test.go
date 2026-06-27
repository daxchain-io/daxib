//go:build integration

// Package integration holds daxib's real-node (regtest bitcoind) end-to-end tests.
// They are excluded from the normal unit build by the `integration` build tag and
// run only via `go test -tags=integration ./integration/...` (see
// .github/workflows/integration.yml). Each test drives the ACTUAL daxib binary
// against a throwaway bitcoind regtest node, proving the build -> coin-select ->
// policy -> sign -> broadcast -> confirm -> RBF pipeline against real Bitcoin
// consensus (not a mock backend).
//
// If bitcoind / bitcoin-cli are not on PATH the suite SKIPS (so the tagged build
// stays runnable anywhere); CI installs Bitcoin Core to exercise it.
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ---- daxib binary ---------------------------------------------------------

// buildDaxib compiles the daxib binary once into a temp dir and returns its path.
func buildDaxib(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "daxib")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/daxchain-io/daxib/cmd/daxib")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build daxib: %v\n%s", err, out)
	}
	return bin
}

// node is a running regtest bitcoind plus the RPC coordinates daxib + bitcoin-cli
// need to reach it.
type node struct {
	dir      string
	rpcPort  int
	rpcUser  string
	rpcPass  string
	cliBase  []string // bitcoin-cli args that target this node (no wallet)
	minerWal string
}

func (n *node) rpcURL() string { return fmt.Sprintf("http://127.0.0.1:%d", n.rpcPort) }

// freePort asks the OS for an unused TCP port and returns it (closing the listener
// so bitcoind can bind it). A small race window is acceptable for a throwaway node.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	defer l.Close() //nolint:errcheck
	return l.Addr().(*net.TCPAddr).Port
}

// startRegtest launches a throwaway bitcoind regtest node, waits for RPC, creates a
// funded "miner" wallet (101 blocks => the first coinbase is mature/spendable), and
// registers teardown. It SKIPS the test when bitcoind/bitcoin-cli are absent.
func startRegtest(ctx context.Context, t *testing.T) *node {
	t.Helper()
	if _, err := exec.LookPath("bitcoind"); err != nil {
		t.Skip("bitcoind not on PATH; skipping regtest integration test")
	}
	if _, err := exec.LookPath("bitcoin-cli"); err != nil {
		t.Skip("bitcoin-cli not on PATH; skipping regtest integration test")
	}

	dir := t.TempDir()
	port := freePort(t)
	n := &node{
		dir:      dir,
		rpcPort:  port,
		rpcUser:  "daxibrt",
		rpcPass:  "rt-" + strconv.Itoa(port),
		minerWal: "miner",
	}
	n.cliBase = []string{
		"-regtest",
		"-datadir=" + dir,
		"-rpcconnect=127.0.0.1",
		"-rpcport=" + strconv.Itoa(port),
		"-rpcuser=" + n.rpcUser,
		"-rpcpassword=" + n.rpcPass,
	}

	bd := exec.CommandContext(ctx, "bitcoind",
		"-regtest",
		"-datadir="+dir,
		"-rpcport="+strconv.Itoa(port),
		"-rpcuser="+n.rpcUser,
		"-rpcpassword="+n.rpcPass,
		"-fallbackfee=0.0002", // regtest has no fee market; the node's own sendtoaddress needs this
		"-txindex=1",          // daxib's Core TxStatus uses getrawtransaction, which needs txindex to find a CONFIRMED non-wallet tx by txid
		"-server=1",
		"-listen=0", // no P2P peers needed
		"-printtoconsole=0",
	)
	bd.Stdout, bd.Stderr = os.Stderr, os.Stderr
	if err := bd.Start(); err != nil {
		t.Fatalf("start bitcoind: %v", err)
	}
	t.Cleanup(func() {
		_ = bd.Process.Kill()
		_, _ = bd.Process.Wait()
	})

	// Wait for the RPC to answer getblockchaininfo.
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := n.cliRaw("getblockchaininfo"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("bitcoind RPC did not become ready within 30s")
		}
		time.Sleep(250 * time.Millisecond)
	}

	// A funded miner wallet: create it, mine 101 blocks to it so block 1's coinbase
	// (101 confs) is spendable.
	n.cli(t, "createwallet", n.minerWal)
	addr := n.cliWallet(t, "getnewaddress")
	n.cliWallet(t, "generatetoaddress", "101", addr)
	return n
}

// cliRaw runs bitcoin-cli against the node (no wallet) and returns trimmed stdout.
func (n *node) cliRaw(args ...string) (string, error) {
	cmd := exec.Command("bitcoin-cli", append(append([]string{}, n.cliBase...), args...)...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%v: %s", err, errb.String())
	}
	return strings.TrimSpace(out.String()), nil
}

// cli runs bitcoin-cli (no wallet) and fails the test on error.
func (n *node) cli(t *testing.T, args ...string) string {
	t.Helper()
	out, err := n.cliRaw(args...)
	if err != nil {
		t.Fatalf("bitcoin-cli %v: %v", args, err)
	}
	return out
}

// cliWallet runs bitcoin-cli against the miner wallet and fails on error.
func (n *node) cliWallet(t *testing.T, args ...string) string {
	t.Helper()
	full := append([]string{"-rpcwallet=" + n.minerWal}, args...)
	return n.cli(t, full...)
}

// mine generates n blocks to a fresh miner address (advances the tip / confirms).
func (n *node) mine(t *testing.T, blocks int) {
	t.Helper()
	addr := n.cliWallet(t, "getnewaddress")
	n.cliWallet(t, "generatetoaddress", strconv.Itoa(blocks), addr)
}

// ---- daxib driver ---------------------------------------------------------

const dxPass = "regtest-keystore-pass"

// daxCtx is the env + binary for driving daxib against the node.
type daxCtx struct {
	bin string
	env []string
}

func newDaxCtx(t *testing.T, bin string, n *node) *daxCtx {
	t.Helper()
	home := t.TempDir()
	env := append(os.Environ(),
		"HOME="+home,
		"DAXIB_CONFIG="+filepath.Join(home, "cfg"),
		"DAXIB_KEYSTORE="+filepath.Join(home, "ks"),
		"DAXIB_STATE_DIR="+filepath.Join(home, "state"),
		"DAXIB_NETWORK=regtest",
		"DAXIB_PASSPHRASE="+dxPass,
		"DAXIB_PASSPHRASE_CONFIRM="+dxPass, // first-init double-entry (non-TTY)
		"DAXIB_RT_RPCPASS="+n.rpcPass,      // referenced by the backend's --rpcpassword ${env:...}
	)
	return &daxCtx{bin: bin, env: env}
}

// run executes `daxib args...`, returning (stdout, stderr, exitcode).
func (d *daxCtx) run(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(d.bin, args...)
	cmd.Env = d.env
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("daxib %v: exec error: %v", args, err)
		}
	}
	return out.String(), errb.String(), code
}

// mustRun runs daxib and fails on a non-zero exit.
func (d *daxCtx) mustRun(t *testing.T, args ...string) string {
	t.Helper()
	out, errb, code := d.run(t, args...)
	if code != 0 {
		t.Fatalf("daxib %v: exit %d\nstdout: %s\nstderr: %s", args, code, out, errb)
	}
	return out
}

// mustJSON runs daxib --json and decodes the stdout object.
func (d *daxCtx) mustJSON(t *testing.T, args ...string) map[string]any {
	t.Helper()
	out := d.mustRun(t, append(args, "--json")...)
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("daxib %v: decode json: %v\n%s", args, err, out)
	}
	return m
}

// ---- the test -------------------------------------------------------------

// TestRegtestSendConfirmRBF proves the full pipeline against real consensus:
// fund a daxib wallet, send + confirm a tx, then RBF-replace an unconfirmed tx and
// confirm the replacement.
func TestRegtestSendConfirmRBF(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	n := startRegtest(ctx, t)
	bin := buildDaxib(t)
	d := newDaxCtx(t, bin, n)

	// Wallet (agnostic; regtest HRP is bcrt1 under DAXIB_NETWORK=regtest).
	d.mustRun(t, "wallet", "create", "rt", "--yes")
	// Core backend pointing at the node; password via an ${env:} ref (never a literal).
	d.mustRun(t, "backend", "add", "core",
		"--type", "core",
		"--url", n.rpcURL(),
		"--rpcuser", n.rpcUser,
		"--rpcpassword", "${env:DAXIB_RT_RPCPASS}",
		"--network", "regtest")
	d.mustRun(t, "backend", "use", "core")

	// Fund: a daxib receive address, paid by the miner wallet, then 1 block to confirm.
	addr, _ := stringField(t, d.mustJSON(t, "address", "new", "--wallet", "rt"), "address")
	if !strings.HasPrefix(addr, "bcrt1") {
		t.Fatalf("expected a bcrt1 regtest address, got %q", addr)
	}
	n.cliWallet(t, "sendtoaddress", addr, "5.0")
	n.mine(t, 1)

	// Balance: daxib's scantxoutset path must see the confirmed 5 BTC.
	bal := d.mustJSON(t, "balance", "--wallet", "rt")
	if got := satField(t, bal, "confirmed_sat", "confirmed"); got < 500_000_000 {
		t.Fatalf("expected >= 5 BTC confirmed, got %d sat\n%v", got, bal)
	}

	// Send 1 BTC back to the miner; explicit fee-rate (regtest has no estimatesmartfee).
	dest := n.cliWallet(t, "getnewaddress")
	sent := d.mustJSON(t, "tx", "send", "--wallet", "rt", "--to", dest, "--amount", "1btc", "--fee-rate", "2", "--yes")
	txid, _ := stringField(t, sent, "txid")
	if len(txid) != 64 {
		t.Fatalf("expected a 64-hex txid, got %q\n%v", txid, sent)
	}
	// It must be in the node mempool (real broadcast happened).
	if mp := n.cli(t, "getrawmempool"); !strings.Contains(mp, txid) {
		t.Fatalf("sent txid %s not in node mempool: %s", txid, mp)
	}
	// Confirm it; daxib must report confirmed.
	n.mine(t, 1)
	st := d.mustJSON(t, "tx", "status", txid)
	if s := lowerField(st, "status", "state"); !strings.Contains(s, "confirm") {
		t.Fatalf("tx %s not confirmed per daxib: %v", txid, st)
	}

	// RBF: send another (leave unconfirmed), then speedup -> a replacement txid that
	// evicts the original from the mempool.
	dest2 := n.cliWallet(t, "getnewaddress")
	orig := d.mustJSON(t, "tx", "send", "--wallet", "rt", "--to", dest2, "--amount", "1btc", "--fee-rate", "2", "--yes")
	origTxid, _ := stringField(t, orig, "txid")
	rep := d.mustJSON(t, "tx", "speedup", origTxid, "--wallet", "rt", "--fee-rate", "20", "--yes")
	repTxid := firstTxidLike(rep, origTxid)
	if repTxid == "" || repTxid == origTxid {
		t.Fatalf("speedup did not yield a distinct replacement txid: %v", rep)
	}
	mp := n.cli(t, "getrawmempool")
	if !strings.Contains(mp, repTxid) {
		t.Fatalf("replacement %s not in mempool: %s", repTxid, mp)
	}
	if strings.Contains(mp, origTxid) {
		t.Fatalf("original %s still in mempool after RBF replacement: %s", origTxid, mp)
	}
	// Confirm the replacement.
	n.mine(t, 1)
	rst := d.mustJSON(t, "tx", "status", repTxid)
	if s := lowerField(rst, "status", "state"); !strings.Contains(s, "confirm") {
		t.Fatalf("replacement %s not confirmed per daxib: %v", repTxid, rst)
	}
}

// ---- small JSON helpers ---------------------------------------------------

func stringField(t *testing.T, m map[string]any, keys ...string) (string, bool) {
	t.Helper()
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok {
				return s, true
			}
		}
	}
	return "", false
}

func lowerField(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok {
				return strings.ToLower(s)
			}
		}
	}
	return ""
}

// satField reads an integer sat amount, tolerating a number or a numeric string.
func satField(t *testing.T, m map[string]any, keys ...string) int64 {
	t.Helper()
	for _, k := range keys {
		v, ok := m[k]
		if !ok {
			continue
		}
		switch x := v.(type) {
		case float64:
			return int64(x)
		case json.Number:
			n, _ := x.Int64()
			return n
		case string:
			if n, err := strconv.ParseInt(x, 10, 64); err == nil {
				return n
			}
		}
	}
	t.Fatalf("no integer sat field %v in %v", keys, m)
	return 0
}

// firstTxidLike returns a 64-hex txid value from the result that differs from `not`.
func firstTxidLike(m map[string]any, not string) string {
	for _, k := range []string{"replacement_txid", "replacement", "new_txid", "txid"} {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && len(s) == 64 && s != not {
				return s
			}
		}
	}
	return ""
}
