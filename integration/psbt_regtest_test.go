//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"
	"time"
)

// psbt_regtest_test.go proves the PSBT (BIP-174) pipeline against real Bitcoin
// consensus: fund a daxib wallet, build an UNSIGNED PSBT (`psbt create`), sign its
// wallet-owned inputs through the SEALED-SPEND-POLICY chokepoint (`psbt sign` — the
// only path to the keystore signer, gated by eng.Reserve exactly like `tx send`),
// then finalize + extract + broadcast it (`psbt broadcast`), and assert the tx
// lands in the node mempool and confirms. It mirrors regtest_test.go's node +
// daxCtx harness and SKIPS when bitcoind/bitcoin-cli are absent.
//
// This is the end-to-end proof that a PSBT round-trip moves real coins under policy
// — the chokepoint is not a mock: keys.SignInputs signs the real prevouts, the
// witness is lifted into the PSBT, finalize assembles it, and the extracted raw tx
// is accepted by bitcoind.
func TestRegtestPSBTCreateSignBroadcast(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	n := startRegtest(ctx, t)
	bin := buildDaxib(t)
	d := newDaxCtx(t, bin, n)

	// Wallet + Core backend pointed at the node (password via an ${env:} ref).
	d.mustRun(t, "wallet", "create", "rt", "--yes")
	d.mustRun(t, "backend", "add", "core",
		"--type", "core",
		"--url", n.rpcURL(),
		"--rpcuser", n.rpcUser,
		"--rpcpassword", "${env:DAXIB_RT_RPCPASS}",
		"--network", "regtest")
	d.mustRun(t, "backend", "use", "core")

	// Fund a daxib receive address with 5 BTC, then confirm it.
	addr, _ := stringField(t, d.mustJSON(t, "address", "new", "--wallet", "rt"), "address")
	if !strings.HasPrefix(addr, "bcrt1") {
		t.Fatalf("expected a bcrt1 regtest address, got %q", addr)
	}
	n.cliWallet(t, "sendtoaddress", addr, "5.0")
	n.mine(t, 1)
	if got := satField(t, d.mustJSON(t, "balance", "--wallet", "rt"), "confirmed_sat", "confirmed"); got < 500_000_000 {
		t.Fatalf("expected >= 5 BTC confirmed, got %d sat", got)
	}

	dest := n.cliWallet(t, "getnewaddress")

	// (1) CREATE an unsigned PSBT spending 1 BTC to the miner. --quiet so stdout is the
	// bare base64 for the next stage. Create authorizes nothing (no policy charge).
	unsigned := strings.TrimSpace(d.mustRun(t,
		"psbt", "create", "--wallet", "rt", "--to", dest, "--amount", "1btc", "--fee-rate", "2", "--quiet"))
	if unsigned == "" || strings.ContainsAny(unsigned, " \t\n") {
		t.Fatalf("psbt create must emit one clean base64 line, got %q", unsigned)
	}

	// (2) DECODE it for sanity: incomplete, wallet owns the input, one recipient + change.
	dec := d.mustJSON(t, "psbt", "decode", unsigned, "--wallet", "rt")
	if mine := intField(dec, "signed_by_us"); mine != 0 {
		t.Fatalf("a freshly created PSBT must have signed_by_us=0, got %v", dec["signed_by_us"])
	}

	// (3) SIGN through the policy chokepoint (passphrase via DAXIB_PASSPHRASE; --yes
	// authorizes the non-interactive sign). A PartialSig is attached only AFTER the
	// reservation succeeds.
	signed := strings.TrimSpace(d.mustRun(t,
		"psbt", "sign", unsigned, "--wallet", "rt", "--yes", "--quiet"))
	if signed == "" || signed == unsigned {
		t.Fatalf("psbt sign must emit an updated PSBT distinct from the unsigned one")
	}
	sdec := d.mustJSON(t, "psbt", "decode", signed, "--wallet", "rt")
	if sb := intField(sdec, "signed_by_us"); sb < 1 {
		t.Fatalf("the signed PSBT must report signed_by_us>=1, got %v", sdec["signed_by_us"])
	}

	// (4) BROADCAST: finalize-if-needed + extract + submit, committing the sign-time
	// reservation. --yes authorizes the non-interactive broadcast.
	bres := d.mustJSON(t, "psbt", "broadcast", signed, "--wallet", "rt", "--yes")
	txid, _ := stringField(t, bres, "txid")
	if len(txid) != 64 {
		t.Fatalf("expected a 64-hex txid from psbt broadcast, got %q\n%v", txid, bres)
	}

	// It reached the real node mempool.
	if mp := n.cli(t, "getrawmempool"); !strings.Contains(mp, txid) {
		t.Fatalf("broadcast PSBT txid %s not in node mempool: %s", txid, mp)
	}

	// Confirm it; daxib must report confirmed.
	n.mine(t, 1)
	st := d.mustJSON(t, "tx", "status", txid)
	if s := lowerField(st, "status", "state"); !strings.Contains(s, "confirm") {
		t.Fatalf("PSBT tx %s not confirmed per daxib: %v", txid, st)
	}
}

// intField reads a JSON-number field (e.g. signed_by_us) as an int64, defaulting
// to 0 when the field is absent or non-numeric.
func intField(m map[string]any, key string) int64 {
	if x, ok := m[key].(float64); ok {
		return int64(x)
	}
	return 0
}
