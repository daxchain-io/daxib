package keys

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/btcutil"

	"github.com/daxchain-io/daxib/internal/domain"
)

// witnessProgram decodes a bech32(m) P2WPKH address and returns its witness
// program bytes (the hash160 of the pubkey), independent of the HRP.
func witnessProgram(t *testing.T, addr string, net domain.Network) []byte {
	t.Helper()
	a, err := btcutil.DecodeAddress(addr, chainParams(net))
	if err != nil {
		t.Fatalf("decode %q: %v", addr, err)
	}
	return a.ScriptAddress()
}

// loadMetaFor reads + parses the keystore's meta.json from disk (post-save shape),
// exercising the v2 on-disk format.
func loadMetaFor(t *testing.T, dir string) *metaFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		t.Fatalf("read meta: %v", err)
	}
	var m metaFile
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal meta: %v", err)
	}
	return &m
}

// TestAgnosticCreateStoresBothChains asserts a default (agnostic) wallet stores
// BOTH coin_type chains (0 and 1), each with a materialized 0/0 receive address.
func TestAgnosticCreateStoresBothChains(t *testing.T) {
	s := openLight(t)
	ctx := context.Background()
	if _, err := s.CreateWallet(ctx, "any", 12, domain.NetworkMainnet, false, pass("pw"), pass("pw")); err != nil {
		t.Fatalf("CreateWallet: %v", err)
	}
	m := loadMetaFor(t, s.dir)
	_, w, ok := m.findWalletByName("any")
	if !ok {
		t.Fatal("wallet not found")
	}
	if w.Scope != scopeAgnostic {
		t.Fatalf("scope = %q, want agnostic", w.Scope)
	}
	if w.Network != "" {
		t.Fatalf("agnostic Network = %q, want empty", w.Network)
	}
	if len(w.Chains) != 2 {
		t.Fatalf("agnostic chains = %d, want 2", len(w.Chains))
	}
	for _, key := range []string{"0", "1"} {
		c, ok := w.Chains[key]
		if !ok || c == nil {
			t.Fatalf("missing chain %q", key)
		}
		if c.NextReceive != 1 {
			t.Fatalf("chain %q next_receive = %d, want 1", key, c.NextReceive)
		}
		if len(c.Addresses) != 1 {
			t.Fatalf("chain %q addresses = %d, want 1", key, len(c.Addresses))
		}
	}
	// The two chains' xpubs differ (different coin_type derivation paths).
	if w.Chains["0"].AccountXpub == w.Chains["1"].AccountXpub {
		t.Fatal("ct0 and ct1 xpubs are identical; expected distinct account keys")
	}
}

// TestBoundCreateStoresOneChain asserts a --bind wallet stores ONLY its network's
// coin_type chain.
func TestBoundCreateStoresOneChain(t *testing.T) {
	s := openLight(t)
	ctx := context.Background()
	if _, err := s.CreateWallet(ctx, "tnet", 12, domain.NetworkTestnet, true, pass("pw"), pass("pw")); err != nil {
		t.Fatalf("CreateWallet bound: %v", err)
	}
	m := loadMetaFor(t, s.dir)
	_, w, _ := m.findWalletByName("tnet")
	if w.Scope != scopeBound {
		t.Fatalf("scope = %q, want bound", w.Scope)
	}
	if w.Network != string(domain.NetworkTestnet) {
		t.Fatalf("bound Network = %q, want testnet", w.Network)
	}
	if len(w.Chains) != 1 {
		t.Fatalf("bound chains = %d, want 1", len(w.Chains))
	}
	if _, ok := w.Chains["1"]; !ok {
		t.Fatal("bound testnet wallet missing ct1 chain")
	}
	if _, ok := w.Chains["0"]; ok {
		t.Fatal("bound testnet wallet should not hold the ct0 chain")
	}
}

// TestAgnosticPerCoinTypeWatermarks asserts the two chains advance independently:
// deriving on mainnet bumps ct0's watermark, leaving ct1 untouched.
func TestAgnosticPerCoinTypeWatermarks(t *testing.T) {
	s := openLight(t)
	ctx := context.Background()
	if _, err := s.CreateWallet(ctx, "any", 12, domain.NetworkMainnet, false, pass("pw"), pass("pw")); err != nil {
		t.Fatalf("CreateWallet: %v", err)
	}
	// Derive twice on mainnet (ct0); ct1 stays at the create watermark.
	for i := 0; i < 2; i++ {
		if _, err := s.DeriveNext(ctx, "any", domain.NetworkMainnet, domain.BranchReceive); err != nil {
			t.Fatalf("DeriveNext mainnet: %v", err)
		}
	}
	m := loadMetaFor(t, s.dir)
	_, w, _ := m.findWalletByName("any")
	if w.Chains["0"].NextReceive != 3 {
		t.Fatalf("ct0 next_receive = %d, want 3", w.Chains["0"].NextReceive)
	}
	if w.Chains["1"].NextReceive != 1 {
		t.Fatalf("ct1 next_receive = %d, want 1 (untouched)", w.Chains["1"].NextReceive)
	}
}

// TestAgnosticSignetRegtestSameIndexDifferentHRP asserts that the SAME ct1
// watermark yields tb1 on signet and bcrt1 on regtest at the same index, with the
// SAME underlying pubkey (only the HRP/encoding differs).
func TestAgnosticSignetRegtestSameIndexDifferentHRP(t *testing.T) {
	s := openLight(t)
	ctx := context.Background()
	if _, err := s.CreateWallet(ctx, "any", 12, domain.NetworkMainnet, false, pass("pw"), pass("pw")); err != nil {
		t.Fatalf("CreateWallet: %v", err)
	}
	// AddressAt(0/0) on signet and regtest reads the SAME ct1 chain at index 0.
	sig, err := s.AddressAt(ctx, "any", domain.NetworkSignet, domain.BranchReceive, 0)
	if err != nil {
		t.Fatalf("AddressAt signet: %v", err)
	}
	reg, err := s.AddressAt(ctx, "any", domain.NetworkRegtest, domain.BranchReceive, 0)
	if err != nil {
		t.Fatalf("AddressAt regtest: %v", err)
	}
	if sig.Address[:3] != "tb1" {
		t.Fatalf("signet address = %q, want tb1...", sig.Address)
	}
	if reg.Address[:5] != "bcrt1" {
		t.Fatalf("regtest address = %q, want bcrt1...", reg.Address)
	}
	// Same underlying pubkey: the witness program (hash160) must match. We compare
	// via the decoded witness-program bytes by re-deriving on testnet (tb) which
	// shares ct1; signet and regtest must encode the identical program.
	wantProg := witnessProgram(t, sig.Address, domain.NetworkSignet)
	gotProg := witnessProgram(t, reg.Address, domain.NetworkRegtest)
	if string(wantProg) != string(gotProg) {
		t.Fatal("signet and regtest witness programs differ; expected the same pubkey")
	}
}

// TestV1MigrationToBound hand-writes a format-1 meta.json and asserts loadMeta
// migrates it IN MEMORY to a BOUND v2 wallet: scope=bound, Network preserved, the
// single chain moved under its coin_type, legacy scalars gone.
func TestV1MigrationToBound(t *testing.T) {
	s := openLight(t)
	ctx := context.Background()
	// Seed the keystore passphrase + a wallet blob the legacy meta can reference is
	// not needed for loadMeta (it only reads meta.json). Initialize the keystore so
	// permissions/dir exist by creating then overwriting meta.json.
	if _, err := s.CreateWallet(ctx, "seed", 12, domain.NetworkMainnet, true, pass("pw"), pass("pw")); err != nil {
		t.Fatalf("CreateWallet seed: %v", err)
	}

	// Hand-write a format-1 meta.json (the legacy flat shape) for a testnet wallet.
	v1 := map[string]any{
		"daxib_meta":     1,
		"default_wallet": "legacy",
		"wallets": map[string]any{
			"11111111-1111-1111-1111-111111111111": map[string]any{
				"name":         "legacy",
				"network":      "testnet",
				"created_at":   "2020-01-01T00:00:00Z",
				"path_prefix":  "m/84'/1'/0'",
				"account_xpub": "tpubDUMMYxpubDUMMYxpubDUMMY",
				"next_receive": 3,
				"next_change":  1,
				"addresses": map[string]any{
					"0/0": map[string]any{"address": "tb1qexample", "created_at": "2020-01-01T00:00:00Z"},
				},
			},
		},
	}
	raw, err := json.MarshalIndent(v1, "", "  ")
	if err != nil {
		t.Fatalf("marshal v1: %v", err)
	}
	if err := os.WriteFile(filepath.Join(s.dir, "meta.json"), raw, 0o600); err != nil {
		t.Fatalf("write v1 meta: %v", err)
	}

	m, err := s.loadMeta()
	if err != nil {
		t.Fatalf("loadMeta (v1 migration): %v", err)
	}
	if m.Format != metaFormatVersion {
		t.Fatalf("migrated format = %d, want %d", m.Format, metaFormatVersion)
	}
	_, w, ok := m.findWalletByName("legacy")
	if !ok {
		t.Fatal("migrated wallet not found")
	}
	if w.Scope != scopeBound {
		t.Fatalf("migrated scope = %q, want bound", w.Scope)
	}
	if w.Network != "testnet" {
		t.Fatalf("migrated Network = %q, want testnet", w.Network)
	}
	if len(w.Chains) != 1 {
		t.Fatalf("migrated chains = %d, want 1", len(w.Chains))
	}
	c, ok := w.Chains["1"]
	if !ok {
		t.Fatal("migrated wallet missing ct1 chain")
	}
	if c.AccountXpub != "tpubDUMMYxpubDUMMYxpubDUMMY" {
		t.Fatalf("migrated xpub = %q, not carried from v1", c.AccountXpub)
	}
	if c.NextReceive != 3 || c.NextChange != 1 {
		t.Fatalf("migrated watermarks = (%d,%d), want (3,1)", c.NextReceive, c.NextChange)
	}
	if len(c.Addresses) != 1 {
		t.Fatalf("migrated addresses = %d, want 1", len(c.Addresses))
	}
	if _, ok := w.Chains["0"]; ok {
		t.Fatal("migrated bound wallet should not hold the ct0 chain")
	}
}

// TestWalletUpgradeBoundToAgnostic asserts upgrade adds the missing coin_type
// chain and flips the wallet to agnostic.
func TestWalletUpgradeBoundToAgnostic(t *testing.T) {
	s := openLight(t)
	ctx := context.Background()
	if _, err := s.CreateWallet(ctx, "tnet", 12, domain.NetworkTestnet, true, pass("pw"), pass("pw")); err != nil {
		t.Fatalf("CreateWallet bound: %v", err)
	}
	info, err := s.WalletUpgrade(ctx, "tnet", domain.NetworkMainnet, pass("pw"))
	if err != nil {
		t.Fatalf("WalletUpgrade: %v", err)
	}
	if info.Scope != scopeAgnostic {
		t.Fatalf("upgraded scope = %q, want agnostic", info.Scope)
	}
	m := loadMetaFor(t, s.dir)
	_, w, _ := m.findWalletByName("tnet")
	if w.Scope != scopeAgnostic || w.Network != "" {
		t.Fatalf("upgraded meta scope=%q network=%q, want agnostic + empty", w.Scope, w.Network)
	}
	if len(w.Chains) != 2 {
		t.Fatalf("upgraded chains = %d, want 2", len(w.Chains))
	}
	if _, ok := w.Chains["0"]; !ok {
		t.Fatal("upgrade did not add the ct0 chain")
	}
	// Upgrading an already-agnostic wallet is a usage error.
	if _, err := s.WalletUpgrade(ctx, "tnet", domain.NetworkMainnet, pass("pw")); err == nil {
		t.Fatal("upgrading an agnostic wallet should error")
	} else if got := codeOf(t, err); got != "usage.already_agnostic" {
		t.Fatalf("re-upgrade code = %q, want usage.already_agnostic", got)
	}
}

// TestCheckWatermarkPerChain asserts checkWatermark trips on EITHER coin_type
// chain: an agnostic wallet whose ct1 chain has a materialized index past its
// watermark fails closed.
func TestCheckWatermarkPerChain(t *testing.T) {
	s := openLight(t)
	ctx := context.Background()
	if _, err := s.CreateWallet(ctx, "any", 12, domain.NetworkMainnet, false, pass("pw"), pass("pw")); err != nil {
		t.Fatalf("CreateWallet: %v", err)
	}
	m, err := s.loadMeta()
	if err != nil {
		t.Fatalf("loadMeta: %v", err)
	}
	_, w, _ := m.findWalletByName("any")
	// Materialize a ct1 index (5) above its watermark (1) -> inconsistent.
	w.Chains["1"].Addresses["0/5"] = &metaAddress{Address: "tb1qbogus", CreatedAt: "x"}
	if err := m.checkWatermark(); err == nil {
		t.Fatal("checkWatermark should trip on the ct1 chain")
	} else if got := codeOf(t, err); got != CodeKeystoreDerivationWatermark {
		t.Fatalf("checkWatermark code = %q, want %q", got, CodeKeystoreDerivationWatermark)
	}
}
