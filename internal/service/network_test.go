package service

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/daxchain-io/daxib/internal/domain"
)

// openNet opens a service with explicit Network/NetworkSource/Config, sharing one
// keystore+config+state root so the persisted defaults.network is observable across
// reopens. secrets come from env (no TTY).
func openNet(t *testing.T, dir string, network, source, configDir string, env map[string]string) (*Service, func()) {
	t.Helper()
	env2 := map[string]string{"DAXIB_KDF_LIGHT": "1"}
	for k, v := range env {
		env2[k] = v
	}
	svc, err := Open(context.Background(), Options{
		Keystore:      dir,
		Config:        configDir,
		State:         dir + "/state",
		Network:       network,
		NetworkSource: source,
		KDFLight:      true,
		Secret: SecretIO{
			Stdin:     bytes.NewBufferString(""),
			LookupEnv: func(k string) (string, bool) { v, ok := env2[k]; return v, ok },
			IsTTY:     func() bool { return false },
			Prompt:    func(string) ([]byte, error) { return nil, errors.New("no TTY in test") },
		},
	})
	if err != nil {
		t.Fatalf("service.Open(network=%q): %v", network, err)
	}
	return svc, func() { _ = svc.Close() }
}

// TestRequireNetworkUnset proves an unresolved network yields usage.network_required
// (exit 2) at the service guard, for the network-requiring ops, and that a resolved
// network does NOT trip the guard.
func TestRequireNetworkUnset(t *testing.T) {
	dir := t.TempDir()
	cfg := t.TempDir()

	svc, done := openNet(t, dir, "", "", cfg, nil)
	defer done()

	if svc.net != "" {
		t.Fatalf("net = %q, want unresolved \"\"", svc.net)
	}
	if err := svc.requireNetwork(); err == nil {
		t.Fatal("requireNetwork() = nil, want usage.network_required")
	} else if c := code(t, err); c != domain.CodeNetworkRequired {
		t.Fatalf("requireNetwork() code = %q, want %q", c, domain.CodeNetworkRequired)
	}

	ctx := context.Background()
	// A representative set of network-requiring ops must all surface
	// usage.network_required when nothing is selected.
	if _, err := svc.WalletList(ctx, domain.LocalCLI(), domain.WalletListRequest{}); code(t, err) != domain.CodeNetworkRequired {
		t.Errorf("WalletList code = %q, want network_required", code(t, err))
	}
	if _, err := svc.WalletShow(ctx, domain.LocalCLI(), domain.WalletShowRequest{Name: "x"}); code(t, err) != domain.CodeNetworkRequired {
		t.Errorf("WalletShow code = %q, want network_required", code(t, err))
	}
	if _, err := svc.AddressList(ctx, domain.LocalCLI(), domain.AddressListRequest{Wallet: "x"}); code(t, err) != domain.CodeNetworkRequired {
		t.Errorf("AddressList code = %q, want network_required", code(t, err))
	}
	if _, err := svc.Fee(ctx, domain.LocalCLI(), domain.FeeRequest{}); code(t, err) != domain.CodeNetworkRequired {
		t.Errorf("Fee code = %q, want network_required", code(t, err))
	}
	if _, err := svc.SendTx(ctx, domain.LocalCLI(), domain.SendRequest{To: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", Amount: "0.001", FeeRate: "10", Yes: true}, nil); code(t, err) != domain.CodeNetworkRequired {
		t.Errorf("SendTx code = %q, want network_required", code(t, err))
	}
	if _, err := svc.MessageSign(ctx, domain.LocalCLI(), domain.MessageSignRequest{Ref: "x/0/0"}, MessageSignInput{}); code(t, err) != domain.CodeNetworkRequired {
		t.Errorf("MessageSign code = %q, want network_required", code(t, err))
	}
	if _, err := svc.PolicyShow(ctx, domain.LocalCLI()); code(t, err) != domain.CodeNetworkRequired {
		t.Errorf("PolicyShow code = %q, want network_required", code(t, err))
	}
	// AF1-1: verify must NOT silently apply MAINNET semantics (chainParams("")->
	// MainNetParams). With no network it fails closed like its sibling MessageSign.
	if _, err := svc.MessageVerify(ctx, domain.LocalCLI(), domain.MessageVerifyRequest{
		Address:   "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
		Message:   "hello",
		Signature: "AAAA",
	}); code(t, err) != domain.CodeNetworkRequired {
		t.Errorf("MessageVerify code = %q, want network_required", code(t, err))
	}
	// AF1-2: contacts add validates + pins per network; with none it must fail closed,
	// not silently accept mainnet addresses and pin a blank network.
	if _, err := svc.ContactAdd(ctx, domain.LocalCLI(), domain.ContactAddRequest{
		Name: "alice", Address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
	}); code(t, err) != domain.CodeNetworkRequired {
		t.Errorf("ContactAdd code = %q, want network_required", code(t, err))
	}
	// AF1-4: tx list was the lone tx subcommand that succeeded (rc=0) with no network;
	// it must now fail closed like send/status/abandon/etc.
	if _, err := svc.ListTxs(ctx, domain.LocalCLI(), domain.TxListRequest{}); code(t, err) != domain.CodeNetworkRequired {
		t.Errorf("ListTxs code = %q, want network_required", code(t, err))
	}
}

// TestNetworkResolutionPrecedence proves flag > env (NetworkSource) > config
// defaults.network > unresolved. The flag/env distinction is the NetworkSource the
// host supplies with a non-empty Network; the config rung is resolved at Open.
func TestNetworkResolutionPrecedence(t *testing.T) {
	dir := t.TempDir()
	cfg := t.TempDir()
	ctx := context.Background()

	// Persist defaults.network=signet via NetworkUse (needs a config dir).
	{
		svc, done := openNet(t, dir, "", "", cfg, nil)
		if _, err := svc.NetworkUse(ctx, domain.LocalCLI(), "signet"); err != nil {
			t.Fatalf("NetworkUse(signet): %v", err)
		}
		done()
	}

	// No flag/env: the persisted config default wins (source "config").
	{
		svc, done := openNet(t, dir, "", "", cfg, nil)
		if svc.net != domain.NetworkSignet || svc.netSource != "config" {
			t.Fatalf("config rung: net=%q source=%q, want signet/config", svc.net, svc.netSource)
		}
		done()
	}

	// env override (NetworkSource "env") beats the persisted default.
	{
		svc, done := openNet(t, dir, "testnet", "env", cfg, nil)
		if svc.net != domain.NetworkTestnet || svc.netSource != "env" {
			t.Fatalf("env rung: net=%q source=%q, want testnet/env", svc.net, svc.netSource)
		}
		done()
	}

	// flag override (NetworkSource "flag") beats everything.
	{
		svc, done := openNet(t, dir, "regtest", "flag", cfg, nil)
		if svc.net != domain.NetworkRegtest || svc.netSource != "flag" {
			t.Fatalf("flag rung: net=%q source=%q, want regtest/flag", svc.net, svc.netSource)
		}
		done()
	}
}

// TestNetworkUseShowListRoundtrip exercises the network noun service methods.
func TestNetworkUseShowListRoundtrip(t *testing.T) {
	dir := t.TempDir()
	cfg := t.TempDir()
	ctx := context.Background()

	// Unset: show reports unresolved/unset.
	{
		svc, done := openNet(t, dir, "", "", cfg, nil)
		show, err := svc.NetworkShow(ctx, domain.LocalCLI())
		if err != nil {
			t.Fatalf("NetworkShow: %v", err)
		}
		if show.Resolved || show.Source != "unset" || show.Network != "" {
			t.Fatalf("show unset = %+v, want resolved=false source=unset network=\"\"", show)
		}
		// list always returns the five, none active when unresolved.
		list, err := svc.NetworkList(ctx, domain.LocalCLI())
		if err != nil {
			t.Fatalf("NetworkList: %v", err)
		}
		if len(list.Networks) != 5 {
			t.Fatalf("list len = %d, want 5", len(list.Networks))
		}
		for _, n := range list.Networks {
			if n.Active {
				t.Errorf("network %q marked active with no resolved network", n.Network)
			}
		}
		// use persists.
		if _, err := svc.NetworkUse(ctx, domain.LocalCLI(), "testnet4"); err != nil {
			t.Fatalf("NetworkUse(testnet4): %v", err)
		}
		done()
	}

	// Reopen with no flag/env: show now reports testnet4 from config, and list marks
	// it active.
	{
		svc, done := openNet(t, dir, "", "", cfg, nil)
		show, err := svc.NetworkShow(ctx, domain.LocalCLI())
		if err != nil {
			t.Fatalf("NetworkShow: %v", err)
		}
		if !show.Resolved || show.Network != "testnet4" || show.Source != "config" {
			t.Fatalf("show after use = %+v, want testnet4/config/resolved", show)
		}
		list, _ := svc.NetworkList(ctx, domain.LocalCLI())
		var active string
		for _, n := range list.Networks {
			if n.Active {
				active = n.Network
			}
		}
		if active != "testnet4" {
			t.Fatalf("active network = %q, want testnet4", active)
		}
		// Clear it.
		if _, err := svc.NetworkUse(ctx, domain.LocalCLI(), ""); err != nil {
			t.Fatalf("NetworkUse(clear): %v", err)
		}
		done()
	}

	// Cleared: back to unresolved.
	{
		svc, done := openNet(t, dir, "", "", cfg, nil)
		if svc.net != "" {
			t.Fatalf("net after clear = %q, want unresolved", svc.net)
		}
		done()
	}
}

// TestAgnosticCreateWithoutNetworkSucceeds proves an agnostic `wallet create` with
// NO resolved network still succeeds (both coin_type chains materialized), rendering
// no per-network sample address. A --bind create with no network must fail.
func TestAgnosticCreateWithoutNetworkSucceeds(t *testing.T) {
	dir := t.TempDir()
	cfg := t.TempDir()
	ctx := context.Background()

	env := map[string]string{
		"DAXIB_PASSPHRASE":         "test-pass-12345678",
		"DAXIB_PASSPHRASE_CONFIRM": "test-pass-12345678",
	}
	svc, done := openNet(t, dir, "", "", cfg, env)
	defer done()

	res, err := svc.WalletCreate(ctx, domain.LocalCLI(), domain.WalletCreateRequest{Name: "agno", Words: 12}, WalletCreateInput{})
	if err != nil {
		t.Fatalf("agnostic create with no network: %v", err)
	}
	if res.Scope != "agnostic" {
		t.Errorf("scope = %q, want agnostic", res.Scope)
	}
	if res.Receive0Address != "" || res.Receive0 != "" {
		t.Errorf("expected NO per-network sample address, got ref=%q addr=%q", res.Receive0, res.Receive0Address)
	}
	if res.Network != "" {
		t.Errorf("display network = %q, want empty", res.Network)
	}

	// A --bind create with no network is usage.network_required.
	_, berr := svc.WalletCreate(ctx, domain.LocalCLI(), domain.WalletCreateRequest{Name: "bound", Words: 12, Bind: true}, WalletCreateInput{})
	if berr == nil {
		t.Fatal("bind create with no network: expected usage.network_required")
	}
	if c := code(t, berr); c != domain.CodeNetworkRequired {
		t.Fatalf("bind create code = %q, want %q", c, domain.CodeNetworkRequired)
	}
}
