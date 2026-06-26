package config

import (
	"context"
	"errors"
	"testing"

	"github.com/daxchain-io/daxib/internal/domain"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir()) // Open takes the config DIRECTORY; it joins config.toml inside
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

// TestRoundTrip proves an endpoint survives add -> list -> use -> get, the default
// marker tracks, and remove clears the default.
func TestRoundTrip(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	_, err := s.AddEndpoint(ctx, "localcore", Endpoint{
		Network:    string(domain.NetworkRegtest),
		Type:       string(domain.BackendCore),
		URLRef:     "http://127.0.0.1:18443",
		RPCUserRef: "x",
		RPCPassRef: "${env:DAXIB_RPCPASS}",
	}, false)
	if err != nil {
		t.Fatalf("AddEndpoint: %v", err)
	}

	views, err := s.ListEndpoints("")
	if err != nil {
		t.Fatalf("ListEndpoints: %v", err)
	}
	if len(views) != 1 || views[0].Name != "localcore" || views[0].Default {
		t.Fatalf("list = %+v, want one non-default localcore", views)
	}

	network, err := s.UseEndpoint(ctx, "localcore")
	if err != nil {
		t.Fatalf("UseEndpoint: %v", err)
	}
	if network != string(domain.NetworkRegtest) {
		t.Fatalf("UseEndpoint network = %q, want regtest", network)
	}
	def, _ := s.DefaultForNetwork(string(domain.NetworkRegtest))
	if def != "localcore" {
		t.Fatalf("default = %q, want localcore", def)
	}

	// The stored refs are RAW (unresolved) so the service resolves them at dial.
	ep, err := s.GetEndpoint("localcore")
	if err != nil {
		t.Fatalf("GetEndpoint: %v", err)
	}
	if ep.RPCPassRef != "${env:DAXIB_RPCPASS}" {
		t.Fatalf("rpcpassword stored = %q, want the RAW ref", ep.RPCPassRef)
	}

	clearedFor, err := s.RemoveEndpoint(ctx, "localcore")
	if err != nil {
		t.Fatalf("RemoveEndpoint: %v", err)
	}
	if clearedFor != string(domain.NetworkRegtest) {
		t.Fatalf("clearedFor = %q, want regtest", clearedFor)
	}
	if def, _ := s.DefaultForNetwork(string(domain.NetworkRegtest)); def != "" {
		t.Fatalf("default after remove = %q, want empty", def)
	}
}

// TestAddDuplicate proves a duplicate name is backend.exists (exit 2).
func TestAddDuplicate(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ep := Endpoint{Network: "mainnet", Type: "esplora", URLRef: "https://mempool.space/api"}
	if _, err := s.AddEndpoint(ctx, "m", ep, false); err != nil {
		t.Fatalf("first add: %v", err)
	}
	_, err := s.AddEndpoint(ctx, "m", ep, false)
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != domain.CodeBackendExists {
		t.Fatalf("dup add err = %v, want backend.exists", err)
	}
}

// TestGetUnknown proves an unknown name is backend.not_found (exit 10).
func TestGetUnknown(t *testing.T) {
	s := newStore(t)
	_, err := s.GetEndpoint("nope")
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != domain.CodeBackendNotFound {
		t.Fatalf("err = %v, want backend.not_found", err)
	}
	if de.Exit != domain.ExitNotFound {
		t.Fatalf("exit = %d, want %d", de.Exit, domain.ExitNotFound)
	}
}

// TestResolveSecretRefs proves ${env:} resolution + the missing-var error +
// the literal/escape passthrough.
func TestResolveSecretRefs(t *testing.T) {
	env := map[string]string{"DAXIB_RPCPASS": "hunter2"}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }

	got, err := ResolveSecretRefs("${env:DAXIB_RPCPASS}", lookup)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != "hunter2" {
		t.Fatalf("resolved = %q, want hunter2", got)
	}

	// A missing var is secret.unresolved (exit 4 AUTH).
	_, err = ResolveSecretRefs("${env:DAXIB_MISSING}", lookup)
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != "secret.unresolved" {
		t.Fatalf("missing-var err = %v, want secret.unresolved", err)
	}
	if de.Exit != domain.ExitAuth {
		t.Fatalf("exit = %d, want %d (auth)", de.Exit, domain.ExitAuth)
	}

	// A plain literal passes through; the $${ escape becomes ${.
	if v, _ := ResolveSecretRefs("plain", lookup); v != "plain" {
		t.Fatalf("literal = %q, want plain", v)
	}
	if v, _ := ResolveSecretRefs("$${env:X}", lookup); v != "${env:X}" {
		t.Fatalf("escape = %q, want ${env:X}", v)
	}
}

// TestMaskKeepsRefDropsLiteral proves masking keeps a ${…} reference verbatim and
// reduces an embedded literal credential to "***".
func TestMaskKeepsRefDropsLiteral(t *testing.T) {
	if got := MaskSecretRefs("https://node/api?key=${env:KEY}"); got != "https://node/api?key=${env:KEY}" {
		t.Errorf("masking a ref changed it: %q", got)
	}
	got := MaskSecretRefs("https://node.example/v2/abcdef0123456789abcdef0123456789deadbeef")
	if got != "https://node.example/v2/***" {
		t.Errorf("literal secret not masked: %q", got)
	}
}

// TestAddLiteralSecretWarns proves a literal rpcpassword produces a warning (not a
// hard error) when strict is off.
func TestAddLiteralSecretWarns(t *testing.T) {
	s := newStore(t)
	warnings, err := s.AddEndpoint(context.Background(), "core1", Endpoint{
		Network: "regtest", Type: "core", URLRef: "http://127.0.0.1:18443",
		RPCPassRef: "literalpassword",
	}, false)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if len(warnings) == 0 {
		t.Fatal("expected a literal-secret warning")
	}
}

// TestAddLiteralSecretStrictFails proves --strict-secrets hard-fails on a literal.
func TestAddLiteralSecretStrictFails(t *testing.T) {
	s := newStore(t)
	_, err := s.AddEndpoint(context.Background(), "core1", Endpoint{
		Network: "regtest", Type: "core", URLRef: "http://127.0.0.1:18443",
		RPCPassRef: "literalpassword",
	}, true)
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != domain.CodeUsage+".literal_secret" {
		t.Fatalf("strict add err = %v, want usage.literal_secret", err)
	}
}
