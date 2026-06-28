package service

import (
	"context"
	"testing"

	fakebackend "github.com/daxchain-io/daxib/internal/backend/fake"
	"github.com/daxchain-io/daxib/internal/domain"
)

// TestConfigGetSetRoundtrip is the config noun round-trip: set
// networks.mainnet.default-backend, read it back via get + list, then clear it.
// It also asserts the policy.* rejection (the sealed-anchor carve-out) and the
// unknown-key / unknown-backend error paths.
func TestConfigGetSetRoundtrip(t *testing.T) {
	// newSendService registers backend "fake-x" on mainnet and selects it, so the
	// default-backend key starts at "fake-x".
	svc, done := newSendService(t, fakebackend.New())
	defer done()
	ctx := context.Background()

	const key = "networks.mainnet.default-backend"

	// Get reflects the BackendUse selection from setup.
	got, err := svc.ConfigGet(ctx, domain.LocalCLI(), domain.ConfigGetRequest{Key: key})
	if err != nil {
		t.Fatalf("ConfigGet: %v", err)
	}
	if got.Value != "fake-x" {
		t.Fatalf("initial %s = %q; want fake-x", key, got.Value)
	}

	// Clearing the default (empty value) is allowed and round-trips.
	if _, err := svc.ConfigSet(ctx, domain.LocalCLI(), domain.ConfigSetRequest{Key: key, Value: ""}); err != nil {
		t.Fatalf("ConfigSet clear: %v", err)
	}
	got, _ = svc.ConfigGet(ctx, domain.LocalCLI(), domain.ConfigGetRequest{Key: key})
	if got.Value != "" {
		t.Fatalf("after clear %s = %q; want empty", key, got.Value)
	}

	// Re-setting it to the existing mainnet backend round-trips.
	if _, err := svc.ConfigSet(ctx, domain.LocalCLI(), domain.ConfigSetRequest{Key: key, Value: "fake-x"}); err != nil {
		t.Fatalf("ConfigSet fake-x: %v", err)
	}
	got, _ = svc.ConfigGet(ctx, domain.LocalCLI(), domain.ConfigGetRequest{Key: key})
	if got.Value != "fake-x" {
		t.Fatalf("after set %s = %q; want fake-x", key, got.Value)
	}

	// List includes the key with its effective value + source "file".
	list, err := svc.ConfigList(ctx, domain.LocalCLI())
	if err != nil {
		t.Fatalf("ConfigList: %v", err)
	}
	var found bool
	for _, kv := range list.Entries {
		if kv.Key == key {
			found = true
			if kv.Value != "fake-x" || kv.Source != "file" {
				t.Errorf("list %s = %q (source %q); want fake-x/file", key, kv.Value, kv.Source)
			}
		}
	}
	if !found {
		t.Fatalf("list %+v missing %s", list.Entries, key)
	}

	// Setting to a non-existent backend is a not_found (exit 10).
	if _, err := svc.ConfigSet(ctx, domain.LocalCLI(), domain.ConfigSetRequest{Key: key, Value: "ghost"}); err == nil {
		t.Fatal("ConfigSet ghost: want error, got nil")
	} else if de := domain.AsError(err); de.Exit != domain.ExitNotFound {
		t.Errorf("ghost exit=%d; want %d (not_found)", de.Exit, domain.ExitNotFound)
	}

	// A policy.* key is rejected on BOTH get and set (the sealed-anchor carve-out).
	if _, err := svc.ConfigSet(ctx, domain.LocalCLI(), domain.ConfigSetRequest{Key: "policy.max-tx", Value: "100000"}); err == nil {
		t.Fatal("ConfigSet policy.max-tx: want rejection, got nil")
	} else if de := domain.AsError(err); de.Exit != domain.ExitUsage {
		t.Errorf("policy-set exit=%d; want %d (usage)", de.Exit, domain.ExitUsage)
	}
	if _, err := svc.ConfigGet(ctx, domain.LocalCLI(), domain.ConfigGetRequest{Key: "policy.max-tx"}); err == nil {
		t.Fatal("ConfigGet policy.max-tx: want rejection, got nil")
	} else if de := domain.AsError(err); de.Exit != domain.ExitUsage {
		t.Errorf("policy-get exit=%d; want %d (usage)", de.Exit, domain.ExitUsage)
	}

	// An unknown key is ref.not_found (exit 10).
	if _, err := svc.ConfigGet(ctx, domain.LocalCLI(), domain.ConfigGetRequest{Key: "no.such.key"}); err == nil {
		t.Fatal("ConfigGet unknown: want not_found, got nil")
	} else if de := domain.AsError(err); de.Exit != domain.ExitNotFound {
		t.Errorf("unknown-key exit=%d; want %d (not_found)", de.Exit, domain.ExitNotFound)
	}

	// CFG-GET-1: a WELL-SHAPED key naming a non-existent network must be ref.not_found
	// on get (exit 10) — get and set must agree (set already rejects it). A typo'd
	// network ("signett") and a garbage network must NOT silently return "" with exit 0.
	for _, badKey := range []string{
		"networks.signett.default-backend", // a near-miss typo of "signet"
		"networks.bogusnet.default-backend",
	} {
		if _, err := svc.ConfigGet(ctx, domain.LocalCLI(), domain.ConfigGetRequest{Key: badKey}); err == nil {
			t.Fatalf("ConfigGet %q: want not_found, got nil (GET/SET asymmetry)", badKey)
		} else if de := domain.AsError(err); de.Exit != domain.ExitNotFound {
			t.Errorf("bad-network-get %q exit=%d; want %d (not_found)", badKey, de.Exit, domain.ExitNotFound)
		}
	}
}
