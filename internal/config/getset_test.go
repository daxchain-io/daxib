package config

import (
	"context"
	"errors"
	"testing"

	"github.com/daxchain-io/daxib/internal/domain"
)

// TestDefaultsNetworkRoundTrip proves the defaults.network key (GAP-3) survives
// set -> get -> DefaultNetwork() -> list, validates the value, and clears to "".
func TestDefaultsNetworkRoundTrip(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	// Unset: get is "", DefaultNetwork() is "".
	if v, err := s.GetKey(defaultsNetworkKey); err != nil || v != "" {
		t.Fatalf("get unset defaults.network = (%q,%v), want (\"\",nil)", v, err)
	}
	if v, err := s.DefaultNetwork(); err != nil || v != "" {
		t.Fatalf("DefaultNetwork() unset = (%q,%v), want (\"\",nil)", v, err)
	}

	// Set to a valid network.
	if err := s.SetKey(ctx, defaultsNetworkKey, "signet"); err != nil {
		t.Fatalf("set defaults.network=signet: %v", err)
	}
	if v, err := s.GetKey(defaultsNetworkKey); err != nil || v != "signet" {
		t.Fatalf("get defaults.network = (%q,%v), want (signet,nil)", v, err)
	}
	if v, err := s.DefaultNetwork(); err != nil || v != "signet" {
		t.Fatalf("DefaultNetwork() = (%q,%v), want (signet,nil)", v, err)
	}

	// It appears in the list with source "file".
	kvs, err := s.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	var found bool
	for _, kv := range kvs {
		if kv.Key == defaultsNetworkKey {
			found = true
			if kv.Value != "signet" || kv.Source != "file" {
				t.Errorf("list defaults.network = {%q,%q}, want {signet,file}", kv.Value, kv.Source)
			}
		}
	}
	if !found {
		t.Errorf("defaults.network missing from ListKeys output")
	}

	// Empty clears it.
	if err := s.SetKey(ctx, defaultsNetworkKey, ""); err != nil {
		t.Fatalf("clear defaults.network: %v", err)
	}
	if v, err := s.DefaultNetwork(); err != nil || v != "" {
		t.Fatalf("DefaultNetwork() after clear = (%q,%v), want (\"\",nil)", v, err)
	}
}

// TestDefaultsNetworkRejectsBadValue proves a non-network value is a usage error.
func TestDefaultsNetworkRejectsBadValue(t *testing.T) {
	s := newStore(t)
	err := s.SetKey(context.Background(), defaultsNetworkKey, "bogusnet")
	if err == nil {
		t.Fatal("set defaults.network=bogusnet: expected an error")
	}
	var de *domain.Error
	if !errors.As(err, &de) || de.Exit != domain.ExitUsage {
		t.Fatalf("set bad defaults.network err = %v, want usage (exit 2)", err)
	}
}
