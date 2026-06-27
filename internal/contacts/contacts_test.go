package contacts

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/daxchain-io/daxib/internal/domain"
)

// TestStoreRoundtrip exercises the address-book store directly: add → resolve →
// list → remove, plus the name-grammar + duplicate + not-found error paths. The
// store validates only the NAME (the service validates the address), so a raw
// non-address string is a fine address here.
func TestStoreRoundtrip(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx := context.Background()

	if _, err := s.Add(ctx, Contact{Name: "Alice", Address: "addr-a", Network: "mainnet"}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Resolve is case-insensitive and returns the pinned address.
	c, found, err := s.Resolve(ctx, "alice")
	if err != nil || !found {
		t.Fatalf("Resolve: found=%v err=%v", found, err)
	}
	if c.Address != "addr-a" {
		t.Errorf("resolved address=%q; want addr-a", c.Address)
	}

	// A non-existent name resolves as not-found WITHOUT an error (fall-through).
	if _, found, err := s.Resolve(ctx, "nobody"); found || err != nil {
		t.Errorf("Resolve(nobody): found=%v err=%v; want false/nil", found, err)
	}
	// A grammar-invalid input (an address-like string with '/') is not a contact —
	// fall-through, no error.
	if _, found, err := s.Resolve(ctx, "bc1q.../weird"); found || err != nil {
		t.Errorf("Resolve(bad grammar): found=%v err=%v; want false/nil", found, err)
	}

	// Duplicate (case-insensitive) is a usage error.
	if _, err := s.Add(ctx, Contact{Name: "ALICE", Address: "addr-b"}); err == nil {
		t.Fatal("Add duplicate: want error, got nil")
	} else if de := domain.AsError(err); de.Exit != domain.ExitUsage {
		t.Errorf("duplicate exit=%d; want %d", de.Exit, domain.ExitUsage)
	}

	// A bad name grammar is a usage error.
	if _, err := s.Add(ctx, Contact{Name: "bad/name", Address: "x"}); err == nil {
		t.Fatal("Add bad name: want error, got nil")
	}

	if _, err := s.Add(ctx, Contact{Name: "carol", Address: "addr-c"}); err != nil {
		t.Fatalf("Add carol: %v", err)
	}
	list, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 || list[0].Name != "alice" || list[1].Name != "carol" {
		t.Fatalf("List = %+v; want name-sorted [alice carol]", list)
	}

	if _, err := s.Remove(ctx, "alice"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := s.Show(ctx, "alice"); err == nil {
		t.Fatal("Show after remove: want not_found")
	} else if de := domain.AsError(err); de.Exit != domain.ExitNotFound {
		t.Errorf("not-found exit=%d; want %d", de.Exit, domain.ExitNotFound)
	}
}

// TestSchemaVersionGuard proves a file written by a newer binary (higher version)
// is refused (fail closed).
func TestSchemaVersionGuard(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, fileName), []byte(`{"v":999,"contacts":[]}`), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	s, _ := Open(dir)
	if _, err := s.List(context.Background()); err == nil {
		t.Fatal("List on a future-version file: want refusal, got nil")
	}
}
