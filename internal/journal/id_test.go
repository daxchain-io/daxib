package journal

import (
	"bytes"
	"sort"
	"testing"
	"time"
)

// TestULIDDeterministicWithStubbedEntropy swaps randReader + nowFn and asserts a
// fixed ULID string, then checks lexicographic sortability (a later-timestamp ULID
// sorts after an earlier one — so a string sort on `id` is a time sort).
func TestULIDDeterministicWithStubbedEntropy(t *testing.T) {
	origRand, origNow := randReader, nowFn
	defer func() { randReader, nowFn = origRand, origNow }()

	// Fixed entropy (10 bytes of 0x00) and a fixed timestamp.
	randReader = bytes.NewReader(make([]byte, 10))
	fixed := time.Date(2026, 6, 26, 0, 0, 0, 0, time.UTC)
	nowFn = func() time.Time { return fixed }

	id1, err := newULID()
	if err != nil {
		t.Fatalf("newULID: %v", err)
	}
	if len(id1) != ulidLen {
		t.Fatalf("ULID len=%d, want %d", len(id1), ulidLen)
	}
	// Deterministic with the same inputs.
	randReader = bytes.NewReader(make([]byte, 10))
	id1again, _ := newULID()
	if id1 != id1again {
		t.Errorf("ULID not deterministic with stubbed entropy: %q vs %q", id1, id1again)
	}

	// A later timestamp must sort lexicographically after an earlier one.
	earlier, _ := newULIDAt(fixed)
	later, _ := newULIDAt(fixed.Add(time.Hour))
	ids := []string{later, earlier}
	sort.Strings(ids)
	if ids[0] != earlier {
		t.Errorf("ULID lexicographic sort is not a time sort: earlier=%q later=%q sorted=%v", earlier, later, ids)
	}
}

// TestULIDEntropyFailureSurfaces proves a read error from the entropy source
// surfaces (so Append fails rather than writing a low-entropy/empty id).
func TestULIDEntropyFailureSurfaces(t *testing.T) {
	origRand := randReader
	defer func() { randReader = origRand }()
	randReader = bytes.NewReader(nil) // EOF on the first read
	if _, err := newULID(); err == nil {
		t.Fatalf("expected an entropy-read error")
	}
}
