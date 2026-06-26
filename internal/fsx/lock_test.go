package fsx

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestLockSiblingFilename asserts the on-disk lock object is the sibling
// "<path>.lock" (never the data file itself).
func TestLockSiblingFilename(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "index")
	unlock, err := Lock(context.Background(), base)
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	defer unlock()
	if _, err := os.Stat(base + ".lock"); err != nil {
		t.Errorf("expected sibling lock %q to exist: %v", base+".lock", err)
	}
}

// TestLockExclusive asserts a second exclusive acquire blocks until ctx expiry
// and returns the ctx error (callers map this to state.lock_timeout / exit 11).
func TestLockExclusive(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "index")

	unlock, err := Lock(context.Background(), base)
	if err != nil {
		t.Fatalf("first Lock: %v", err)
	}
	defer unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = Lock(ctx, base)
	if err == nil {
		t.Fatal("second Lock succeeded while the first is held")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want context.DeadlineExceeded", err)
	}
	if time.Since(start) < 40*time.Millisecond {
		t.Errorf("second Lock returned too fast (%v); it should wait for ctx", time.Since(start))
	}
}

// TestUnlockIdempotent asserts the returned unlock is safe to call more than
// once and releases the lock so a later acquire succeeds.
func TestUnlockIdempotent(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "index")
	unlock, err := Lock(context.Background(), base)
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	unlock()
	unlock() // second call must not panic

	// The lock is free now; re-acquire must succeed quickly.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	u2, err := Lock(ctx, base)
	if err != nil {
		t.Fatalf("re-Lock after unlock: %v", err)
	}
	u2()
}
