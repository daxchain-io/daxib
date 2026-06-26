package config

import (
	"context"
	"path/filepath"
	"testing"
)

func TestAnchorReadWriteRoundTrip(t *testing.T) {
	dir := t.TempDir()
	ar, err := OpenAnchor(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Pre-bootstrap: absent anchor is (nil, false, nil), never an error.
	raw, found, err := ar.ReadAnchor(ctx)
	if err != nil || found || raw != nil {
		t.Fatalf("absent anchor: raw=%v found=%v err=%v; want nil,false,nil", raw, found, err)
	}

	want := []byte(`{"verify_key":"ed25519:AAAA","nonce_watermark":1}`)
	if err := ar.WriteAnchor(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, found, err := ar.ReadAnchor(ctx)
	if err != nil || !found {
		t.Fatalf("read after write: found=%v err=%v", found, err)
	}
	if string(got) != string(want) {
		t.Fatalf("round-trip mismatch: %s != %s", got, want)
	}
	if ar.Path() != filepath.Join(dir, "policy-anchor.json") {
		t.Fatalf("anchor path = %s; want <dir>/policy-anchor.json", ar.Path())
	}
}

// TestAnchorCarveOut pins the §4.6 isolation: NO DAXIB_POLICY_* env var (and no
// flag, which the config package never reads anyway) can change which file the
// anchor is read from or synthesize anchor contents. The anchor path is a pure join
// of the config dir + the fixed file name; a compromised agent setting
// DAXIB_POLICY_VERIFY_KEY in its own environment gains nothing.
func TestAnchorCarveOut(t *testing.T) {
	dir := t.TempDir()

	// An agent tries to inject a verify key / redirect the anchor through env.
	t.Setenv("DAXIB_POLICY_VERIFY_KEY", "ed25519:ATTACKER")
	t.Setenv("DAXIB_POLICY_ANCHOR", filepath.Join(t.TempDir(), "attacker-anchor.json"))
	t.Setenv("DAXIB_POLICY_MAX_TX", "100000000")
	t.Setenv("DAXIB_POLICY_NONCE_WATERMARK", "0")

	ar, err := OpenAnchor(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Path isolation: the env-injected path does NOT leak in.
	if ar.Path() != filepath.Join(dir, "policy-anchor.json") {
		t.Fatalf("env must not change the anchor path; got %s", ar.Path())
	}

	// Content isolation: with no on-disk anchor, ReadAnchor returns not-found
	// regardless of env — the attacker's verify key does NOT synthesize an anchor.
	raw, found, err := ar.ReadAnchor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if found || raw != nil {
		t.Fatalf("env-injected anchor must NOT materialize; got found=%v raw=%s", found, raw)
	}
}
