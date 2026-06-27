package keys

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/secret"
)

// passphrase_test.go exercises the atomic keystore re-encryption (§3.8 parity):
// ChangePassphrase re-encrypts the verifier + EVERY wallet blob under a new
// passphrase, the old passphrase stops working after, the new unlocks all wallets,
// and a crash at any stage leaves a single-passphrase keystore (roll forward on a
// committed marker, roll back on orphaned .new files).

// seedTwoWallets creates a light keystore with two wallets under pass "old-pass".
func seedTwoWallets(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(context.Background(), Options{Dir: dir, Light: true})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx := context.Background()
	if _, err := s.CreateWallet(ctx, "alpha", 12, domain.NetworkMainnet, false, pass("old-pass"), pass("old-pass")); err != nil {
		t.Fatalf("CreateWallet alpha: %v", err)
	}
	if _, err := s.ImportWallet(ctx, "beta", domain.NetworkMainnet, false, secret.NewString(canonicalMnemonic), nil, pass("old-pass"), pass("old-pass")); err != nil {
		t.Fatalf("ImportWallet beta: %v", err)
	}
	return s, dir
}

// reopen reopens the keystore at dir (running Open's recovery + watermark checks).
func reopen(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := Open(context.Background(), Options{Dir: dir, Light: true})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestChangePassphraseRotatesEverything is the happy path: after rotation the OLD
// passphrase fails and the NEW unlocks BOTH wallets' mnemonics, and the verifier
// proves the new passphrase.
func TestChangePassphraseRotatesEverything(t *testing.T) {
	s, dir := seedTwoWallets(t)
	ctx := context.Background()

	n, err := s.ChangePassphrase(ctx, pass("old-pass"), pass("new-pass"))
	if err != nil {
		t.Fatalf("ChangePassphrase: %v", err)
	}
	if n != 3 { // verifier + 2 wallet blobs
		t.Fatalf("rotated %d files, want 3 (verifier + 2 wallets)", n)
	}

	s2 := reopen(t, dir)

	// OLD passphrase now fails on the verifier.
	if verr := s2.VerifyPassphrase(pass("old-pass")); verr == nil {
		t.Fatal("OLD passphrase still verifies after rotation")
	} else if code := codeOf(t, verr); code != CodeKeystoreBadPassphrase {
		t.Fatalf("OLD verify code=%s, want %s", code, CodeKeystoreBadPassphrase)
	}
	// NEW passphrase verifies.
	if verr := s2.VerifyPassphrase(pass("new-pass")); verr != nil {
		t.Fatalf("NEW passphrase does not verify: %v", verr)
	}
	// NEW passphrase exports BOTH wallets' mnemonics (each blob was re-encrypted).
	for _, name := range []string{"alpha", "beta"} {
		_, mn, _, eerr := s2.ExportWallet(ctx, name, pass("new-pass"))
		if eerr != nil {
			t.Fatalf("ExportWallet %q under NEW passphrase: %v", name, eerr)
		}
		mn.Zero()
		// OLD passphrase must NOT export.
		if _, _, _, oerr := s2.ExportWallet(ctx, name, pass("old-pass")); oerr == nil {
			t.Fatalf("ExportWallet %q under OLD passphrase succeeded after rotation", name)
		}
	}
}

// TestChangePassphraseRefusesOrphanBlob is the ROT-1 regression: a wallet blob on
// disk that meta.json does NOT list would be skipped by the meta-derived rotation
// set and silently stranded under the old passphrase. Rotation must instead fail
// closed (state.corrupt, exit 11) and stage nothing.
func TestChangePassphraseRefusesOrphanBlob(t *testing.T) {
	s, dir := seedTwoWallets(t)
	ctx := context.Background()

	// Plant an orphan blob: copy an existing wallet blob to a fresh uuid filename that
	// meta.json never records.
	walletsDir := filepath.Join(dir, "wallets")
	entries, err := os.ReadDir(walletsDir)
	if err != nil {
		t.Fatalf("ReadDir wallets: %v", err)
	}
	var srcBlob string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			srcBlob = filepath.Join(walletsDir, e.Name())
			break
		}
	}
	if srcBlob == "" {
		t.Fatal("no wallet blob to copy")
	}
	raw, err := os.ReadFile(srcBlob) //nolint:gosec // test-controlled path
	if err != nil {
		t.Fatalf("read blob: %v", err)
	}
	orphan := filepath.Join(walletsDir, "00000000-0000-0000-0000-000000000000.json")
	if werr := os.WriteFile(orphan, raw, 0o600); werr != nil {
		t.Fatalf("write orphan: %v", werr)
	}

	_, cerr := s.ChangePassphrase(ctx, pass("old-pass"), pass("new-pass"))
	if cerr == nil {
		t.Fatal("ChangePassphrase rotated a keystore with an orphan blob (want fail-closed)")
	}
	if code := codeOf(t, cerr); code != CodeStateCorrupt {
		t.Fatalf("orphan-blob code=%s, want %s", code, CodeStateCorrupt)
	}

	// Fail-closed means nothing committed: no staged artifacts, and the ORIGINAL
	// passphrase still opens the keystore.
	assertNoStaged(t, dir)
	s2 := reopen(t, dir)
	if verr := s2.VerifyPassphrase(pass("old-pass")); verr != nil {
		t.Fatalf("ORIGINAL passphrase broken after a refused rotation: %v", verr)
	}
}

// TestChangePassphraseWrongOldFails proves a wrong OLD passphrase rotates nothing
// (exit 4) and leaves the keystore openable under the original passphrase.
func TestChangePassphraseWrongOldFails(t *testing.T) {
	s, dir := seedTwoWallets(t)
	ctx := context.Background()

	_, err := s.ChangePassphrase(ctx, pass("WRONG-old"), pass("new-pass"))
	if err == nil {
		t.Fatal("ChangePassphrase accepted a wrong OLD passphrase")
	}
	if code := codeOf(t, err); code != CodeKeystoreBadPassphrase {
		t.Fatalf("wrong-old code=%s, want %s", code, CodeKeystoreBadPassphrase)
	}

	// No staged artifacts should remain, and the ORIGINAL passphrase still works.
	assertNoStaged(t, dir)
	s2 := reopen(t, dir)
	if verr := s2.VerifyPassphrase(pass("old-pass")); verr != nil {
		t.Fatalf("ORIGINAL passphrase broken after a failed rotation: %v", verr)
	}
}

// TestChangePassphraseCrashRollForward injects a crash right after the commit
// marker is written but before the swaps complete, then proves a reopen rolls
// FORWARD (the new passphrase unlocks everything; the old is dead; no marker left).
func TestChangePassphraseCrashRollForward(t *testing.T) {
	s, dir := seedTwoWallets(t)
	ctx := context.Background()

	withFault(t, "after_commit", func() {
		_, err := s.ChangePassphrase(ctx, pass("old-pass"), pass("new-pass"))
		if err == nil {
			t.Fatal("expected the injected fault to abort ChangePassphrase")
		}
	})

	// The marker should be present pre-recovery (commit happened, swaps did not).
	if _, statErr := os.Stat(filepath.Join(dir, rotateMarkerName)); statErr != nil {
		t.Fatalf("expected the commit marker on disk after the post-commit crash: %v", statErr)
	}

	// Reopen runs forward recovery.
	s2 := reopen(t, dir)
	assertNoStaged(t, dir)
	if _, statErr := os.Stat(filepath.Join(dir, rotateMarkerName)); statErr == nil {
		t.Fatal("commit marker survived forward recovery")
	}
	if verr := s2.VerifyPassphrase(pass("new-pass")); verr != nil {
		t.Fatalf("NEW passphrase does not verify after roll-forward: %v", verr)
	}
	if verr := s2.VerifyPassphrase(pass("old-pass")); verr == nil {
		t.Fatal("OLD passphrase still verifies after roll-forward")
	}
	for _, name := range []string{"alpha", "beta"} {
		_, mn, _, eerr := s2.ExportWallet(ctx, name, pass("new-pass"))
		if eerr != nil {
			t.Fatalf("ExportWallet %q after roll-forward: %v", name, eerr)
		}
		mn.Zero()
	}
}

// TestChangePassphraseCrashRollBack injects a crash mid-STAGE (before the commit
// marker), then proves a reopen rolls BACK: the OLD passphrase still unlocks
// everything and no staged artifacts survive.
func TestChangePassphraseCrashRollBack(t *testing.T) {
	s, dir := seedTwoWallets(t)
	ctx := context.Background()

	withFault(t, "before_commit", func() {
		_, err := s.ChangePassphrase(ctx, pass("old-pass"), pass("new-pass"))
		if err == nil {
			t.Fatal("expected the injected fault to abort ChangePassphrase")
		}
	})

	// No marker (we crashed before commit). The abort path already cleaned the
	// .new files; a reopen's rollback is idempotent.
	if _, statErr := os.Stat(filepath.Join(dir, rotateMarkerName)); statErr == nil {
		t.Fatal("a commit marker exists after a pre-commit crash")
	}
	s2 := reopen(t, dir)
	assertNoStaged(t, dir)

	// OLD passphrase still unlocks everything; NEW does not.
	if verr := s2.VerifyPassphrase(pass("old-pass")); verr != nil {
		t.Fatalf("OLD passphrase broken after roll-back: %v", verr)
	}
	if verr := s2.VerifyPassphrase(pass("new-pass")); verr == nil {
		t.Fatal("NEW passphrase verifies after a rolled-back rotation")
	}
	for _, name := range []string{"alpha", "beta"} {
		_, mn, _, eerr := s2.ExportWallet(ctx, name, pass("old-pass"))
		if eerr != nil {
			t.Fatalf("ExportWallet %q after roll-back: %v", name, eerr)
		}
		mn.Zero()
	}
}

// TestChangePassphraseStagedOrphanRollback drops a bare orphaned .new file (no
// marker) into the keystore and proves Open's recovery deletes it (an interrupted
// STAGE that never committed).
func TestChangePassphraseStagedOrphanRollback(t *testing.T) {
	_, dir := seedTwoWallets(t)
	orphan := filepath.Join(dir, "keystore.json"+stagedSuffix)
	if err := os.WriteFile(orphan, []byte("{}"), 0o600); err != nil {
		t.Fatalf("writing orphan: %v", err)
	}
	_ = reopen(t, dir)
	if _, statErr := os.Stat(orphan); statErr == nil {
		t.Fatal("orphaned .new survived rollback recovery")
	}
}

// TestKeystoreInfo reports the path, format, KDF, and wallet count without unlock.
func TestKeystoreInfo(t *testing.T) {
	s, dir := seedTwoWallets(t)
	info, err := s.KeystoreInfo(context.Background())
	if err != nil {
		t.Fatalf("KeystoreInfo: %v", err)
	}
	if info.Path != dir {
		t.Errorf("path = %q, want %q", info.Path, dir)
	}
	if !info.Initialized {
		t.Error("Initialized = false, want true")
	}
	if info.Wallets != 2 {
		t.Errorf("wallets = %d, want 2", info.Wallets)
	}
	if info.KDF != kdfName {
		t.Errorf("kdf = %q, want %q", info.KDF, kdfName)
	}
	if info.ScryptN != lightScryptN {
		t.Errorf("scrypt N = %d, want lightScryptN %d", info.ScryptN, lightScryptN)
	}
}

// withFault installs faultHook for the duration of fn at the named point, then
// clears it.
func withFault(t *testing.T, point string, fn func()) {
	t.Helper()
	faultHook = func(p string) error {
		if p == point {
			return errKeys(CodeStateCorrupt, "injected fault at "+p)
		}
		return nil
	}
	defer func() { faultHook = nil }()
	fn()
}

// assertNoStaged fails if any ".new" staged file remains under the keystore dir or
// its wallets/ subdir.
func assertNoStaged(t *testing.T, dir string) {
	t.Helper()
	for _, d := range []string{dir, filepath.Join(dir, "wallets")} {
		entries, err := os.ReadDir(d)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("ReadDir %s: %v", d, err)
		}
		for _, e := range entries {
			if filepath.Ext(e.Name()) == stagedSuffix {
				t.Errorf("staged file survived: %s", filepath.Join(d, e.Name()))
			}
		}
	}
}
