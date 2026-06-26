package keys

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/daxchain-io/daxib/internal/domain"
)

// TestDerivationWatermarkTripwire asserts that Open fails closed with
// keystore.derivation_watermark when meta.json's next_receive is below a
// materialized receive index — the restore-coupling tripwire (§3.4). This
// simulates a keystore restored without its derivation watermark.
func TestDerivationWatermarkTripwire(t *testing.T) {
	s := openLight(t)
	ctx := context.Background()
	if _, err := s.CreateWallet(ctx, "vec", 12, domain.NetworkMainnet, pass("pw"), pass("pw")); err != nil {
		t.Fatalf("CreateWallet: %v", err)
	}
	// Derive a couple more receive addresses so indices 0,1,2 are materialized and
	// next_receive == 3.
	for i := 0; i < 2; i++ {
		if _, err := s.DeriveNext(ctx, "vec", domain.BranchReceive); err != nil {
			t.Fatalf("DeriveNext: %v", err)
		}
	}
	dir := s.dir
	_ = s.Close()

	// Corrupt meta.json: rewind next_receive below the highest materialized index
	// (2), so the watermark invariant (next > every index) is violated.
	metaPath := filepath.Join(dir, "meta.json")
	raw, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("read meta: %v", err)
	}
	var m metaFile
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal meta: %v", err)
	}
	for _, w := range m.Wallets {
		w.NextReceive = 1 // but indices 0,1,2 are materialized -> inconsistent
	}
	out, err := json.MarshalIndent(&m, "", "  ")
	if err != nil {
		t.Fatalf("marshal meta: %v", err)
	}
	if err := os.WriteFile(metaPath, out, 0o600); err != nil {
		t.Fatalf("write meta: %v", err)
	}

	// Reopening must fail closed with the watermark code.
	_, err = Open(ctx, Options{Dir: dir, Light: true})
	if got := codeOf(t, err); got != CodeKeystoreDerivationWatermark {
		t.Fatalf("watermark-tripwire code = %q, want %q", got, CodeKeystoreDerivationWatermark)
	}
}
