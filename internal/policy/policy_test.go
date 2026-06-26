package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/policyseal"
	"github.com/daxchain-io/daxib/internal/secret"
)

// lightParams keeps the admin KDF cheap in tests (production is N=2^17).
var lightParams = policyseal.ScryptParams{N: 1 << 4, R: 8, P: 1}

// testEngine builds an engine rooted at a temp state dir, bootstraps the anchor
// under adminPass, and returns the engine + the in-memory anchor. The engine's KDF
// cost is forced cheap by swapping DefaultScryptParams via a fresh InitSeal that we
// re-do here with light params (InitSeal uses DefaultScryptParams, so we bootstrap
// manually for speed).
func testEngine(t *testing.T, adminPass string, self []string) (*Engine, func() time.Time) {
	t.Helper()
	dir := t.TempDir()
	clk := fixedClock()
	// Manual bootstrap with light params (mirrors InitSeal but cheaper).
	salt, err := policyseal.NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	sk, pk, err := policyseal.DeriveSealKey([]byte(adminPass), salt, lightParams)
	if err != nil {
		t.Fatal(err)
	}
	anchor := policyseal.Anchor{
		VerifyKey:      policyseal.EncodeKey(pk),
		Salt:           policyseal.EncodeSalt(salt),
		Scrypt:         lightParams,
		NonceWatermark: 0,
	}
	eng, err := Open(dir, anchor, true, clk)
	if err != nil {
		t.Fatal(err)
	}
	body := defaultPolicy("test")
	body.Nonce = 1
	body.SelfAddresses = sortedLower(self)
	if werr := eng.sealAndWriteWith(sk, body); werr != nil {
		t.Fatal(werr)
	}
	eng.anchor.NonceWatermark = 1
	zeroKey(sk)
	return eng, clk
}

func fixedClock() func() time.Time {
	now := time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return now }
}

// setLimits applies a Set under the admin passphrase.
func setLimits(t *testing.T, eng *Engine, adminPass string, def *Limits) {
	t.Helper()
	pass := secret.NewString(adminPass)
	defer pass.Zero()
	if _, err := eng.Set(pass, Change{Default: def, WrittenBy: "test"}); err != nil {
		t.Fatalf("Set: %v", err)
	}
}

func satPtr(s string) *string { return &s }
func boolPtr(b bool) *bool    { return &b }

// ── seal / anchor / discrimination ───────────────────────────────────────────

func TestSealRoundTripAndShow(t *testing.T) {
	eng, _ := testEngine(t, "admin", nil)
	_, st, err := eng.Show()
	if err != nil {
		t.Fatal(err)
	}
	if !st.Present || !st.Verified {
		t.Fatalf("seal status = %+v; want present+verified", st)
	}
}

func TestTamperedBodyFailsVerify(t *testing.T) {
	eng, _ := testEngine(t, "admin", nil)
	// Flip a byte inside the stored envelope's body — the seal must fail.
	path := eng.policyPath()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Mutate a byte in the middle of the file (inside body_b64).
	raw[len(raw)/2] ^= 0x01
	if werr := os.WriteFile(path, raw, 0o600); werr != nil {
		t.Fatal(werr)
	}
	_, _, err = eng.Show()
	if got := domain.AsError(err).Code; got != codeSealViolation {
		t.Fatalf("tampered body: code=%s want %s", got, codeSealViolation)
	}
}

func TestWrongAdminPassphraseIsAdminAuth(t *testing.T) {
	eng, _ := testEngine(t, "correct-admin", nil)
	pass := secret.NewString("WRONG-admin")
	defer pass.Zero()
	_, err := eng.Set(pass, Change{Default: &Limits{MaxTxSat: satPtr("100")}, WrittenBy: "x"})
	if got := domain.AsError(err).Code; got != codeAdminAuth {
		t.Fatalf("wrong passphrase: code=%s want %s (NOT seal_violation)", got, codeAdminAuth)
	}
	if exit := domain.AsError(err).Exit; exit != domain.ExitAuth {
		t.Fatalf("admin_auth exit = %d want %d", exit, domain.ExitAuth)
	}
}

func TestValidPassphraseCorruptSigIsSealViolation(t *testing.T) {
	eng, _ := testEngine(t, "admin", nil)
	// Corrupt the seal signature (not the body) — the correct passphrase derives the
	// pinned key, but the on-disk seal no longer verifies ⇒ seal_violation.
	path := eng.policyPath()
	raw, _ := os.ReadFile(path)
	// Find the "sig":"..." and flip a base64 char inside it.
	s := string(raw)
	idx := indexOf(s, `"sig":"`)
	if idx < 0 {
		t.Fatal("no sig field")
	}
	pos := idx + len(`"sig":"`) + 2
	if raw[pos] == 'A' {
		raw[pos] = 'B'
	} else {
		raw[pos] = 'A'
	}
	_ = os.WriteFile(path, raw, 0o600)

	pass := secret.NewString("admin")
	defer pass.Zero()
	_, err := eng.Set(pass, Change{Default: &Limits{MaxTxSat: satPtr("100")}, WrittenBy: "x"})
	if got := domain.AsError(err).Code; got != codeSealViolation {
		t.Fatalf("corrupt sig: code=%s want %s", got, codeSealViolation)
	}
}

func TestNonceRollbackRefused(t *testing.T) {
	eng, _ := testEngine(t, "admin", nil)
	// Advance the policy a few times so its nonce climbs and the watermark with it.
	setLimits(t, eng, "admin", &Limits{MaxTxSat: satPtr("100")})
	setLimits(t, eng, "admin", &Limits{MaxTxSat: satPtr("200")})

	// Snapshot the now-current policy.json (a validly-sealed file with the high
	// nonce), then bump the anchor watermark above it (simulating a later tighten),
	// then verify the engine refuses the older file.
	current, _ := os.ReadFile(eng.policyPath())
	_ = current

	// Build a fresh engine whose anchor watermark is ABOVE the file's nonce.
	_, st, err := eng.Show()
	if err != nil {
		t.Fatal(err)
	}
	highWatermark := st.Nonce + 5
	rolled := eng.anchor
	rolled.NonceWatermark = highWatermark
	eng2, err := Open(eng.dir, rolled, true, eng.clock)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = eng2.Show()
	if got := domain.AsError(err).Code; got != codeRollback {
		t.Fatalf("rollback: code=%s want %s", got, codeRollback)
	}
}

func TestAnchorPresentPolicyMissingIsSealViolation(t *testing.T) {
	eng, _ := testEngine(t, "admin", nil)
	if err := os.Remove(eng.policyPath()); err != nil {
		t.Fatal(err)
	}
	_, _, err := eng.Show()
	if got := domain.AsError(err).Code; got != codeSealViolation {
		t.Fatalf("anchor+no-policy: code=%s want %s", got, codeSealViolation)
	}
}

func TestNoAnchorNoPolicyIsPermissive(t *testing.T) {
	dir := t.TempDir()
	eng, err := Open(dir, policyseal.Anchor{}, false, fixedClock())
	if err != nil {
		t.Fatal(err)
	}
	// Reserve must be permissive (no-op) with no policy.
	res, rerr := eng.Reserve(context.Background(), Check{Network: "regtest", Recipient: "x", AmountSat: 1, FeeSat: 1})
	if rerr != nil {
		t.Fatalf("permissive reserve errored: %v", rerr)
	}
	if !res.noop {
		t.Fatal("expected a no-op reservation with no policy")
	}
}

func TestUnknownBodyFieldIsVersionRefusal(t *testing.T) {
	eng, _ := testEngine(t, "admin", nil)
	// Re-seal a body that contains an unknown field. We craft the envelope manually
	// using the engine's key (derive it the same way) so the SEAL is valid but the
	// strict decode rejects the unknown field ⇒ version refusal.
	salt, _ := eng.anchor.SaltBytes()
	sk, _, err := policyseal.DeriveSealKey([]byte("admin"), salt, eng.anchor.Scrypt)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"version":1,"nonce":2,"updated_at":"","written_by":"x","rules":{"default":{"max_tx_sat":null,"max_day_sat":null,"max_fee_rate_sat_vb":null,"allowlist_enabled":true,"include_self":true},"networks":[]},"allowlist":[],"denylist":[],"self_addresses":[],"BOGUS":1}`)
	sig := policyseal.Sign(body, sk)
	env := marshalEnvelope(body, sig)
	if werr := os.WriteFile(eng.policyPath(), env, 0o600); werr != nil {
		t.Fatal(werr)
	}
	_, _, serr := eng.Show()
	if got := domain.AsError(serr).Code; got != codeVersion {
		t.Fatalf("unknown field: code=%s want %s", got, codeVersion)
	}
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// ── pin / canonical body / paths ─────────────────────────────────────────────

func TestPolicyPaths(t *testing.T) {
	eng, _ := testEngine(t, "admin", nil)
	if filepath.Base(eng.policyPath()) != "policy.json" {
		t.Fatalf("policy path = %s", eng.policyPath())
	}
}
