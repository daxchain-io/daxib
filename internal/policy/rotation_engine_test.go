package policy

import (
	"os"
	"testing"

	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/policyseal"
	"github.com/daxchain-io/daxib/internal/secret"
)

// rotation_engine_test.go is the SI-1 engine-level regression for the crash-safe
// staged admin-passphrase rotation. It exercises the happy path (stage → reseal →
// promote converges to the NEW key) plus the crash-point recoveries: a crash after
// STAGE rolls BACK (policy.json still under OLD), a crash after RESEAL rolls FORWARD
// (policy.json under NEW ⇒ promote). At every crash point policy.json verifies and the
// limits are never wiped.

// reopenWith builds a fresh engine over eng's state dir pinned to the given anchor —
// the in-process stand-in for "land the anchor, then a new process Opens it".
func reopenWith(t *testing.T, eng *Engine, anchor policyseal.Anchor) *Engine {
	t.Helper()
	e2, err := Open(eng.dir, anchor, true, eng.clock)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	return e2
}

// assertVerifiesWithLimit fails unless policy.json verifies under the engine's anchor
// AND the resolved per-tx cap equals wantMaxTx (proving the limits survived).
func assertVerifiesWithLimit(t *testing.T, eng *Engine, wantMaxTx string) {
	t.Helper()
	pol, st, err := eng.Show()
	if err != nil || !st.Verified {
		t.Fatalf("policy must verify: st=%+v err=%v", st, err)
	}
	got := pol.Rules.Default.MaxTxSat
	if got == nil || *got != wantMaxTx {
		t.Fatalf("limit wiped/changed: maxTx=%v, want %s", got, wantMaxTx)
	}
}

// TestStagedRotationHappyPath stages, reseals, promotes — the NEW passphrase
// authenticates + verifies, the OLD does not, and the limit is preserved.
func TestStagedRotationHappyPath(t *testing.T) {
	eng, _ := testEngine(t, "old-admin", nil)
	setLimits(t, eng, "old-admin", &Limits{MaxTxSat: satPtr("777")})

	cur := secret.NewString("old-admin")
	next := secret.NewString("new-admin")
	defer cur.Zero()
	defer next.Zero()

	staged, err := eng.StageAdminRotation(cur, next)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if staged.VerifyKeyNext == "" || staged.StagedSalt == "" {
		t.Fatalf("staged anchor must carry verify_key_next + staged_salt: %+v", staged)
	}
	// Mid-stage, policy.json STILL verifies (under OLD) and the limit is intact.
	assertVerifiesWithLimit(t, eng, "777")

	if rerr := eng.ResealUnderStagedRotation(secret.NewString("new-admin")); rerr != nil {
		t.Fatalf("reseal: %v", rerr)
	}
	// Post-reseal (anchor still dual-key) it verifies under the NEW staged key.
	assertVerifiesWithLimit(t, eng, "777")

	promoted, perr := eng.PromoteAdminRotation()
	if perr != nil {
		t.Fatalf("promote: %v", perr)
	}
	if promoted.VerifyKeyNext != "" || promoted.StagedSalt != "" {
		t.Fatalf("promoted anchor must be single-key: %+v", promoted)
	}

	// Re-Open under the promoted (single NEW key) anchor: it verifies, the NEW
	// passphrase authenticates a follow-up mutation, the OLD does not.
	e2 := reopenWith(t, eng, promoted)
	assertVerifiesWithLimit(t, e2, "777")

	nn := secret.NewString("new-admin")
	defer nn.Zero()
	if _, err := e2.Set(nn, Change{Default: &Limits{MaxTxSat: satPtr("888")}, WrittenBy: "x"}); err != nil {
		t.Fatalf("NEW passphrase must authenticate after promote: %v", err)
	}
	old := secret.NewString("old-admin")
	defer old.Zero()
	if _, err := e2.Set(old, Change{Default: &Limits{MaxTxSat: satPtr("1")}, WrittenBy: "x"}); domain.AsError(err).Code != codeAdminAuth {
		t.Fatal("OLD passphrase must NOT authenticate after promote")
	}
}

// TestStagedRotationCrashAfterStageRollsBack simulates a crash AFTER the staged anchor
// landed but BEFORE the reseal: policy.json is still sealed under OLD. Recovery must
// roll BACK (drop the staged key) and the OLD passphrase must still authenticate. The
// limit is never wiped.
func TestStagedRotationCrashAfterStageRollsBack(t *testing.T) {
	eng, _ := testEngine(t, "old-admin", nil)
	setLimits(t, eng, "old-admin", &Limits{MaxTxSat: satPtr("777")})

	cur := secret.NewString("old-admin")
	next := secret.NewString("new-admin")
	defer cur.Zero()
	defer next.Zero()

	staged, err := eng.StageAdminRotation(cur, next)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	// CRASH here: the staged anchor is "landed" (we Open with it) but policy.json was
	// never resealed. Recovery inspects + converges.
	e2 := reopenWith(t, eng, staged)
	anchor, changed, rerr := e2.RecoverAdminRotation()
	if rerr != nil {
		t.Fatalf("recover: %v", rerr)
	}
	if !changed {
		t.Fatal("recovery after a post-stage crash must change the anchor (roll back)")
	}
	if anchor.VerifyKeyNext != "" || anchor.StagedSalt != "" {
		t.Fatalf("rolled-back anchor must drop the staged key: %+v", anchor)
	}

	// Re-Open under the rolled-back anchor: it verifies, the OLD passphrase still
	// authenticates, the NEW does not, and the limit survived.
	e3 := reopenWith(t, e2, anchor)
	assertVerifiesWithLimit(t, e3, "777")
	old := secret.NewString("old-admin")
	defer old.Zero()
	if _, err := e3.Set(old, Change{Default: &Limits{MaxTxSat: satPtr("778")}, WrittenBy: "x"}); err != nil {
		t.Fatalf("OLD passphrase must still authenticate after roll-back: %v", err)
	}
	nn := secret.NewString("new-admin")
	defer nn.Zero()
	if _, err := e3.Set(nn, Change{Default: &Limits{MaxTxSat: satPtr("1")}, WrittenBy: "x"}); domain.AsError(err).Code != codeAdminAuth {
		t.Fatal("NEW passphrase must NOT authenticate after a rolled-back rotation")
	}
}

// TestStagedRotationCrashAfterResealRollsForward simulates a crash AFTER the reseal but
// BEFORE the promote landed: policy.json is sealed under NEW while the on-disk anchor
// is still dual-key. Recovery must roll FORWARD (promote to single NEW key). The OLD
// passphrase must stop authenticating; the limit is never wiped.
func TestStagedRotationCrashAfterResealRollsForward(t *testing.T) {
	eng, _ := testEngine(t, "old-admin", nil)
	setLimits(t, eng, "old-admin", &Limits{MaxTxSat: satPtr("777")})

	cur := secret.NewString("old-admin")
	next := secret.NewString("new-admin")
	defer cur.Zero()
	defer next.Zero()

	staged, err := eng.StageAdminRotation(cur, next)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if rerr := eng.ResealUnderStagedRotation(secret.NewString("new-admin")); rerr != nil {
		t.Fatalf("reseal: %v", rerr)
	}
	// CRASH here: policy.json is under NEW, but the on-disk anchor is still the DUAL-KEY
	// staged anchor (promote never landed). Recovery rolls forward.
	e2 := reopenWith(t, eng, staged)
	anchor, changed, rerr := e2.RecoverAdminRotation()
	if rerr != nil {
		t.Fatalf("recover: %v", rerr)
	}
	if !changed {
		t.Fatal("recovery after a post-reseal crash must change the anchor (roll forward)")
	}
	if anchor.VerifyKeyNext != "" || anchor.StagedSalt != "" {
		t.Fatalf("promoted anchor must be single-key: %+v", anchor)
	}

	// Re-Open under the promoted anchor: verifies, NEW authenticates, OLD does not, the
	// limit survived.
	e3 := reopenWith(t, e2, anchor)
	assertVerifiesWithLimit(t, e3, "777")
	nn := secret.NewString("new-admin")
	defer nn.Zero()
	if _, err := e3.Set(nn, Change{Default: &Limits{MaxTxSat: satPtr("888")}, WrittenBy: "x"}); err != nil {
		t.Fatalf("NEW passphrase must authenticate after roll-forward: %v", err)
	}
	old := secret.NewString("old-admin")
	defer old.Zero()
	if _, err := e3.Set(old, Change{Default: &Limits{MaxTxSat: satPtr("1")}, WrittenBy: "x"}); domain.AsError(err).Code != codeAdminAuth {
		t.Fatal("OLD passphrase must NOT authenticate after roll-forward")
	}
}

// TestStagedRotationDualKeyWindowVerifiesPolicyOnDisk proves the crash-safety
// invariant directly: in the dual-key window, the ON-DISK policy.json verifies under
// the anchor whether it is sealed under OLD (pre-reseal) or NEW (post-reseal).
func TestStagedRotationDualKeyWindowVerifiesPolicyOnDisk(t *testing.T) {
	eng, _ := testEngine(t, "old-admin", nil)
	setLimits(t, eng, "old-admin", &Limits{MaxTxSat: satPtr("777")})

	cur := secret.NewString("old-admin")
	next := secret.NewString("new-admin")
	defer cur.Zero()
	defer next.Zero()
	staged, err := eng.StageAdminRotation(cur, next)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}

	raw, _ := os.ReadFile(eng.policyPath())
	_, body, _ := decodeEnvelope(raw)
	env, _, _ := decodeEnvelope(raw)
	sig, _ := decodeBase64(env.Seal.Sig)

	// Pre-reseal: verifies under the dual-key anchor (via the OLD verify_key).
	if !verifyUnderAnchor(body, sig, staged) {
		t.Fatal("pre-reseal policy.json must verify under the dual-key anchor")
	}

	if rerr := eng.ResealUnderStagedRotation(secret.NewString("new-admin")); rerr != nil {
		t.Fatalf("reseal: %v", rerr)
	}
	raw2, _ := os.ReadFile(eng.policyPath())
	_, body2, _ := decodeEnvelope(raw2)
	env2, _, _ := decodeEnvelope(raw2)
	sig2, _ := decodeBase64(env2.Seal.Sig)
	// Post-reseal: still verifies under the same dual-key anchor (via verify_key_next).
	if !verifyUnderAnchor(body2, sig2, staged) {
		t.Fatal("post-reseal policy.json must verify under the dual-key anchor (NEW key)")
	}
}
