package policy

import (
	"math/big"
	"testing"

	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/policyseal"
	"github.com/daxchain-io/daxib/internal/secret"
)

func mustBig(s string) *big.Int {
	v, _ := new(big.Int).SetString(s, 10)
	return v
}

// TestAdminKeystoreIndependence asserts the admin secret and the keystore secret
// are independent: deriving the SEAL key uses the anchor salt + admin scrypt params,
// which are distinct from any keystore KDF. A different passphrase (what a
// compromised agent holds as the keystore passphrase) derives a different verify key
// and CANNOT authenticate a policy mutation.
func TestAdminKeystoreIndependence(t *testing.T) {
	eng, _ := testEngine(t, "ADMIN-passphrase", nil)

	// The "keystore passphrase" (a different secret the agent might hold) does not
	// derive the pinned verify key.
	keystorePass := secret.NewString("KEYSTORE-passphrase")
	defer keystorePass.Zero()
	_, err := eng.Set(keystorePass, Change{Default: &Limits{MaxTxSat: satPtr("1")}, WrittenBy: "x"})
	if got := domain.AsError(err).Code; got != codeAdminAuth {
		t.Fatalf("keystore passphrase must NOT authenticate a policy mutation: code=%s want %s", got, codeAdminAuth)
	}

	// The correct admin passphrase does authenticate.
	adminPass := secret.NewString("ADMIN-passphrase")
	defer adminPass.Zero()
	if _, err := eng.Set(adminPass, Change{Default: &Limits{MaxTxSat: satPtr("1")}, WrittenBy: "x"}); err != nil {
		t.Fatalf("admin passphrase must authenticate: %v", err)
	}
}

func TestAllowDenyMutations(t *testing.T) {
	eng, _ := testEngine(t, "admin", nil)
	pass := func() *secret.Bytes { return secret.NewString("admin") }

	if _, err := eng.Allow(pass(), AllowEntry{Address: recipA, Label: "exchange", WrittenBy: "x"}); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Deny(pass(), DenyEntry{Address: recipB, Label: "drainer", WrittenBy: "x"}); err != nil {
		t.Fatal(err)
	}
	pol, _, err := eng.Show()
	if err != nil {
		t.Fatal(err)
	}
	if !matchPinAddr(pol.Allowlist, recipA) {
		t.Error("recipA should be allowlisted")
	}
	if !matchPinAddr(pol.Denylist, recipB) {
		t.Error("recipB should be denylisted")
	}

	// Remove the allow entry.
	if _, err := eng.Allow(pass(), AllowEntry{Address: recipA, Remove: true, WrittenBy: "x"}); err != nil {
		t.Fatal(err)
	}
	pol, _, _ = eng.Show()
	if matchPinAddr(pol.Allowlist, recipA) {
		t.Error("recipA should be removed from the allowlist")
	}
}

func TestNonceAdvancesAndWatermarkBumps(t *testing.T) {
	eng, _ := testEngine(t, "admin", nil)
	_, st0, _ := eng.Show()
	setLimits(t, eng, "admin", &Limits{MaxTxSat: satPtr("100")})
	_, st1, _ := eng.Show()
	if st1.Nonce <= st0.Nonce {
		t.Fatalf("nonce must advance: %d -> %d", st0.Nonce, st1.Nonce)
	}
	if eng.anchor.NonceWatermark < st1.Nonce {
		t.Fatalf("watermark must keep up with the nonce: wm=%d nonce=%d", eng.anchor.NonceWatermark, st1.Nonce)
	}
}

func TestSelfAddressesRefreshedOnMutation(t *testing.T) {
	eng, _ := testEngine(t, "admin", nil)
	pass := secret.NewString("admin")
	defer pass.Zero()
	if _, err := eng.Set(pass, Change{
		Default:     &Limits{AllowlistOn: boolPtr(true), IncludeSelf: boolPtr(true)},
		RefreshSelf: []string{recipA, recipB},
		WrittenBy:   "x",
	}); err != nil {
		t.Fatal(err)
	}
	pol, _, _ := eng.Show()
	if len(pol.SelfAddresses) != 2 {
		t.Fatalf("self_addresses snapshot = %v; want 2", pol.SelfAddresses)
	}
}

// TestChangeAdminPassphraseReseals drives the staged rotation (stage → reseal →
// promote) end-to-end at the engine level: the OLD passphrase stops authenticating,
// the NEW reseals verifiably, and a follow-up mutation under NEW takes.
func TestChangeAdminPassphraseReseals(t *testing.T) {
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
	if staged.VerifyKeyNext == "" {
		t.Fatal("stage must produce a staged verify key")
	}
	if rerr := eng.ResealUnderStagedRotation(secret.NewString("new-admin")); rerr != nil {
		t.Fatalf("reseal: %v", rerr)
	}
	newAnchor, perr := eng.PromoteAdminRotation()
	if perr != nil {
		t.Fatalf("promote: %v", perr)
	}
	if newAnchor.VerifyKey == "" || newAnchor.VerifyKeyNext != "" {
		t.Fatalf("promoted anchor must be single-key: %+v", newAnchor)
	}

	// The OLD passphrase no longer authenticates.
	old := secret.NewString("old-admin")
	defer old.Zero()
	if _, err := eng.Set(old, Change{Default: &Limits{MaxTxSat: satPtr("1")}, WrittenBy: "x"}); domain.AsError(err).Code != codeAdminAuth {
		t.Fatal("old passphrase must no longer authenticate after rotation")
	}
	// The NEW passphrase authenticates and the resealed body still verifies.
	nn := secret.NewString("new-admin")
	defer nn.Zero()
	if _, err := eng.Set(nn, Change{Default: &Limits{MaxTxSat: satPtr("888")}, WrittenBy: "x"}); err != nil {
		t.Fatalf("new passphrase must authenticate: %v", err)
	}
	pol, st, err := eng.Show()
	if err != nil || !st.Verified {
		t.Fatalf("resealed policy must verify: st=%+v err=%v", st, err)
	}
	if pol.Rules.Default.MaxTxSat == nil || *pol.Rules.Default.MaxTxSat != "888" {
		t.Fatalf("post-rotation set did not take: %+v", pol.Rules.Default.MaxTxSat)
	}
}

func TestResetUnderAnchorReseals(t *testing.T) {
	eng, _ := testEngine(t, "admin", nil)
	setLimits(t, eng, "admin", &Limits{MaxTxSat: satPtr("100")})
	pass := secret.NewString("admin")
	defer pass.Zero()
	if _, err := eng.Reset(pass, []string{recipA}, "x"); err != nil {
		t.Fatalf("reset: %v", err)
	}
	pol, st, err := eng.Show()
	if err != nil || !st.Verified {
		t.Fatalf("reset policy must verify: %v", err)
	}
	// The default body carries no enforced limit — the resolved limit is unlimited
	// (a default-block absent limit serializes as null = no limit, which resolves to
	// a nil *big.Int).
	if lim := resolveLimits(pol, "regtest"); lim.maxTx != nil {
		t.Fatalf("reset must clear the per-tx cap; resolved maxTx=%v", lim.maxTx)
	}
}

func TestInitSealRefusesExistingAnchor(t *testing.T) {
	eng, _ := testEngine(t, "admin", nil)
	pass := secret.NewString("admin")
	defer pass.Zero()
	if _, err := eng.InitSeal(pass, nil, "x"); domain.AsError(err).Code != codeAdminAuth {
		t.Fatalf("InitSeal must refuse to replace an existing trust root, got %v", err)
	}
}

func TestInitSealBootstrapsFresh(t *testing.T) {
	dir := t.TempDir()
	// A fresh engine with NO anchor.
	eng, err := Open(dir, policyseal.Anchor{}, false, fixedClock())
	if err != nil {
		t.Fatal(err)
	}
	pass := secret.NewString("admin")
	defer pass.Zero()
	anchor, err := eng.InitSeal(pass, []string{recipA}, "x")
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if anchor.VerifyKey == "" || anchor.Salt == "" {
		t.Fatalf("bootstrap anchor incomplete: %+v", anchor)
	}
	// The engine now has the anchor pinned; Show verifies.
	_, st, err := eng.Show()
	if err != nil || !st.Verified {
		t.Fatalf("bootstrapped policy must verify: st=%+v err=%v", st, err)
	}
}
