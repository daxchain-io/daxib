package service

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/daxchain-io/daxib/internal/backend"
	fakebackend "github.com/daxchain-io/daxib/internal/backend/fake"
	"github.com/daxchain-io/daxib/internal/domain"
)

// policy_rotation_test.go is the SI-1 service-level crash-point regression: the staged
// admin-passphrase rotation (stage → reseal → promote) survives a crash at ANY phase —
// recovery at the next Open converges (forward or back), policy.json ALWAYS verifies,
// and the limits are never wiped. It mirrors the keystore rotation crash tests
// (internal/keys/passphrase_test.go).

// rotationDirs holds the three state-class dirs so a crash-point test can re-Open the
// SAME service tree (running reconcileAtOpen → recoverPolicyRotation).
type rotationDirs struct {
	keystore, config, state string
}

// newRotationService builds a service with BOTH admin passphrases wired (current +
// new) over the given dirs, a sealed policy bootstrapped with a max-tx limit, and the
// canonical wallet imported. The config dir is WRITABLE so the anchor lands.
func newRotationService(t *testing.T, dirs rotationDirs, fake *fakebackend.Client) (*Service, func()) {
	t.Helper()
	env := map[string]string{
		"DAXIB_KEYSTORE":             dirs.keystore,
		"DAXIB_KDF_LIGHT":            "1",
		"DAXIB_PASSPHRASE":           "test-pass-12345678",
		"DAXIB_PASSPHRASE_CONFIRM":   "test-pass-12345678",
		"DAXIB_ADMIN_PASSPHRASE":     "admin-OLD-secret",
		"DAXIB_ADMIN_NEW_PASSPHRASE": "admin-NEW-secret",
	}
	svc, err := Open(context.Background(), Options{
		Keystore: dirs.keystore,
		Config:   dirs.config,
		State:    dirs.state,
		Network:  "mainnet",
		KDFLight: true,
		Dial: func(_ context.Context, _ backend.Options) (backend.Client, error) {
			return fake, nil
		},
		Secret: SecretIO{
			Stdin:     strings.NewReader(canonicalMnemonic),
			LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok },
			IsTTY:     func() bool { return false },
			Prompt:    func(string) ([]byte, error) { return nil, io.EOF },
		},
	})
	if err != nil {
		t.Fatalf("service.Open: %v", err)
	}
	importCanonical(t, svc, "vec")
	return svc, func() { _ = svc.Close() }
}

// reopenRotationService re-Opens the service tree WITHOUT re-importing the wallet (it
// already exists) — the recovery path under test runs in reconcileAtOpen on Open.
func reopenRotationService(t *testing.T, dirs rotationDirs, fake *fakebackend.Client, adminPass, newPass string) (*Service, func()) {
	t.Helper()
	env := map[string]string{
		"DAXIB_KEYSTORE":           dirs.keystore,
		"DAXIB_KDF_LIGHT":          "1",
		"DAXIB_PASSPHRASE":         "test-pass-12345678",
		"DAXIB_PASSPHRASE_CONFIRM": "test-pass-12345678",
		"DAXIB_ADMIN_PASSPHRASE":   adminPass,
	}
	if newPass != "" {
		env["DAXIB_ADMIN_NEW_PASSPHRASE"] = newPass
	}
	svc, err := Open(context.Background(), Options{
		Keystore: dirs.keystore,
		Config:   dirs.config,
		State:    dirs.state,
		Network:  "mainnet",
		KDFLight: true,
		Dial: func(_ context.Context, _ backend.Options) (backend.Client, error) {
			return fake, nil
		},
		Secret: SecretIO{
			Stdin:     strings.NewReader(canonicalMnemonic),
			LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok },
			IsTTY:     func() bool { return false },
			Prompt:    func(string) ([]byte, error) { return nil, io.EOF },
		},
	})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	return svc, func() { _ = svc.Close() }
}

// withPolicyRotationFault installs the fault hook for fn at the named point.
func withPolicyRotationFault(t *testing.T, point string, fn func()) {
	t.Helper()
	policyRotationFaultHook = func(p string) error {
		if p == point {
			return domain.New("internal", "injected policy-rotation fault at "+p)
		}
		return nil
	}
	defer func() { policyRotationFaultHook = nil }()
	fn()
}

// assertPolicyVerifiesUnder reopens the service tree and asserts policy.json verifies
// AND the named admin passphrase authenticates a mutation (proving the seal converged
// under that key) AND the limit survived. wantOld selects which passphrase must work.
func assertPolicyVerifiesUnder(t *testing.T, dirs rotationDirs, fake *fakebackend.Client, wantNew bool) {
	t.Helper()
	// Re-Open (runs reconcileAtOpen → recoverPolicyRotation), then assert.
	svc, teardown := reopenRotationService(t, dirs, fake, "admin-OLD-secret", "")
	defer teardown()

	// policy.json verifies under the (converged) pinned anchor.
	st, err := svc.PolicyVerify(context.Background())
	if err != nil || !st.Verified {
		t.Fatalf("policy.json must verify after recovery: st=%+v err=%v", st, err)
	}

	// The limit survived (never wiped).
	show, serr := svc.PolicyShow(context.Background())
	if serr != nil {
		t.Fatalf("PolicyShow: %v", serr)
	}
	if show.Default.MaxTxSat != "500000" {
		t.Fatalf("limit wiped/changed after recovery: max_tx=%q, want 500000", show.Default.MaxTxSat)
	}

	// The expected passphrase authenticates a follow-up mutation; the other does not.
	good, bad := "admin-OLD-secret", "admin-NEW-secret"
	if wantNew {
		good, bad = "admin-NEW-secret", "admin-OLD-secret"
	}
	if err := mutateWithAdmin(t, dirs, fake, good); err != nil {
		t.Fatalf("the expected admin passphrase must authenticate after recovery: %v", err)
	}
	if err := mutateWithAdmin(t, dirs, fake, bad); err == nil {
		t.Fatalf("the other admin passphrase must NOT authenticate after recovery")
	} else if domain.AsError(err).Code != "policy.admin_auth" {
		t.Fatalf("wrong-passphrase code=%s, want policy.admin_auth", domain.AsError(err).Code)
	}
}

// mutateWithAdmin runs a `policy set` under the given admin passphrase by re-Opening
// the service tree with that passphrase wired as DAXIB_ADMIN_PASSPHRASE. It is the
// post-recovery authentication probe: the converged key authenticates; the other
// returns policy.admin_auth.
func mutateWithAdmin(t *testing.T, dirs rotationDirs, fake *fakebackend.Client, adminPass string) error {
	t.Helper()
	s2, teardown := reopenRotationService(t, dirs, fake, adminPass, "")
	defer teardown()
	_, merr := s2.PolicySet(context.Background(), PolicySetInput{MaxFeeRate: "99"})
	return merr
}

// bootstrapRotationPolicy seeds a sealed policy under the OLD admin passphrase with a
// max-tx limit (so a "limits never wiped" assertion has something concrete to check).
func bootstrapRotationPolicy(t *testing.T, svc *Service) {
	t.Helper()
	if _, err := svc.PolicySet(context.Background(), PolicySetInput{
		MaxTxSat: "500000", AllowlistOn: boolFalse(),
	}); err != nil {
		t.Fatalf("bootstrap policy: %v", err)
	}
}

func TestPolicyRotationCrashAfterStageRollsBack(t *testing.T) {
	dirs := rotationDirs{keystore: t.TempDir(), config: t.TempDir(), state: t.TempDir()}
	fake := fakebackend.New()

	svc, teardown := newRotationService(t, dirs, fake)
	bootstrapRotationPolicy(t, svc)

	// Crash right after the staged anchor lands (before reseal). policy.json is still
	// sealed under OLD ⇒ recovery rolls BACK ⇒ OLD still authenticates.
	withPolicyRotationFault(t, "after_stage", func() {
		_, err := svc.PolicyChangeAdminPassphrase(context.Background(), PolicyRotateInput{})
		if err == nil {
			t.Fatal("expected the injected fault to abort the rotation")
		}
	})
	teardown()

	assertPolicyVerifiesUnder(t, dirs, fake, false /* OLD still works */)
}

func TestPolicyRotationCrashAfterResealRollsForward(t *testing.T) {
	dirs := rotationDirs{keystore: t.TempDir(), config: t.TempDir(), state: t.TempDir()}
	fake := fakebackend.New()

	svc, teardown := newRotationService(t, dirs, fake)
	bootstrapRotationPolicy(t, svc)

	// Crash right after the reseal (before promote). policy.json is sealed under NEW ⇒
	// recovery rolls FORWARD (promote) ⇒ NEW authenticates, OLD does not.
	withPolicyRotationFault(t, "after_reseal", func() {
		_, err := svc.PolicyChangeAdminPassphrase(context.Background(), PolicyRotateInput{})
		if err == nil {
			t.Fatal("expected the injected fault to abort the rotation")
		}
	})
	teardown()

	assertPolicyVerifiesUnder(t, dirs, fake, true /* NEW now works */)
}

func TestPolicyRotationCrashAfterPromoteConverges(t *testing.T) {
	dirs := rotationDirs{keystore: t.TempDir(), config: t.TempDir(), state: t.TempDir()}
	fake := fakebackend.New()

	svc, teardown := newRotationService(t, dirs, fake)
	bootstrapRotationPolicy(t, svc)

	// Crash right after the promote anchor lands (the rotation is effectively complete;
	// the only thing skipped is returning success). Recovery is a no-op (single-key).
	withPolicyRotationFault(t, "after_promote", func() {
		_, err := svc.PolicyChangeAdminPassphrase(context.Background(), PolicyRotateInput{})
		if err == nil {
			t.Fatal("expected the injected fault to abort after promote")
		}
	})
	teardown()

	assertPolicyVerifiesUnder(t, dirs, fake, true /* NEW works */)
}

func TestPolicyRotationHappyPathConverges(t *testing.T) {
	dirs := rotationDirs{keystore: t.TempDir(), config: t.TempDir(), state: t.TempDir()}
	fake := fakebackend.New()

	svc, teardown := newRotationService(t, dirs, fake)
	bootstrapRotationPolicy(t, svc)

	if _, err := svc.PolicyChangeAdminPassphrase(context.Background(), PolicyRotateInput{}); err != nil {
		t.Fatalf("rotation: %v", err)
	}
	teardown()

	assertPolicyVerifiesUnder(t, dirs, fake, true /* NEW works */)
}
