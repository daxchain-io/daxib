package policy

import (
	"context"
	"testing"

	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/secret"
)

// release_test.go is the GAP-4 regression: ReleaseReservation frees a STUCK pending
// reservation (admin-gated) and REFUSES a committed one.

// TestReleaseReservationFreesPending proves an admin can release a stuck PENDING
// reservation: the rolling-24h budget it consumed is freed for a subsequent send.
func TestReleaseReservationFreesPending(t *testing.T) {
	eng, _ := testEngine(t, "admin", nil)
	setLimits(t, eng, "admin", &Limits{MaxDaySat: satPtr("1000"), AllowlistOn: boolPtr(false)})
	ctx := context.Background()

	// Reserve 600 but never commit/release it (a stuck pre-signature reservation).
	r1, err := eng.Reserve(ctx, Check{Network: "regtest", Recipient: recipA, AmountSat: 550, FeeSat: 50})
	if err != nil {
		t.Fatal(err)
	}

	// A 900 send must NOT fit while the 600 is still reserved (600+900 > 1000).
	if _, derr := eng.Reserve(ctx, Check{Network: "regtest", Recipient: recipB, AmountSat: 850, FeeSat: 50}); derr == nil {
		t.Fatal("precondition: a 900 send must be denied while the 600 reservation is live")
	}

	// Admin releases the stuck reservation.
	admin := secret.NewString("admin")
	defer admin.Zero()
	if rerr := eng.ReleaseReservation(ctx, admin, "regtest", r1.ID()); rerr != nil {
		t.Fatalf("ReleaseReservation pending: %v", rerr)
	}

	// Now the 900 send fits (the released 600 no longer counts).
	if _, err := eng.Reserve(ctx, Check{Network: "regtest", Recipient: recipB, AmountSat: 850, FeeSat: 50}); err != nil {
		t.Fatalf("after release a 900 send should fit: %v", err)
	}
}

// TestReleaseReservationRefusesCommitted proves a COMMITTED reservation (a live
// spend) cannot be released — fail closed (policy.state_error).
func TestReleaseReservationRefusesCommitted(t *testing.T) {
	eng, _ := testEngine(t, "admin", nil)
	setLimits(t, eng, "admin", &Limits{MaxDaySat: satPtr("1000"), AllowlistOn: boolPtr(false)})
	ctx := context.Background()

	r1, err := eng.Reserve(ctx, Check{Network: "regtest", Recipient: recipA, AmountSat: 550, FeeSat: 50})
	if err != nil {
		t.Fatal(err)
	}
	if err := r1.Commit(ctx, "txid-live"); err != nil {
		t.Fatal(err)
	}

	admin := secret.NewString("admin")
	defer admin.Zero()
	rerr := eng.ReleaseReservation(ctx, admin, "regtest", r1.ID())
	if rerr == nil {
		t.Fatal("releasing a COMMITTED reservation must be refused (fail closed)")
	}
	if got := domain.AsError(rerr).Code; got != codeStateError {
		t.Fatalf("refuse-committed code=%s, want %s", got, codeStateError)
	}

	// The committed spend is still counted (the refusal did not silently free it).
	r2, err := eng.Reserve(ctx, Check{Network: "regtest", Recipient: recipB, AmountSat: 850, FeeSat: 50})
	if err == nil {
		_ = r2.Release(ctx)
		t.Fatal("the committed spend must remain counted after a refused release")
	}
}

// TestReleaseReservationWrongAdmin proves a non-admin passphrase cannot release a
// reservation (admin-gated; exit 4).
func TestReleaseReservationWrongAdmin(t *testing.T) {
	eng, _ := testEngine(t, "admin", nil)
	setLimits(t, eng, "admin", &Limits{MaxDaySat: satPtr("1000"), AllowlistOn: boolPtr(false)})
	ctx := context.Background()

	r1, err := eng.Reserve(ctx, Check{Network: "regtest", Recipient: recipA, AmountSat: 550, FeeSat: 50})
	if err != nil {
		t.Fatal(err)
	}

	wrong := secret.NewString("not-admin")
	defer wrong.Zero()
	rerr := eng.ReleaseReservation(ctx, wrong, "regtest", r1.ID())
	if got := domain.AsError(rerr).Code; got != codeAdminAuth {
		t.Fatalf("wrong-admin code=%s, want %s", got, codeAdminAuth)
	}
}

// TestReleaseReservationUnknownID proves an unknown reservation id fails closed
// (policy.state_error) rather than silently succeeding.
func TestReleaseReservationUnknownID(t *testing.T) {
	eng, _ := testEngine(t, "admin", nil)
	setLimits(t, eng, "admin", &Limits{MaxDaySat: satPtr("1000"), AllowlistOn: boolPtr(false)})
	ctx := context.Background()

	admin := secret.NewString("admin")
	defer admin.Zero()
	rerr := eng.ReleaseReservation(ctx, admin, "regtest", "does-not-exist")
	if got := domain.AsError(rerr).Code; got != codeStateError {
		t.Fatalf("unknown-id code=%s, want %s", got, codeStateError)
	}
}
