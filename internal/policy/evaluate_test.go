package policy

import (
	"context"
	"os"
	"testing"

	"github.com/daxchain-io/daxib/internal/domain"
)

const recipA = "bcrt1qrecipientaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const recipB = "bcrt1qrecipientbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// ── pure Evaluate: limit caps ────────────────────────────────────────────────

func TestEvaluateMaxTxDenies(t *testing.T) {
	p := Policy{Rules: Rules{Default: Limits{MaxTxSat: satPtr("1000")}}}
	// amount+fee = 1001 > 1000 ⇒ denied.
	d := Evaluate(p, Check{Network: "regtest", Recipient: recipA, AmountSat: 900, FeeSat: 101}, nil, fixedClock()())
	if d.Allowed {
		t.Fatal("over max_tx must be denied")
	}
	if d.Code != codeDeniedTxLimit {
		t.Fatalf("code = %s want %s", d.Code, codeDeniedTxLimit)
	}
	// Exactly at the limit ⇒ allowed.
	d = Evaluate(p, Check{Network: "regtest", Recipient: recipA, AmountSat: 900, FeeSat: 100}, nil, fixedClock()())
	if !d.Allowed {
		t.Fatalf("at-limit must be allowed: %+v", d)
	}
}

func TestEvaluateMaxFeeRateDenies(t *testing.T) {
	p := Policy{Rules: Rules{Default: Limits{MaxFeeRate: satPtr("50")}}}
	d := Evaluate(p, Check{Network: "regtest", Recipient: recipA, AmountSat: 1, FeeSat: 1, FeeRate: 51}, nil, fixedClock()())
	if d.Allowed || d.Code != codeDeniedFeeRate {
		t.Fatalf("over fee-rate cap: %+v", d)
	}
	d = Evaluate(p, Check{Network: "regtest", Recipient: recipA, AmountSat: 1, FeeSat: 1, FeeRate: 50}, nil, fixedClock()())
	if !d.Allowed {
		t.Fatal("at fee-rate cap must be allowed")
	}
}

func TestEvaluateMaxDayRolling(t *testing.T) {
	p := Policy{Rules: Rules{Default: Limits{MaxDaySat: satPtr("1000")}}}
	// Already spent 600 in window; this 500 (amount+fee) ⇒ 1100 > 1000 ⇒ denied.
	spent := mustBig("600")
	d := Evaluate(p, Check{Network: "regtest", Recipient: recipA, AmountSat: 450, FeeSat: 50}, spent, fixedClock()())
	if d.Allowed || d.Code != codeDeniedDayLimit {
		t.Fatalf("over day limit: %+v", d)
	}
	if d.RetryAfter == "" {
		t.Fatal("day-limit denial must carry retry_after")
	}
	// Within budget.
	d = Evaluate(p, Check{Network: "regtest", Recipient: recipA, AmountSat: 350, FeeSat: 50}, spent, fixedClock()())
	if !d.Allowed {
		t.Fatalf("within day budget must be allowed: %+v", d)
	}
}

// ── precedence: denylist > allowlist > include_self ──────────────────────────

func TestPrecedenceDenylistBeatsAllowlist(t *testing.T) {
	p := Policy{
		Rules:     Rules{Default: Limits{AllowlistOn: boolPtr(true)}},
		Allowlist: []PinEntry{{Source: "address", Address: recipA}},
		Denylist:  []PinEntry{{Source: "address", Address: recipA}},
	}
	d := Evaluate(p, Check{Network: "regtest", Recipient: recipA, AmountSat: 1, FeeSat: 1}, nil, fixedClock()())
	if d.Allowed || d.Code != codeDeniedDenylisted {
		t.Fatalf("denylist must beat allowlist: %+v", d)
	}
}

func TestAllowlistGate(t *testing.T) {
	p := Policy{
		Rules:     Rules{Default: Limits{AllowlistOn: boolPtr(true)}},
		Allowlist: []PinEntry{{Source: "address", Address: recipA}},
	}
	// Allowlisted recipient passes.
	if d := Evaluate(p, Check{Network: "regtest", Recipient: recipA, AmountSat: 1, FeeSat: 1}, nil, fixedClock()()); !d.Allowed {
		t.Fatalf("allowlisted recipient must pass: %+v", d)
	}
	// Non-allowlisted recipient denied.
	d := Evaluate(p, Check{Network: "regtest", Recipient: recipB, AmountSat: 1, FeeSat: 1}, nil, fixedClock()())
	if d.Allowed || d.Code != codeDeniedNotAllowlist {
		t.Fatalf("non-allowlisted recipient must be denied: %+v", d)
	}
}

func TestIncludeSelfAndChange(t *testing.T) {
	p := Policy{
		Rules:         Rules{Default: Limits{AllowlistOn: boolPtr(true), IncludeSelf: boolPtr(true)}},
		SelfAddresses: []string{recipA},
	}
	// A sealed self address passes via include_self.
	if d := Evaluate(p, Check{Network: "regtest", Recipient: recipA, AmountSat: 1, FeeSat: 1}, nil, fixedClock()()); !d.Allowed {
		t.Fatalf("self address must pass include_self: %+v", d)
	}
	// The tx's own change address passes even if not in the snapshot.
	if d := Evaluate(p, Check{Network: "regtest", Recipient: recipB, ChangeAddr: recipB, AmountSat: 1, FeeSat: 1}, nil, fixedClock()()); !d.Allowed {
		t.Fatalf("change address must pass include_self: %+v", d)
	}
	// include_self OFF: the self address is denied.
	p.Rules.Default.IncludeSelf = boolPtr(false)
	if d := Evaluate(p, Check{Network: "regtest", Recipient: recipA, AmountSat: 1, FeeSat: 1}, nil, fixedClock()()); d.Allowed {
		t.Fatal("self address must be denied when include_self is off")
	}
}

func TestPerNetworkOverride(t *testing.T) {
	p := Policy{Rules: Rules{
		Default:  Limits{MaxTxSat: satPtr("1000")},
		Networks: []NetworkRule{{Network: "regtest", Limits: Limits{MaxTxSat: satPtr("5000")}}},
	}}
	// On regtest the override (5000) applies: 2000 is allowed.
	if d := Evaluate(p, Check{Network: "regtest", Recipient: recipA, AmountSat: 2000, FeeSat: 0}, nil, fixedClock()()); !d.Allowed {
		t.Fatalf("regtest override should allow 2000: %+v", d)
	}
	// On mainnet the default (1000) applies: 2000 is denied.
	if d := Evaluate(p, Check{Network: "mainnet", Recipient: recipA, AmountSat: 2000, FeeSat: 0}, nil, fixedClock()()); d.Allowed {
		t.Fatal("mainnet default should deny 2000")
	}
}

func TestPerNetworkNullLiftsLimit(t *testing.T) {
	null := nullSentinel
	p := Policy{Rules: Rules{
		Default:  Limits{MaxTxSat: satPtr("1000")},
		Networks: []NetworkRule{{Network: "regtest", Limits: Limits{MaxTxSat: &null}}},
	}}
	// regtest null ⇒ no limit; a huge spend passes.
	if d := Evaluate(p, Check{Network: "regtest", Recipient: recipA, AmountSat: 1_000_000, FeeSat: 0}, nil, fixedClock()()); !d.Allowed {
		t.Fatalf("null per-network limit must lift the cap: %+v", d)
	}
}

// ── engine Reserve / counters: rolling-24h durable + fail-closed ─────────────

func TestReserveCommitAccumulatesWindow(t *testing.T) {
	eng, _ := testEngine(t, "admin", nil)
	// max_day = 1000, allowlist off, no per-tx.
	setLimits(t, eng, "admin", &Limits{MaxDaySat: satPtr("1000"), AllowlistOn: boolPtr(false)})
	ctx := context.Background()

	// First send: 600 (amount 550 + fee 50). Reserve + Commit.
	r1, err := eng.Reserve(ctx, Check{Network: "regtest", Recipient: recipA, AmountSat: 550, FeeSat: 50})
	if err != nil {
		t.Fatalf("reserve 1: %v", err)
	}
	if err := r1.Commit(ctx, "txid1"); err != nil {
		t.Fatal(err)
	}

	// Second send: 500 (amount 450 + fee 50). 600+500 = 1100 > 1000 ⇒ DENIED (exit 3).
	_, err = eng.Reserve(ctx, Check{Network: "regtest", Recipient: recipB, AmountSat: 450, FeeSat: 50})
	if err == nil {
		t.Fatal("second send over the day limit must be denied")
	}
	de := domain.AsError(err)
	if de.Code != codeDeniedDayLimit || de.Exit != domain.ExitPolicyDenied {
		t.Fatalf("second send: code=%s exit=%d; want %s / exit 3", de.Code, de.Exit, codeDeniedDayLimit)
	}
}

func TestReleaseFreesWindow(t *testing.T) {
	eng, _ := testEngine(t, "admin", nil)
	setLimits(t, eng, "admin", &Limits{MaxDaySat: satPtr("1000"), AllowlistOn: boolPtr(false)})
	ctx := context.Background()

	// Reserve 600, then RELEASE it (a pre-sign failure) — the budget is freed.
	r1, err := eng.Reserve(ctx, Check{Network: "regtest", Recipient: recipA, AmountSat: 550, FeeSat: 50})
	if err != nil {
		t.Fatal(err)
	}
	if err := r1.Release(ctx); err != nil {
		t.Fatal(err)
	}

	// Now a 900 send fits (the released 600 no longer counts).
	r2, err := eng.Reserve(ctx, Check{Network: "regtest", Recipient: recipB, AmountSat: 850, FeeSat: 50})
	if err != nil {
		t.Fatalf("after release a 900 send should fit: %v", err)
	}
	_ = r2
}

func TestCounterFailsClosedOnCorruption(t *testing.T) {
	eng, _ := testEngine(t, "admin", nil)
	setLimits(t, eng, "admin", &Limits{MaxDaySat: satPtr("1000"), AllowlistOn: boolPtr(false)})
	ctx := context.Background()

	// Create a counter file with one reservation.
	r1, _ := eng.Reserve(ctx, Check{Network: "regtest", Recipient: recipA, AmountSat: 100, FeeSat: 1})
	_ = r1.Commit(ctx, "tx")

	// Corrupt the counter file (an attacker zeroing/garbling it to re-widen the
	// window must NOT silently succeed).
	cpath := eng.counterPath("regtest")
	if err := os.WriteFile(cpath, []byte("{ this is not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := eng.Reserve(ctx, Check{Network: "regtest", Recipient: recipB, AmountSat: 1, FeeSat: 1})
	if got := domain.AsError(err).Code; got != codeStateError {
		t.Fatalf("corrupt counter: code=%s want %s (fail-closed)", got, codeStateError)
	}
}

func TestCheckWritesNoReservation(t *testing.T) {
	eng, _ := testEngine(t, "admin", nil)
	setLimits(t, eng, "admin", &Limits{MaxDaySat: satPtr("1000"), AllowlistOn: boolPtr(false)})
	ctx := context.Background()

	// A dry-run Check must not persist a counter entry.
	d, err := eng.Check(ctx, Check{Network: "regtest", Recipient: recipA, AmountSat: 100, FeeSat: 1})
	if err != nil || !d.Allowed {
		t.Fatalf("check: %+v err=%v", d, err)
	}
	if _, statErr := os.Stat(eng.counterPath("regtest")); statErr == nil {
		t.Fatal("Check must NOT write a counter file")
	}
}

func TestOrphanReconcile(t *testing.T) {
	eng, _ := testEngine(t, "admin", nil)
	setLimits(t, eng, "admin", &Limits{AllowlistOn: boolPtr(false)})
	ctx := context.Background()

	r1, _ := eng.Reserve(ctx, Check{Network: "regtest", Recipient: recipA, AmountSat: 10, FeeSat: 1})
	// Left reserved (a crash) — Orphans should surface it.
	orphans, err := eng.Orphans(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(orphans) != 1 || orphans[0].ID != r1.ID() {
		t.Fatalf("orphans = %+v; want [%s]", orphans, r1.ID())
	}
	// Reconcile: commit it.
	if err := eng.CommitOrphan(ctx, "regtest", r1.ID(), "txid"); err != nil {
		t.Fatal(err)
	}
	orphans, _ = eng.Orphans(ctx)
	if len(orphans) != 0 {
		t.Fatalf("after commit, no orphans expected: %+v", orphans)
	}
}
