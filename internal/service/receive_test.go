package service

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	fakebackend "github.com/daxchain-io/daxib/internal/backend/fake"
	"github.com/daxchain-io/daxib/internal/domain"
)

// arriveAfterFirstPoll programs the fake so the given UTXOs are ABSENT on the first
// UTXOs poll (the listen-start baseline) and PRESENT on every poll thereafter —
// simulating an inbound that lands AFTER listening began. This is the contract the
// receive engine detects against (RECV-1: a delta "since listening", not a stale
// pre-existing balance).
func arriveAfterFirstPoll(fake *fakebackend.Client, addr string, utxos []domain.UTXO) {
	var mu sync.Mutex
	polls := 0
	fake.UTXOsFn = func(_ context.Context, addrs []string) ([]domain.UTXO, error) {
		mu.Lock()
		polls++
		first := polls == 1
		mu.Unlock()
		if first {
			return nil, nil // baseline poll: address is empty
		}
		var out []domain.UTXO
		for _, a := range addrs {
			if a == addr {
				out = append(out, utxos...)
			}
		}
		return out, nil
	}
}

// canonicalReceive1 is the canonical-vector wallet's receive-1 address
// (m/84'/0'/0'/0/1). Import materializes receive-0, so `receive` PEEKs the next
// UNUSED receive index — index 1 — for a freshly imported wallet.
const canonicalReceive1 = "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"

// TestReceiveDetectsInbound is the load-bearing receive test: it imports the
// canonical-vector wallet, programs the FAKE backend to return a confirmed inbound
// UTXO to the address `receive` PEEKs (receive-1, since import materialized
// receive-0), and asserts svc.Receive blocks, detects the payment, and completes
// (exit 0) with the right confirmed total — the full keys→backend→detection loop
// with no live node.
func TestReceiveDetectsInbound(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	svc, done := newSendService(t, fake)
	defer done()

	// A confirmed 150000-sat inbound that arrives AFTER listening began (absent on the
	// baseline poll, present thereafter) — the delta the receive engine detects.
	arriveAfterFirstPoll(fake, canonicalReceive1, []domain.UTXO{{
		Txid: "deadbeef", Vout: 0, Address: canonicalReceive1,
		ValueSat: 150000, Height: 799994, Confirmations: 7,
	}})

	var kinds []domain.ReceiveEventKind
	sink := func(ev domain.ReceiveEvent) { kinds = append(kinds, ev.Kind) }

	res, err := svc.Receive(context.Background(), domain.ReceiveRequest{
		Wallet:       "vec",
		Amount:       "150000sat",
		PollInterval: domain.Duration{D: time.Millisecond},
	}, sink)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}

	if res.Status != "complete" || res.Exit != int(domain.ExitOK) {
		t.Fatalf("status=%q exit=%d; want complete/0", res.Status, res.Exit)
	}
	if res.Address != canonicalReceive1 {
		t.Errorf("address=%q; want the peeked receive-1 %q", res.Address, canonicalReceive1)
	}
	if res.ConfirmedSat != 150000 {
		t.Errorf("confirmed_sat=%d; want 150000", res.ConfirmedSat)
	}
	if res.RemainingSat != 0 {
		t.Errorf("remaining_sat=%d; want 0", res.RemainingSat)
	}
	if res.ConfirmedBTC != "0.00150000" {
		t.Errorf("confirmed_btc=%q; want 0.00150000", res.ConfirmedBTC)
	}

	// The stream led with listening (address up front) and ended with complete.
	if len(kinds) == 0 || kinds[0] != domain.RecvListening {
		t.Fatalf("first event = %v; want listening", kinds)
	}
	if kinds[len(kinds)-1] != domain.RecvComplete {
		t.Fatalf("terminal event = %v; want complete", kinds[len(kinds)-1])
	}
	if !containsKind(kinds, domain.RecvDetected) || !containsKind(kinds, domain.RecvConfirmed) {
		t.Errorf("stream %v missing detected/confirmed", kinds)
	}
}

// TestReceiveAnyInbound proves the no-amount (any-inbound) mode completes on any
// confirmed inbound.
func TestReceiveAnyInbound(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	svc, done := newSendService(t, fake)
	defer done()

	arriveAfterFirstPoll(fake, canonicalReceive1, []domain.UTXO{{
		Txid: "cafe", Vout: 1, Address: canonicalReceive1,
		ValueSat: 5000, Height: 799999, Confirmations: 2,
	}})

	res, err := svc.Receive(context.Background(), domain.ReceiveRequest{
		Wallet: "vec", PollInterval: domain.Duration{D: time.Millisecond},
	}, nil)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if res.Status != "complete" || res.ConfirmedSat != 5000 {
		t.Fatalf("status=%q confirmed=%d; want complete/5000", res.Status, res.ConfirmedSat)
	}
}

// TestReceiveTimeout proves a bounded --timeout with no inbound returns the
// resumable timeout outcome (exit 8, not a Go error).
func TestReceiveTimeout(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	svc, done := newSendService(t, fake)
	defer done()
	// No UTXOs programmed: nothing ever arrives.

	res, err := svc.Receive(context.Background(), domain.ReceiveRequest{
		Wallet:       "vec",
		Amount:       "1000sat",
		Timeout:      domain.Duration{D: 20 * time.Millisecond},
		PollInterval: domain.Duration{D: 5 * time.Millisecond},
	}, nil)
	if err != nil {
		t.Fatalf("Receive returned a Go error for a timeout (should be (result,nil)): %v", err)
	}
	if res.Status != "timeout" || res.Exit != int(domain.ExitTimeoutPending) {
		t.Fatalf("status=%q exit=%d; want timeout/%d", res.Status, res.Exit, int(domain.ExitTimeoutPending))
	}
}

// TestReceiveUnconfirmedDoesNotComplete proves a payment below the confirmation
// target is detected but does NOT satisfy the (confirmed) target — it stays pending
// until the timeout.
func TestReceiveUnconfirmedDoesNotComplete(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	svc, done := newSendService(t, fake)
	defer done()

	// An inbound that arrives after listening but is still in the mempool (0
	// confirmations) — below the conf=1 default, so the confirmed cumulative stays 0.
	arriveAfterFirstPoll(fake, canonicalReceive1, []domain.UTXO{{
		Txid: "ee", Vout: 0, Address: canonicalReceive1,
		ValueSat: 9000, Height: 0, Confirmations: 0,
	}})

	res, err := svc.Receive(context.Background(), domain.ReceiveRequest{
		Wallet:       "vec",
		Amount:       "9000sat",
		Timeout:      domain.Duration{D: 20 * time.Millisecond},
		PollInterval: domain.Duration{D: 5 * time.Millisecond},
	}, nil)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if res.Status != "timeout" {
		t.Fatalf("status=%q; want timeout (an unconfirmed inbound must not complete a confirmed target)", res.Status)
	}
	if res.ConfirmedSat != 0 {
		t.Errorf("confirmed_sat=%d; want 0 (the inbound is unconfirmed)", res.ConfirmedSat)
	}
}

// TestReceivePreFundedTimesOut is the RECV-1 regression: an address that ALREADY
// holds a confirmed UTXO when listening begins must NOT complete on that stale
// balance — detection is on the delta "since listening". With a bounded timeout and
// no new inbound, the outcome is timeout (exit 8), never a stale-balance complete.
func TestReceivePreFundedTimesOut(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	svc, done := newSendService(t, fake)
	defer done()

	// Pre-fund the receive address with a confirmed UTXO present from the very first
	// poll (the baseline) — and never deliver anything new.
	fake.UTXOsByAddr[canonicalReceive1] = []domain.UTXO{{
		Txid: "stale", Vout: 0, Address: canonicalReceive1,
		ValueSat: 150000, Height: 799994, Confirmations: 7,
	}}

	res, err := svc.Receive(context.Background(), domain.ReceiveRequest{
		Wallet:       "vec",
		Amount:       "150000sat",
		Timeout:      domain.Duration{D: 20 * time.Millisecond},
		PollInterval: domain.Duration{D: 5 * time.Millisecond},
	}, nil)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if res.Status != "timeout" || res.Exit != int(domain.ExitTimeoutPending) {
		t.Fatalf("status=%q exit=%d; want timeout/%d (a pre-existing confirmed balance must NOT complete)",
			res.Status, res.Exit, int(domain.ExitTimeoutPending))
	}
	if res.ConfirmedSat != 0 {
		t.Errorf("confirmed_sat=%d; want 0 (the pre-existing UTXO is baseline, not a payment)", res.ConfirmedSat)
	}
}

// TestReceiveEventShapeStable is the RECV-2 / RECV-JSON-1 regression: every event on
// the receive NDJSON stream marshals with the SAME stable key set (vout, value_sat,
// confirmations no longer drop on zero), and every decimal-string field (value_btc,
// confirmed_btc) is a valid decimal like "0.00000000" — never the empty string — on
// EVERY event including the non-payment listening/complete lines.
func TestReceiveEventShapeStable(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	svc, done := newSendService(t, fake)
	defer done()

	arriveAfterFirstPoll(fake, canonicalReceive1, []domain.UTXO{{
		Txid: "deadbeef", Vout: 0, Address: canonicalReceive1,
		ValueSat: 150000, Height: 799994, Confirmations: 7,
	}})

	var events []domain.ReceiveEvent
	sink := func(ev domain.ReceiveEvent) { events = append(events, ev) }

	if _, err := svc.Receive(context.Background(), domain.ReceiveRequest{
		Wallet:       "vec",
		Amount:       "150000sat",
		PollInterval: domain.Duration{D: time.Millisecond},
	}, sink); err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("no events emitted")
	}

	var wantKeys string
	for i, ev := range events {
		b, err := json.Marshal(ev)
		if err != nil {
			t.Fatalf("marshal event %d (%s): %v", i, ev.Kind, err)
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("unmarshal event %d: %v", i, err)
		}

		// The numeric/decimal keys present on EVERY event (the stable contract).
		for _, k := range []string{"vout", "value_sat", "value_btc", "confirmations", "confirmed_sat", "confirmed_btc", "remaining_sat"} {
			if _, ok := m[k]; !ok {
				t.Errorf("event %d (%s) is missing the stable key %q: %s", i, ev.Kind, k, b)
			}
		}
		// Decimal-string fields must be a valid decimal, never "".
		if ev.ValueBTC == "" {
			t.Errorf("event %d (%s) value_btc is empty (want a decimal like 0.00000000)", i, ev.Kind)
		}
		if ev.ConfirmedBTC == "" {
			t.Errorf("event %d (%s) confirmed_btc is empty (want a decimal)", i, ev.Kind)
		}
		if !strings.Contains(ev.ConfirmedBTC, ".") {
			t.Errorf("event %d (%s) confirmed_btc=%q is not a decimal", i, ev.Kind, ev.ConfirmedBTC)
		}

		keys := make([]string, 0, len(m))
		for k := range m {
			// event/address/target/txid/exit are legitimately kind-specific
			// (omitempty); the assertion is over the always-present numeric set above.
			switch k {
			case "event", "address", "network", "target", "txid", "exit":
				continue
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		got := strings.Join(keys, ",")
		if wantKeys == "" {
			wantKeys = got
		} else if got != wantKeys {
			t.Errorf("event %d (%s) numeric key set %q != %q", i, ev.Kind, got, wantKeys)
		}
	}
}

func containsKind(kinds []domain.ReceiveEventKind, want domain.ReceiveEventKind) bool {
	for _, k := range kinds {
		if k == want {
			return true
		}
	}
	return false
}
