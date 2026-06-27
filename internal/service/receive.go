package service

import (
	"context"
	"sort"
	"time"

	"github.com/daxchain-io/daxib/internal/backend"
	"github.com/daxchain-io/daxib/internal/domain"
)

// receive.go is the `daxib receive` engine: the inbound counterpart that completes
// the agent-to-agent payment loop (the Bitcoin sibling of daxie's receive engine,
// reframed for the UTXO model). It resolves or derives a receive address, emits it
// UP FRONT (so a counterparty can be handed it before the command blocks), then
// polls the backend's UTXO view until the cumulative CONFIRMED inbound to that
// address reaches the target (or any single confirmed inbound, in the any-inbound
// mode) — or the bounded --timeout hits, which is NOT an error (exit 8, resumable
// by re-running: detection is stateless, it re-reads the live UTXO set each poll).
//
// All detection lives HERE in the core (the arch matrix forbids the cli frontend
// from importing a backend), so the cli is a thin host that wires the stream sink.

// defaultReceivePoll is the backend poll cadence when the request leaves it unset.
const defaultReceivePoll = 5 * time.Second

// Receive blocks until the resolved receive address is paid (and confirms) or the
// optional timeout hits. It streams listening → detected → confirmed → complete (or
// timeout) events through sink and returns the terminal result. A timeout returns
// (result, nil) with result.Exit==8 (the terminal event is already emitted) — the
// caller projects the exit; only true failures (bad wallet, rpc.unreachable,
// keystore.read_only on --new) come back as a non-nil error.
func (s *Service) Receive(ctx context.Context, req domain.ReceiveRequest, sink domain.ReceiveEventSink) (domain.ReceiveResult, error) {
	wallet, err := s.resolveWallet(ctx, req.Wallet)
	if err != nil {
		return domain.ReceiveResult{}, err
	}
	if err := s.assertWalletNetwork(ctx, wallet); err != nil {
		return domain.ReceiveResult{}, err
	}

	// Resolve the receive address: --new derives (a keystore write — requires a
	// writable keystore); otherwise PEEK the next-unused receive index so a no-op
	// listen burns nothing.
	var address string
	if req.New {
		d, derr := s.keys.DeriveNext(ctx, wallet, s.net, domain.BranchReceive)
		if derr != nil {
			return domain.ReceiveResult{}, derr
		}
		address = d.Address
	} else {
		d, derr := s.keys.PeekNext(ctx, wallet, s.net, domain.BranchReceive)
		if derr != nil {
			return domain.ReceiveResult{}, derr
		}
		address = d.Address
	}

	// Resolve the completion target (amount + confirmations + timeout view).
	var targetSat int64
	if req.Amount != "" {
		targetSat, err = domain.ParseAmountToSats(req.Amount)
		if err != nil {
			return domain.ReceiveResult{}, err
		}
	}
	confTarget := domain.DefaultReceiveConfirmations
	if req.Confirmations != nil {
		confTarget = *req.Confirmations
	}
	target := domain.ReceiveTarget{
		AmountSat:     targetSat,
		AmountBTC:     domain.SatsToBTC(targetSat),
		Confirmations: confTarget,
		Timeout:       timeoutView(req.Timeout),
	}

	// Emit the listening event UP FRONT (the address is the share value).
	emitRecv(sink, domain.ReceiveEvent{
		Kind:    domain.RecvListening,
		Address: address,
		Network: string(s.net),
		Target:  &target,
	})

	return s.receiveLoop(ctx, wallet, address, target, req, sink)
}

// receiveLoop is the poll body: dial the backend, then on each tick re-read the
// receive address's UTXOs, classify confirmed vs pending, emit detected/confirmed
// transitions, and finish when the target is met (complete, exit 0) or the deadline
// hits (timeout, exit 8). It owns the dialed client for its lifetime.
func (s *Service) receiveLoop(ctx context.Context, wallet, address string, target domain.ReceiveTarget, req domain.ReceiveRequest, sink domain.ReceiveEventSink) (domain.ReceiveResult, error) {
	client, _, _, err := s.dialActiveBackend(ctx)
	if err != nil {
		return domain.ReceiveResult{}, err
	}
	defer client.Close()

	poll := defaultReceivePoll
	if req.PollInterval.D > 0 {
		poll = req.PollInterval.D
	}
	var deadline time.Time
	if req.Timeout.D > 0 {
		deadline = s.clock().Add(req.Timeout.D)
	}

	// seen tracks every outpoint we have already announced via a detected event so a
	// re-poll does not re-emit it; confirmedSeen tracks the ones already announced
	// confirmed. Both keep the stream idempotent across the (stateless) re-reads.
	seen := map[string]bool{}
	confirmedSeen := map[string]bool{}

	// baseline is the set of outpoints ALREADY present at the address when listening
	// began. Detection counts only outpoints NOT in the baseline, so a pre-existing
	// confirmed balance never produces a false-positive "complete" (RECV-1) — we
	// detect on the delta "since listening", mirroring daxie's receive engine. It is
	// captured on the first poll (nil until then) under the live UTXO read.
	var baseline map[string]bool

	for {
		payments, confirmedSat, perr := s.pollReceive(ctx, client, address, target.Confirmations, sink, seen, confirmedSeen, &baseline)
		if perr != nil {
			return domain.ReceiveResult{}, perr
		}

		if receiveSatisfied(target, confirmedSat) {
			return s.finishReceive(wallet, address, target, payments, confirmedSat, domain.RecvComplete, sink), nil
		}

		// Not yet satisfied — wait for the next tick, honoring the deadline + cancel.
		if !deadline.IsZero() && !s.clock().Before(deadline) {
			return s.finishReceive(wallet, address, target, payments, confirmedSat, domain.RecvTimeout, sink), nil
		}
		if werr := s.sleepReceive(ctx, poll, deadline); werr != nil {
			if werr == errReceiveDeadline {
				return s.finishReceive(wallet, address, target, payments, confirmedSat, domain.RecvTimeout, sink), nil
			}
			return domain.ReceiveResult{}, werr // context canceled (Ctrl-C / SIGTERM)
		}
	}
}

// pollReceive reads the address's UTXOs once, emits a detected event for each newly
// seen inbound and a confirmed event for each that newly reaches the confirmation
// target, and returns the current payment set + the cumulative confirmed satoshis.
//
// *baseline holds the outpoints already present at listen-start: on the FIRST poll
// (it is nil) every UTXO currently at the address is recorded as baseline and
// NOTHING is detected/counted (a stale pre-existing balance is not a payment "since
// listening", closing RECV-1). On later polls only outpoints absent from the
// baseline are detected and accumulated into confirmedSat.
func (s *Service) pollReceive(ctx context.Context, client backend.Client, address string, confTarget uint64, sink domain.ReceiveEventSink, seen, confirmedSeen map[string]bool, baseline *map[string]bool) ([]domain.DetectedPayment, int64, error) {
	utxos, err := client.UTXOs(ctx, []string{address})
	if err != nil {
		return nil, 0, err
	}
	firstPoll := *baseline == nil
	if firstPoll {
		*baseline = make(map[string]bool, len(utxos))
	}
	payments := make([]domain.DetectedPayment, 0, len(utxos))
	var confirmedSat int64
	for _, u := range utxos {
		key := u.Txid + ":" + domain.IndexString(u.Vout)
		if firstPoll {
			// Record everything already at the address as the "since listening"
			// baseline; do not detect or count any of it.
			(*baseline)[key] = true
			continue
		}
		if (*baseline)[key] {
			// A pre-existing outpoint — never a payment that arrived after listening.
			continue
		}
		p := domain.DetectedPayment{
			Txid:          u.Txid,
			Vout:          u.Vout,
			ValueSat:      u.ValueSat,
			ValueBTC:      domain.SatsToBTC(u.ValueSat),
			Confirmations: u.Confirmations,
		}
		payments = append(payments, p)
		if !seen[key] {
			seen[key] = true
			emitRecv(sink, recvPaymentEvent(domain.RecvDetected, p, 0))
		}
		if u.Confirmations >= int64(confTarget) { //nolint:gosec // confTarget is a small config value
			confirmedSat += u.ValueSat
			if !confirmedSeen[key] {
				confirmedSeen[key] = true
				emitRecv(sink, recvPaymentEvent(domain.RecvConfirmed, p, confirmedSat))
			}
		}
	}
	sort.Slice(payments, func(i, j int) bool {
		if payments[i].Confirmations != payments[j].Confirmations {
			return payments[i].Confirmations > payments[j].Confirmations
		}
		return payments[i].Txid+":"+domain.IndexString(payments[i].Vout) <
			payments[j].Txid+":"+domain.IndexString(payments[j].Vout)
	})
	return payments, confirmedSat, nil
}

// finishReceive builds + emits the terminal event and returns the matching result.
func (s *Service) finishReceive(wallet, address string, target domain.ReceiveTarget, payments []domain.DetectedPayment, confirmedSat int64, kind domain.ReceiveEventKind, sink domain.ReceiveEventSink) domain.ReceiveResult {
	remaining := target.AmountSat - confirmedSat
	if remaining < 0 {
		remaining = 0
	}
	status := "complete"
	exit := int(domain.ExitOK)
	if kind == domain.RecvTimeout {
		status = "timeout"
		exit = int(domain.ExitTimeoutPending)
	}
	emitRecv(sink, domain.ReceiveEvent{
		Kind:         kind,
		Address:      address,
		ConfirmedSat: confirmedSat,
		ConfirmedBTC: domain.SatsToBTC(confirmedSat),
		RemainingSat: remaining,
		Exit:         &exit,
	})
	return domain.ReceiveResult{
		Address:      address,
		Wallet:       wallet,
		Network:      s.net,
		Target:       target,
		Status:       status,
		ConfirmedSat: confirmedSat,
		ConfirmedBTC: domain.SatsToBTC(confirmedSat),
		RemainingSat: remaining,
		Payments:     payments,
		Exit:         exit,
	}
}

// errReceiveDeadline is the sentinel sleepReceive returns when the bounded timeout
// elapses during a wait (distinct from a true context cancellation).
var errReceiveDeadline = domain.New("receive.timeout", "receive listen timed out")

// sleepReceive waits one poll interval, returning early with errReceiveDeadline if
// the bounded deadline falls inside the interval, or the ctx error on cancellation.
// It is the one place the loop blocks, so it is the single cancellation/timeout
// chokepoint (the clock is injected, but the actual wait uses a real timer bounded
// by the poll interval so tests with a fake clock still progress per tick).
func (s *Service) sleepReceive(ctx context.Context, poll time.Duration, deadline time.Time) error {
	wait := poll
	if !deadline.IsZero() {
		remaining := deadline.Sub(s.clock())
		if remaining <= 0 {
			return errReceiveDeadline
		}
		if remaining < wait {
			wait = remaining
		}
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		if !deadline.IsZero() && !s.clock().Before(deadline) {
			return errReceiveDeadline
		}
		return nil
	}
}

// receiveSatisfied reports whether the cumulative confirmed inbound meets the
// target. With no amount (any-inbound) any positive confirmed inbound satisfies it;
// with an amount the cumulative confirmed must reach it.
func receiveSatisfied(target domain.ReceiveTarget, confirmedSat int64) bool {
	if target.AmountSat <= 0 {
		return confirmedSat > 0
	}
	return confirmedSat >= target.AmountSat
}

// recvPaymentEvent builds a per-payment detected/confirmed event.
func recvPaymentEvent(kind domain.ReceiveEventKind, p domain.DetectedPayment, confirmedSat int64) domain.ReceiveEvent {
	return domain.ReceiveEvent{
		Kind:          kind,
		Txid:          p.Txid,
		Vout:          p.Vout,
		ValueSat:      p.ValueSat,
		ValueBTC:      p.ValueBTC,
		Confirmations: p.Confirmations,
		ConfirmedSat:  confirmedSat,
		ConfirmedBTC:  domain.SatsToBTC(confirmedSat),
	}
}

// timeoutView renders a Duration as the *string the listening target carries (nil
// ⇒ unbounded, the JSON-null case).
func timeoutView(d domain.Duration) *string {
	if d.D <= 0 {
		return nil
	}
	s := d.D.String()
	return &s
}

// emitRecv calls a receive sink, guarding nil (a non-streaming caller). It first
// normalizes the event's decimal-string fields so a non-payment event never ships a
// numeric-string field as "" — every value_btc/confirmed_btc on the stream is a
// valid decimal like "0.00000000" (RECV-JSON-1 / RECV-2: a stable string shape).
func emitRecv(sink domain.ReceiveEventSink, ev domain.ReceiveEvent) {
	if ev.ValueBTC == "" {
		ev.ValueBTC = domain.SatsToBTC(ev.ValueSat)
	}
	if ev.ConfirmedBTC == "" {
		ev.ConfirmedBTC = domain.SatsToBTC(ev.ConfirmedSat)
	}
	if sink != nil {
		sink(ev)
	}
}
