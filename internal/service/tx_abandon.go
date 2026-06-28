package service

import (
	"context"
	"errors"

	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/journal"
	"github.com/daxchain-io/daxib/internal/policy"
)

// tx_abandon.go is the GAP-1 operator escape hatch: `tx abandon <txid>`. A
// signed-but-never-broadcast tx is otherwise auto-rebroadcast forever (reconcileWallet
// re-submits every `signed` record) and its inputs are permanently excluded from
// coin-selection (reservedOutpoints excludes every non-terminal record's inputs),
// with no recourse. AbandonTx terminalizes such a record `failed` — freeing its UTXOs
// for re-selection — and releases its policy reservation (refunding the rolling-24h
// budget the never-sent spend held).
//
// CONSERVATIVE / fail-closed: it REFUSES a record with ANY recorded broadcast
// (status broadcast/confirmed/replaced). Those bytes reached the network and MAY
// still confirm; abandoning them (freeing the inputs + budget) could double-spend a
// live payment. Only a `signed` record — journaled BEFORE broadcast, with no recorded
// broadcast — is abandonable. This mirrors abortSigned's invariant (never terminalize
// a recorded broadcast) and the orphan reconciler's POL-1 posture.

// AbandonTx implements `tx abandon <txid>`. It runs under the per-wallet+network
// send-lock so it cannot race an in-flight send's reconcile/selection. It returns
// ref.not_found for an unknown txid and tx.already_broadcast (exit 9) for a record
// that already reached broadcast.
func (s *Service) AbandonTx(ctx context.Context, p domain.Principal, req domain.AbandonRequest) (domain.AbandonResult, error) {
	if err := s.requireNetwork(); err != nil {
		return domain.AbandonResult{}, err
	}
	if req.Txid == "" {
		return domain.AbandonResult{}, domain.New(domain.CodeRefNotFound, "a txid is required")
	}
	wallet, err := s.resolveWallet(ctx, req.Wallet)
	if err != nil {
		return domain.AbandonResult{}, err
	}

	// Operator confirmation: abandoning is irreversible (it terminalizes the record
	// and frees its inputs). Non-TTY without --yes is a clean confirmation error.
	if !req.Yes {
		isTTY := s.secret.IsTTY != nil && s.secret.IsTTY()
		if !isTTY {
			return domain.AbandonResult{}, domain.New(domain.CodeUsageConfirmRequired,
				"tx abandon is irreversible: pass --yes to authorize abandoning this signed tx")
		}
	}

	if s.journal == nil {
		return domain.AbandonResult{}, domain.New(domain.CodeRefNotFound, "no journal is configured")
	}

	// Serialize against any in-flight send/reconcile for this wallet+network: take the
	// send-lock BEFORE reading + mutating the record, exactly as the send pipeline does.
	unlock, lerr := s.acquireSendLock(ctx, s.net, wallet)
	if lerr != nil {
		return domain.AbandonResult{}, lerr
	}
	defer unlock()

	rec, jerr := s.journal.ByTxid(ctx, s.net, req.Txid)
	if jerr != nil {
		if errors.Is(jerr, journal.ErrNotFound) {
			return domain.AbandonResult{}, domain.Newf(domain.CodeRefNotFound,
				"no journaled transaction %q on %s to abandon", req.Txid, s.net)
		}
		return domain.AbandonResult{}, jerr
	}
	if rec.Wallet != wallet {
		return domain.AbandonResult{}, domain.Newf(domain.CodeRefNotFound,
			"transaction %q does not belong to wallet %q", req.Txid, wallet)
	}

	// REFUSE any record with a recorded broadcast (or already terminal): a tx on the
	// network may still confirm and must NEVER be abandoned. Only `signed` (no recorded
	// broadcast) is abandonable.
	if rec.Status != journal.StatusSigned {
		return domain.AbandonResult{}, domain.WithData(
			domain.Newf(domain.CodeTxAlreadyBroadcast,
				"refusing to abandon transaction %q: it is %s (a recorded broadcast may still confirm); only a never-broadcast signed tx is abandonable",
				req.Txid, rec.Status),
			map[string]any{"txid": req.Txid, "status": string(rec.Status), "journal_id": rec.ID})
	}

	// REFUSE a `signed` record whose reservation is COMMITTED (GAP-1 double-spend).
	// The send pipeline commits the reservation BEFORE writing SetState(broadcast); a
	// crash/SetState-failure between those two durable writes leaves the record at
	// `signed` while the bytes are live on the network. A committed reservation is the
	// authoritative live-broadcast signal — `signed` ALONE does not mean never-sent.
	// Terminalizing here would free the inputs of a live tx for re-selection (a fresh
	// send could double-spend them). Fail CLOSED: a committed reservation, or any
	// inability to positively prove the reservation is NOT committed, refuses the
	// abandon. (No reservation id ⇒ no committed spend possible ⇒ allowed.)
	if rec.ReservationID != "" {
		eng, perr := s.openPolicyEngine(ctx)
		if perr != nil {
			return domain.AbandonResult{}, perr
		}
		state, found, serr := eng.ReservationState(ctx, string(s.net), rec.ReservationID)
		if serr != nil {
			return domain.AbandonResult{}, serr
		}
		if found && state == policy.CommittedState {
			return domain.AbandonResult{}, domain.WithData(
				domain.Newf(domain.CodeTxAlreadyBroadcast,
					"refusing to abandon transaction %q: its spend reservation is committed (the send committed before journaling the broadcast — the bytes may be live on the network); rebroadcast or wait it out instead",
					req.Txid),
				map[string]any{"txid": req.Txid, "status": string(rec.Status), "journal_id": rec.ID, "reservation_committed": true})
		}
	}

	// Terminalize the record `failed` (frees its inputs for re-selection) FIRST, so the
	// reservation release can never run against a record that is still selection-blocking.
	reason := "operator abandoned a never-broadcast signed tx (tx abandon)"
	if serr := s.journal.SetState(ctx, s.net, rec.ID, journal.StateMutation{Status: journal.StatusFailed, Error: &reason}); serr != nil {
		return domain.AbandonResult{}, serr
	}

	// Release the policy reservation (refund the rolling-24h budget the never-sent
	// spend held). Safe: we already refused above when the reservation is COMMITTED, so
	// only a still-`reserved` row reaches here; ReleaseOrphan additionally refuses any
	// COMMITTED row as a backstop. With no active policy the reservation id is empty and
	// there is nothing to release.
	released := false
	if rec.ReservationID != "" {
		if eng, perr := s.openPolicyEngine(ctx); perr == nil {
			if rerr := eng.ReleaseOrphan(ctx, string(s.net), rec.ReservationID); rerr == nil {
				released = true
			}
		}
	}

	return domain.AbandonResult{
		JournalID:           rec.ID,
		Txid:                rec.Txid,
		Network:             s.net,
		Wallet:              wallet,
		FreedInputs:         len(rec.Inputs),
		ReservationReleased: released,
	}, nil
}
