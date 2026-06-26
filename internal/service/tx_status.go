package service

import (
	"context"
	"errors"
	"time"

	"github.com/daxchain-io/daxib/internal/backend"
	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/journal"
)

// defaultConfirmations is the confirmation target a --wait uses when
// --confirmations is unset (1 = first confirmation).
const defaultConfirmations int64 = 1

// defaultWaitTimeout bounds a `tx wait` when --timeout is unset.
const defaultWaitTimeout = 30 * time.Minute

// waitPollInterval is the tx-wait poll cadence (no lock held — a read path). It
// is a var so tests can shorten it; production keeps the 5s cadence.
var waitPollInterval = 5 * time.Second

// TxStatus reports a transaction's state by folding the journal record with a
// fresh backend re-check. A journaled tx is reconciled (confirmations/height
// updated, and promoted to confirmed when the chain confirms it); a foreign txid
// that is on-chain returns its backend status without a journal row; an unknown
// txid is ref.not_found (exit 10).
func (s *Service) TxStatus(ctx context.Context, req domain.TxStatusRequest) (domain.TxResult, error) {
	client, _, _, err := s.dialActiveBackend(ctx)
	if err != nil {
		return domain.TxResult{}, err
	}
	defer client.Close()

	rec, jerr := s.journal.ByTxid(ctx, s.net, req.Txid)
	if jerr == nil {
		st, serr := client.TxStatus(ctx, req.Txid)
		if serr == nil && st.Confirmed && st.Confirmations >= defaultConfirmations && rec.Status != journal.StatusConfirmed {
			conf, bh := st.Confirmations, st.BlockHeight
			_ = s.journal.SetState(ctx, s.net, rec.ID, journal.StateMutation{
				Status: journal.StatusConfirmed, Confirmations: &conf, BlockHeight: &bh,
			})
		}
		return s.recordResult(rec, st), nil
	}
	if !errors.Is(jerr, journal.ErrNotFound) {
		return domain.TxResult{}, jerr
	}

	// Not in the journal — query the backend directly.
	st, serr := client.TxStatus(ctx, req.Txid)
	if serr != nil {
		return domain.TxResult{}, serr
	}
	if !st.Confirmed && st.BlockHeight == 0 && st.Confirmations == 0 {
		return domain.TxResult{}, domain.Newf(domain.CodeRefNotFound,
			"transaction %q is not in the journal and not found on-chain", req.Txid)
	}
	return domain.TxResult{
		Txid:          req.Txid,
		Network:       s.net,
		Status:        backendState(st),
		Confirmations: st.Confirmations,
		BlockHeight:   st.BlockHeight,
	}, nil
}

// ListTxs returns the journal's records for the active network (newest-first),
// optionally filtered by wallet.
func (s *Service) ListTxs(ctx context.Context, req domain.TxListRequest) (domain.TxListResult, error) {
	wallet := req.Wallet
	recs, err := s.journal.List(ctx, s.net, wallet)
	if err != nil {
		return domain.TxListResult{}, err
	}
	rows := make([]domain.TxRow, 0, len(recs))
	for _, r := range recs {
		if req.Limit > 0 && len(rows) >= req.Limit {
			break
		}
		rows = append(rows, domain.TxRow{
			JournalID:     r.ID,
			Txid:          r.Txid,
			Status:        domain.TxState(r.Status),
			To:            r.RecipientAddr,
			AmountSat:     r.RecipientSat,
			AmountBTC:     domain.SatsToBTC(r.RecipientSat),
			FeeSat:        r.FeeSat,
			Vsize:         r.Vsize,
			Confirmations: r.Confirmations,
			TS:            r.TS,
		})
	}
	return domain.TxListResult{Network: s.net, Wallet: wallet, Txs: rows}, nil
}

// WaitTx is the standalone `tx wait <txid>` use case: it folds the journal,
// rebroadcasts a still-`signed` record (the lost-broadcast window), then polls the
// backend until the confirmation target is met or the deadline hits.
func (s *Service) WaitTx(ctx context.Context, req domain.WaitRequest, sink domain.EventSink) (domain.TxResult, error) {
	client, _, _, err := s.dialActiveBackend(ctx)
	if err != nil {
		return domain.TxResult{}, err
	}
	defer client.Close()

	rec, jerr := s.journal.ByTxid(ctx, s.net, req.Txid)
	var journalID string
	if jerr == nil {
		journalID = rec.ID
	}
	opts := domain.WaitOpts{Enabled: true, Confirmations: req.Confirmations, Timeout: req.Timeout}
	return s.waitOnTxid(ctx, client, req.Txid, journalID, opts, sink)
}

// waitOnTxid polls the backend for txid until Confirmations >= the target or the
// deadline hits. If the journal record is still `signed` (the lost-broadcast
// window) it rebroadcasts the stored bytes FIRST through the shared classifier,
// then polls. On ctx cancel/SIGTERM it returns the CURRENT status as a successful
// result (not an error). On a true deadline it returns tx.wait_timeout (exit 8,
// retryable).
func (s *Service) waitOnTxid(ctx context.Context, client backend.Client, txid, journalID string, opts domain.WaitOpts, sink domain.EventSink) (domain.TxResult, error) {
	target := defaultConfirmations
	if opts.Confirmations != nil && *opts.Confirmations > 0 {
		target = *opts.Confirmations
	}
	timeout := defaultWaitTimeout
	if opts.Timeout.D > 0 {
		timeout = opts.Timeout.D
	}

	// Lazy resurrection: if the record is still `signed`, rebroadcast the stored
	// bytes before polling (a permanent reject during this surfaces immediately).
	if journalID != "" {
		if rec, err := s.journal.ByID(ctx, s.net, journalID); err == nil && rec.Status == journal.StatusSigned && rec.RawTx != "" {
			if raw, derr := decodeHex(rec.RawTx); derr == nil {
				emit(sink, "wait", "rebroadcasting stored signed tx "+rec.ID)
				outcome, btxid, berr := s.broadcastClassified(ctx, client, raw, sink)
				switch outcome {
				case outcomeAccepted:
					t := btxid
					if t == "" {
						t = txid
					}
					_ = s.journal.SetState(ctx, s.net, rec.ID, journal.StateMutation{Status: journal.StatusBroadcast, Txid: &t})
				case outcomeRejected:
					reason := ""
					if berr != nil {
						reason = berr.Error()
					}
					_ = s.journal.SetState(ctx, s.net, rec.ID, journal.StateMutation{Status: journal.StatusFailed, Error: &reason})
					return domain.TxResult{}, mapRejectErr(berr)
				}
			}
		}
	}

	deadline := s.clock().Add(timeout)
	ticker := time.NewTicker(waitPollInterval)
	defer ticker.Stop()

	// Poll immediately, then on each tick.
	for {
		st, err := client.TxStatus(ctx, txid)
		if err == nil {
			if st.Confirmed && st.Confirmations >= target {
				if journalID != "" {
					conf, bh := st.Confirmations, st.BlockHeight
					_ = s.journal.SetState(ctx, s.net, journalID, journal.StateMutation{
						Status: journal.StatusConfirmed, Confirmations: &conf, BlockHeight: &bh,
					})
				}
				emit(sink, "confirm", "confirmed at "+itoa64(st.Confirmations)+" confirmations")
				return s.waitResult(txid, journalID, domain.TxStateConfirmed, st), nil
			}
			emit(sink, "wait", "pending ("+itoa64(st.Confirmations)+"/"+itoa64(target)+" confirmations)")
		}

		if s.clock().After(deadline) {
			res := s.waitResult(txid, journalID, domain.TxStateTimeout, domain.TxStatus{Txid: txid})
			res.Resume = "daxib tx wait " + txid
			return res, domain.Newf(domain.CodeTxWaitTimeout,
				"timed out waiting for %d confirmation(s) of %s; resume with `daxib tx wait %s`", target, txid, txid)
		}

		select {
		case <-ctx.Done():
			// SIGTERM/cancel → return the current status as a SUCCESSFUL result so an
			// agent loop can resume, NOT an error.
			res := s.waitResult(txid, journalID, domain.TxStatePending, domain.TxStatus{Txid: txid})
			res.Resume = "daxib tx wait " + txid
			return res, nil
		case <-ticker.C:
		}
	}
}

// recordResult builds a TxResult from a journal record reconciled with a fresh
// backend status.
func (s *Service) recordResult(rec *journal.Record, st domain.TxStatus) domain.TxResult {
	status := domain.TxState(rec.Status)
	confirmations := rec.Confirmations
	blockHeight := rec.BlockHeight
	switch {
	case st.Confirmed:
		// The backend's current depth is authoritative — adopt it UNCONDITIONALLY,
		// even when it SHRANK (a chain reorg can reduce a tx's confirmation count;
		// CB-8). A stale higher count must never be retained.
		confirmations = st.Confirmations
		blockHeight = st.BlockHeight
		if st.Confirmations >= defaultConfirmations {
			status = domain.TxStateConfirmed
		} else {
			status = domain.TxStatePending
		}
	case (rec.Status == journal.StatusBroadcast || rec.Status == journal.StatusConfirmed) && st.Confirmations == 0 && st.BlockHeight == 0:
		// A previously broadcast/confirmed record that the backend now reports as
		// unconfirmed (0 confs) — a reorg dropped it back to the mempool. Demote to
		// pending and zero the stale depth rather than retaining `confirmed` (CB-8).
		status = domain.TxStatePending
		confirmations = 0
		blockHeight = 0
	}

	outs := make([]domain.TxOutputRef, 0, len(rec.Outputs))
	for _, o := range rec.Outputs {
		outs = append(outs, domain.TxOutputRef{Address: o.Address, ValueSat: o.ValueSat, Change: o.Change})
	}
	ins := make([]domain.TxInputRef, 0, len(rec.Inputs))
	for _, in := range rec.Inputs {
		ins = append(ins, domain.TxInputRef{
			Outpoint: in.Txid + ":" + domain.IndexString(in.Vout),
			Address:  in.Address,
			ValueSat: in.ValueSat,
		})
	}
	return domain.TxResult{
		Txid:          rec.Txid,
		Network:       s.net,
		Wallet:        rec.Wallet,
		To:            rec.RecipientAddr,
		AmountSat:     rec.RecipientSat,
		AmountBTC:     domain.SatsToBTC(rec.RecipientSat),
		FeeSat:        rec.FeeSat,
		FeeBTC:        domain.SatsToBTC(rec.FeeSat),
		FeeRate:       rec.FeeRate,
		Vsize:         rec.Vsize,
		ChangeSat:     changeOf(rec),
		ChangeAddress: rec.ChangeAddr,
		ChangeBTC:     changeBTC(rec),
		Inputs:        ins,
		Outputs:       outs,
		Status:        status,
		Confirmations: confirmations,
		BlockHeight:   blockHeight,
		JournalID:     rec.ID,
	}
}

// waitResult builds a TxResult for a wait outcome, folding the journal record when
// one exists.
func (s *Service) waitResult(txid, journalID string, status domain.TxState, st domain.TxStatus) domain.TxResult {
	if journalID != "" {
		if rec, err := s.journal.ByID(context.Background(), s.net, journalID); err == nil {
			res := s.recordResult(rec, st)
			res.Status = status
			if st.Confirmations > 0 {
				res.Confirmations = st.Confirmations
			}
			return res
		}
	}
	return domain.TxResult{
		Txid:          txid,
		Network:       s.net,
		Status:        status,
		Confirmations: st.Confirmations,
		BlockHeight:   st.BlockHeight,
	}
}

// backendState maps a backend TxStatus to the lifecycle TxState for a foreign tx.
func backendState(st domain.TxStatus) domain.TxState {
	if st.Confirmed {
		return domain.TxStateConfirmed
	}
	return domain.TxStatePending
}

// changeOf returns the change value recorded on a record (the change output's
// value, or 0 when folded into the fee).
func changeOf(rec *journal.Record) int64 {
	for _, o := range rec.Outputs {
		if o.Change {
			return o.ValueSat
		}
	}
	return 0
}

// changeBTC renders the change value as a BTC string, or "" when there is none.
func changeBTC(rec *journal.Record) string {
	c := changeOf(rec)
	if c == 0 {
		return ""
	}
	return domain.SatsToBTC(c)
}
