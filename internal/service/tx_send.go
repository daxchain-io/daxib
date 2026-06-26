package service

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"github.com/daxchain-io/daxib/internal/backend"
	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/fsx"
	"github.com/daxchain-io/daxib/internal/journal"
)

// sendLockTimeout bounds acquisition of the per-wallet+network send-lock. A
// timeout maps to state.lock_timeout (exit 11).
const sendLockTimeout = 30 * time.Second

// broadcast backoff schedule (transport-retry then leave `signed`).
var broadcastBackoff = []time.Duration{0, time.Second, 2 * time.Second, 4 * time.Second}

// SendTx is the M4 transaction-send pipeline (the lifecycle this area owns):
// resolve wallet+network → gather UTXOs, coin-select, build+sign → take the
// wallet send-lock → reconcile any prior `signed` record → journal(signed) BEFORE
// broadcast → broadcast (classified) → SetState(broadcast)/leave-signed/fail →
// optional --wait. The deferred settle/abort guard ensures exactly-one-of:
// terminalize on a permanent reject, leave `signed` on transport exhaustion (the
// recoverable, idempotent-rebroadcast case).
func (s *Service) SendTx(ctx context.Context, req domain.SendRequest, sink domain.EventSink) (domain.TxResult, error) {
	// Validate the amount + destination address FIRST — before wallet resolution or
	// any backend dial — so a malformed --amount/--to is a clean usage error (exit
	// 2) even with no wallet/node. The parsed values are recomputed in buildAndSign.
	if err := s.validateSendInputs(req); err != nil {
		return domain.TxResult{}, err
	}

	wallet, err := s.resolveWallet(ctx, req.Wallet)
	if err != nil {
		return domain.TxResult{}, err
	}
	if err := s.assertWalletNetwork(ctx, wallet); err != nil {
		return domain.TxResult{}, err
	}

	// A real send is a mutating op: non-TTY without --yes (and not --dry-run) is a
	// clean confirmation-required error, never a prompt hang.
	if !req.DryRun && !req.Yes {
		isTTY := s.secret.IsTTY != nil && s.secret.IsTTY()
		if !isTTY {
			return domain.TxResult{}, domain.New(domain.CodeUsageConfirmRequired,
				"a send requires confirmation: pass --yes to authorize this non-interactive send")
		}
	}

	client, backendName, _, err := s.dialActiveBackend(ctx)
	if err != nil {
		return domain.TxResult{}, err
	}
	defer client.Close()
	_ = backendName

	// Resolve the fee rate (explicit --fee-rate verbatim, else the backend estimate
	// by --speed, clamped to the relay floor).
	var est domain.FeeEstimates
	if req.FeeRate == "" {
		est, err = client.FeeEstimates(ctx)
		if err != nil {
			return domain.TxResult{}, err
		}
	}
	feeRate, err := resolveFeeRate(req.FeeRate, req.Speed, est)
	if err != nil {
		return domain.TxResult{}, err
	}

	// --dry-run: preview only — build+sign READ-ONLY (no lock, no journal, no
	// broadcast, and crucially no watermark advance: the change address is PEEKED, so
	// a no-op preview has no durable side effect).
	if req.DryRun {
		art, err := s.buildAndSign(ctx, wallet, client, req, feeRate, true, nil)
		if err != nil {
			return domain.TxResult{}, err
		}
		res := s.previewResult(wallet, art)
		emit(sink, "dry-run", "built tx "+art.txid+" (not broadcast)")
		return res, nil
	}

	// ── The send critical section: take the per-wallet+network send-lock FIRST so
	// the whole gather→select→sign→journal→broadcast sequence is serialized and two
	// concurrent invocations cannot select the same UTXOs.
	unlock, err := s.acquireSendLock(ctx, s.net, wallet)
	if err != nil {
		return domain.TxResult{}, err
	}
	defer unlock()

	// Reconcile any prior `signed` record FIRST, under the lock, BEFORE this new tx
	// is selected/journaled — a crashed prior send's identical bytes are rebroadcast
	// (flipping it to `broadcast`) and its inputs stay reserved.
	s.reconcileWallet(ctx, client, wallet, sink)

	// Compute the set of outpoints reserved by in-flight (non-terminal) journal
	// records for this wallet, so selection cannot re-pick a stranded send's inputs.
	// Runs under the send-lock AFTER reconcile so the set reflects any record reconcile
	// just flipped to `broadcast`.
	consumed := s.reservedOutpoints(ctx, wallet)

	// Build + sign the artifact UNDER THE LOCK: gather UTXOs, coin-select (excluding
	// reserved outpoints), allocate the change address (DeriveNext), and sign.
	art, err := s.buildAndSign(ctx, wallet, client, req, feeRate, false, consumed)
	if err != nil {
		return domain.TxResult{}, err
	}

	// Journal the new tx as `signed` BEFORE broadcast (crash here ⇒ recovery
	// rebroadcasts the same bytes).
	rec := s.journalRecord(wallet, art, feeRate)
	if err := s.journal.Append(ctx, rec); err != nil {
		return domain.TxResult{}, err
	}
	emit(sink, "signed", "journaled "+rec.ID+" (raw tx persisted)")

	settled := false
	defer func() {
		// Exactly-one-of settle/abort: if settled stayed false on an early/panic
		// return, mark the record failed — but ONLY when it is still `signed` (never
		// terminalize a recorded broadcast).
		if !settled {
			s.abortSigned(context.Background(), rec.ID)
		}
	}()

	outcome, txid, berr := s.broadcastClassified(ctx, client, art.rawTx, sink)
	switch outcome {
	case outcomeAccepted:
		t := txid
		if t == "" {
			// An already-known node may not echo the txid; the signed bytes' hash IS
			// the canonical txid.
			t = art.txid
		}
		// CRITICAL: the tx is now LIVE on-chain (Broadcast accepted it). Mark settled
		// BEFORE the SetState write — exactly as the transport-exhausted branch does —
		// so if SetState(broadcast) itself fails (a SIGINT/deadline/journal-lock race
		// after acceptance), the deferred abort cannot terminalize this accepted tx as
		// `failed`. It stays `signed` (recoverable): the next send-lock/reconcile or
		// `tx wait` rebroadcasts the SAME bytes → the node reports already-known →
		// accepted → flips to `broadcast`. An accepted-but-unrecorded broadcast must
		// resolve to `signed`, NEVER `failed`.
		settled = true
		if err := s.journal.SetState(ctx, s.net, rec.ID, journal.StateMutation{Status: journal.StatusBroadcast, Txid: &t}); err != nil {
			// The record remains `signed` with the live bytes; surface a recoverable
			// result + error so the caller resumes via `tx wait` (idempotent
			// rebroadcast) instead of treating the live tx as failed.
			res := s.signedResult(wallet, art, rec.ID)
			res.Txid = t
			return res, domain.WithData(
				domain.Wrap(domain.CodeBackendUnreachable,
					"broadcast accepted but recording it failed; the signed tx is journaled and will be reconciled on retry", err),
				map[string]any{"journal_id": rec.ID, "txid": t})
		}
		txid = t
		emit(sink, "broadcast", "accepted "+t)

	case outcomeTransportExhausted:
		// CRITICAL: mark settled BEFORE returning so the deferred abort cannot
		// terminalize this recoverable `signed` record. The bytes stay journaled for
		// an idempotent rebroadcast on the next send-lock acquisition or `tx wait`.
		settled = true
		res := s.signedResult(wallet, art, rec.ID)
		return res, domain.WithData(
			domain.Wrap(domain.CodeBackendUnreachable,
				"broadcast transport exhausted; the signed tx is journaled and will be rebroadcast on retry", berr),
			map[string]any{"journal_id": rec.ID, "txid": art.txid})

	case outcomeRejected:
		reason := rejectReason(berr)
		if err := s.journal.SetState(ctx, s.net, rec.ID, journal.StateMutation{Status: journal.StatusFailed, Error: &reason}); err != nil {
			return domain.TxResult{}, err
		}
		settled = true
		return domain.TxResult{}, mapRejectErr(berr)
	}

	// Accepted. Optional --wait.
	if req.Wait.Enabled {
		unlock() // release the send-lock before the (lock-free) poll loop
		return s.waitOnTxid(ctx, client, txid, rec.ID, req.Wait, sink)
	}
	return s.broadcastResult(wallet, art, rec.ID, txid), nil
}

// ── broadcast classifier ──────────────────────────────────────────────────────

type broadcastOutcome int

const (
	outcomeAccepted broadcastOutcome = iota
	outcomeTransportExhausted
	outcomeRejected
)

// broadcastClassified submits the raw tx with a 1s/2s/4s transport backoff and
// classifies the result. An accepted/already-known broadcast returns
// outcomeAccepted + the txid; a permanent reject returns outcomeRejected + the
// mapped error; transport exhaustion (after the backoff) returns
// outcomeTransportExhausted, leaving the record `signed` for idempotent
// rebroadcast.
func (s *Service) broadcastClassified(ctx context.Context, client backend.Client, raw []byte, sink domain.EventSink) (broadcastOutcome, string, error) {
	var lastErr error
	for i, d := range broadcastBackoff {
		if d > 0 {
			emit(sink, "broadcast", "retrying after transport error")
			select {
			case <-ctx.Done():
				return outcomeTransportExhausted, "", ctx.Err()
			case <-time.After(d):
			}
		}
		txid, err := client.Broadcast(ctx, raw)
		if err == nil {
			return outcomeAccepted, txid, nil
		}
		lastErr = err
		o, mapped, retry := classifyBroadcastErr(err)
		if o == outcomeAccepted {
			// "already known"/"already in mempool" — treat as accepted; recover the
			// txid from the tx bytes is the caller's job (we return empty here and the
			// caller uses art.txid). Use a sentinel: re-broadcast returns the txid the
			// node echoes, but already-known nodes often echo it too. Fall through to a
			// fresh Broadcast call result is not possible; return accepted with no txid
			// and let the caller fill art.txid.
			return outcomeAccepted, "", nil
		}
		if !retry {
			return outcomeRejected, "", mapped
		}
		_ = i
	}
	return outcomeTransportExhausted, "", lastErr
}

// classifyBroadcastErr maps a backend broadcast error to an outcome + a mapped
// domain error + whether it is transport-retryable. It reads the error string
// (Core sendrawtransaction reject reasons + Esplora 400 bodies) and the
// backend.unreachable class.
func classifyBroadcastErr(err error) (broadcastOutcome, error, bool) {
	if err == nil {
		return outcomeAccepted, nil, false
	}
	msg := strings.ToLower(err.Error())

	// Already-known: the chain has (or will have) it → accepted (idempotent).
	if strings.Contains(msg, "txn-already-in-mempool") ||
		strings.Contains(msg, "already in block chain") ||
		strings.Contains(msg, "transaction already in block chain") ||
		strings.Contains(msg, "already known") ||
		strings.Contains(msg, "txn-already-known") {
		return outcomeAccepted, nil, false
	}

	// Permanent rejects (NOT a rebroadcast-the-same-bytes class).
	switch {
	case strings.Contains(msg, "bad-txns-inputs-missingorspent") || strings.Contains(msg, "missing inputs") || strings.Contains(msg, "missing-inputs"):
		return outcomeRejected, domain.Wrap(domain.CodeTxInputSpent, "broadcast rejected: an input was already spent", err), false
	case strings.Contains(msg, "min relay fee not met") || strings.Contains(msg, "mempool min fee not met") || strings.Contains(msg, "insufficient fee") || strings.Contains(msg, "fee too low") || strings.Contains(msg, "min-relay"):
		return outcomeRejected, domain.Wrap(domain.CodeTxFeeTooLow, "broadcast rejected: fee below the relay floor", err), false
	case strings.Contains(msg, "dust") || strings.Contains(msg, "scriptpubkey") || strings.Contains(msg, "non-mandatory-script-verify") || strings.Contains(msg, "non-final") || strings.Contains(msg, "bad-txns"):
		return outcomeRejected, domain.Wrap(domain.CodeTxBroadcastRejected, "broadcast rejected by the network", err), false
	}

	// Transport: deadline/cancel, dial failure, 5xx, or a wrapped backend.unreachable.
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return outcomeTransportExhausted, domain.Wrap(domain.CodeBackendUnreachable, "broadcast transport failure", err), true
	}
	if de := domain.AsError(err); de != nil && de.Code == domain.CodeBackendUnreachable {
		return outcomeTransportExhausted, de, true
	}
	if strings.Contains(msg, "connection refused") || strings.Contains(msg, "timeout") || strings.Contains(msg, "no such host") || strings.Contains(msg, "eof") || strings.Contains(msg, "5") && strings.Contains(msg, "server error") {
		return outcomeTransportExhausted, domain.Wrap(domain.CodeBackendUnreachable, "broadcast transport failure", err), true
	}
	// An unclassified rpc_error from the backend: treat as a permanent reject so we
	// terminalize rather than spin (a genuinely transient error will have surfaced
	// as backend.unreachable above).
	return outcomeRejected, domain.Wrap(domain.CodeTxBroadcastRejected, "broadcast rejected by the backend", err), false
}

// rejectReason returns the human reject reason recorded on a failed journal
// record: the ROOT cause string (the network's actual reject message, e.g.
// "bad-txns-inputs-missingorspent"), not the wrapping domain envelope, so a `tx
// status`/`tx list` shows the operator why the network refused the tx.
func rejectReason(err error) string {
	if err == nil {
		return "broadcast rejected"
	}
	root := err
	for {
		un := errors.Unwrap(root)
		if un == nil {
			break
		}
		root = un
	}
	return root.Error()
}

// mapRejectErr ensures the returned error is a typed domain error (the classifier
// already produced one; this is a defensive funnel).
func mapRejectErr(err error) error {
	if err == nil {
		return domain.New(domain.CodeTxBroadcastRejected, "broadcast rejected")
	}
	if de := domain.AsError(err); de != nil {
		return de
	}
	return domain.Wrap(domain.CodeTxBroadcastRejected, "broadcast rejected", err)
}

// ── the wallet send-lock ──────────────────────────────────────────────────────

// acquireSendLock takes the EXCLUSIVE per-wallet+network send-lock for the whole
// send critical section, so two `tx send` invocations cannot select the same
// UTXOs. Ordering is send-lock FIRST, then the journal lock inside Append/SetState
// (never the reverse). A timeout maps to state.lock_timeout (exit 11).
func (s *Service) acquireSendLock(ctx context.Context, net domain.Network, wallet string) (func(), error) {
	locksDir := filepath.Join(s.stateDir, "locks")
	if err := fsx.MkdirAll(locksDir, 0o700); err != nil {
		if fsx.IsReadOnly(err) {
			return nil, domain.Wrap(domain.CodeStateCorrupt, "state lock directory is read-only", err)
		}
		return nil, domain.Wrap(domain.CodeStateCorrupt, "cannot create state lock directory", err)
	}
	lockBase := filepath.Join(locksDir, "send-"+string(net)+"-"+wallet)
	lctx, cancel := context.WithTimeout(ctx, sendLockTimeout)
	defer cancel()
	unlock, err := fsx.Lock(lctx, lockBase)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return nil, domain.New(domain.CodeStateLockTimeout,
				"timed out acquiring the wallet send-lock; another daxib send may be in progress")
		}
		return nil, domain.Wrap(domain.CodeStateLockTimeout, "cannot acquire the wallet send-lock", err)
	}
	return unlock, nil
}

// abortSigned terminalizes a record as `failed` ONLY when it is still `signed`
// (the exactly-one-of settle/abort guard). It re-reads the record so a recorded
// broadcast is never terminalized. Best-effort: a failure here is swallowed (the
// record remains `signed`, recoverable on the next reconcile).
func (s *Service) abortSigned(ctx context.Context, id string) {
	rec, err := s.journal.ByID(ctx, s.net, id)
	if err != nil || rec == nil {
		return
	}
	if rec.Status != journal.StatusSigned {
		return // already broadcast/terminal — never terminalize a recorded broadcast
	}
	reason := "send aborted before broadcast was recorded"
	_ = s.journal.SetState(ctx, s.net, id, journal.StateMutation{Status: journal.StatusFailed, Error: &reason})
}

// ── reconcile ─────────────────────────────────────────────────────────────────

// reconcileAtOpen walks the active network's unresolved records at Open
// (best-effort, never fails Open). It leaves `signed` records for lazy rebroadcast
// (under the next send-lock / tx wait) and performs NO destructive action offline.
func (s *Service) reconcileAtOpen(ctx context.Context) {
	if s.journal == nil {
		return
	}
	// Purely informational offline: a `signed` record waits for a send-lock or a
	// `tx wait`; a `broadcast` record is re-polled by `tx status`/`tx wait`. We do
	// NOT dial here (Open must stay offline-safe), so there is nothing to do beyond
	// confirming the journal is readable; swallow any read error.
	_, _ = s.journal.Unresolved(ctx, s.net)
}

// reservedOutpoints returns the set of "txid:vout" outpoints consumed by in-flight
// (non-terminal: signed/broadcast) journal records for the wallet on the active
// network. These are the double-spend-avoidance records (journal.JInput): excluding
// them from selection (under the send-lock, after reconcile) guarantees a new send
// never re-selects a stranded/in-flight tx's inputs. Best-effort: a journal read
// error returns an empty set (the send-lock + reconcile still serialize; the worst
// case is the old behaviour, which the broadcast double-spend reject would catch).
func (s *Service) reservedOutpoints(ctx context.Context, wallet string) map[string]bool {
	out := map[string]bool{}
	if s.journal == nil {
		return out
	}
	unresolved, err := s.journal.Unresolved(ctx, s.net)
	if err != nil {
		return out
	}
	for _, rec := range unresolved {
		if rec.Wallet != wallet || rec.Status.IsTerminal() {
			continue
		}
		for _, in := range rec.Inputs {
			out[in.Txid+":"+domain.IndexString(in.Vout)] = true
		}
	}
	return out
}

// reconcileWallet rebroadcasts any prior `signed` record for the wallet on the
// active network BEFORE a new selection, so a crashed prior send's identical bytes
// reach the mempool and are never re-selected. It runs under the send-lock.
func (s *Service) reconcileWallet(ctx context.Context, client backend.Client, wallet string, sink domain.EventSink) {
	if s.journal == nil {
		return
	}
	unresolved, err := s.journal.Unresolved(ctx, s.net)
	if err != nil {
		return
	}
	for _, rec := range unresolved {
		if rec.Wallet != wallet || rec.Status != journal.StatusSigned || rec.RawTx == "" {
			continue
		}
		raw, derr := decodeHex(rec.RawTx)
		if derr != nil {
			continue
		}
		emit(sink, "reconcile", "rebroadcasting prior signed tx "+rec.ID)
		outcome, txid, _ := s.broadcastClassified(ctx, client, raw, sink)
		switch outcome {
		case outcomeAccepted:
			t := txid
			if t == "" {
				t = rec.Txid
			}
			_ = s.journal.SetState(ctx, s.net, rec.ID, journal.StateMutation{Status: journal.StatusBroadcast, Txid: &t})
		case outcomeRejected:
			reason := "prior signed tx permanently rejected on reconcile"
			_ = s.journal.SetState(ctx, s.net, rec.ID, journal.StateMutation{Status: journal.StatusFailed, Error: &reason})
		case outcomeTransportExhausted:
			// leave `signed` for the next attempt.
		}
	}
}
