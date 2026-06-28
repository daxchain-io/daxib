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
	"github.com/daxchain-io/daxib/internal/policy"
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
func (s *Service) SendTx(ctx context.Context, p domain.Principal, req domain.SendRequest, sink domain.EventSink) (domain.TxResult, error) {
	// No silent default: a send with no resolved network fails before any address
	// decode (which is network-specific) or wallet/backend work.
	if err := s.requireNetwork(); err != nil {
		return domain.TxResult{}, err
	}
	// Resolve --to through the contacts address book FIRST: a contact NAME maps to
	// its pinned address; a raw address falls through unchanged. From here on req.To
	// is always a raw address, so the validation + build path is identical for
	// contact-named and raw-address sends.
	resolvedTo, rerr := s.resolveDestination(ctx, req.To)
	if rerr != nil {
		return domain.TxResult{}, rerr
	}
	req.To = resolvedTo

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
	// a no-op preview has no durable side effect). The policy verdict is included via
	// a CHECK-only Evaluate that writes NO reservation: a dry-run that WOULD be denied
	// exits 3 before the (preview) sign.
	if req.DryRun {
		art, err := s.buildAndSign(ctx, wallet, client, req, feeRate, true, nil, s.dryRunPolicyCheck(wallet))
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

	// Open the policy engine for the send chokepoint. With no anchor + no policy it is
	// permissive (a no-op reservation), so M4 behavior is unchanged when no policy is
	// set. A seal/rollback/version failure (a tampered/rolled-back policy) HALTS the
	// send here (exit 8) — fail-closed.
	eng, perr := s.openPolicyEngine(ctx)
	if perr != nil {
		return domain.TxResult{}, perr
	}

	// resv holds the spend reservation captured by the reserve callback (set after
	// coin-selection, before the keystore sign). committed gates the deferred release.
	var resv policy.Reservation
	committed := false
	reserve := func(rctx context.Context, preArt sendArtifact) error {
		r, rerr := eng.Reserve(rctx, policy.Check{
			Network:    string(s.net),
			Recipient:  preArt.recipient,
			AmountSat:  preArt.recipSat,
			FeeSat:     preArt.feeSat,
			FeeRate:    preArt.feeRate,
			ChangeAddr: preArt.changeAddr,
		})
		if rerr != nil {
			return rerr // policy.denied.* (exit 3) or seal/state failure — BEFORE signing
		}
		resv = r
		return nil
	}

	// Build + sign the artifact UNDER THE LOCK: gather UTXOs, coin-select (excluding
	// reserved outpoints), allocate the change address (DeriveNext), RESERVE the spend
	// (policy chokepoint, before the keystore sign), and sign.
	art, err := s.buildAndSign(ctx, wallet, client, req, feeRate, false, consumed, reserve)
	if err != nil {
		// A pre-sign failure (incl. a policy denial): release the reservation if one
		// was taken (no signature exists, so freeing the budget is correct).
		_ = resv.Release(context.Background())
		return domain.TxResult{}, err
	}

	// Journal the new tx as `signed` BEFORE broadcast (crash here ⇒ recovery
	// rebroadcasts the same bytes). The reservation id is cross-linked so orphan
	// reconciliation can resolve a stranded reservation against this record.
	rec := s.journalRecord(p, wallet, art, feeRate)
	rec.ReservationID = resv.ID()
	if err := s.journal.Append(ctx, rec); err != nil {
		// Pre-broadcast failure (no bytes on the wire): release the reservation.
		_ = resv.Release(context.Background())
		return domain.TxResult{}, err
	}
	emit(sink, "signed", "journaled "+rec.ID+" (raw tx persisted)")

	settled := false
	defer func() {
		// Exactly-one-of settle/abort: if settled stayed false on an early/panic
		// return, mark the record failed — but ONLY when it is still `signed` (never
		// terminalize a recorded broadcast). The reservation is released only when the
		// send did not commit (a recorded broadcast keeps the reservation committed —
		// over-counting is the safe direction).
		if !settled {
			s.abortSigned(context.Background(), rec.ID)
		}
		if !committed {
			_ = resv.Release(context.Background())
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
		// The bytes are LIVE on-chain: commit the spend reservation (reserved →
		// committed). committed gates the deferred release so an accepted broadcast
		// never frees the budget (over-counting is the safe direction).
		committed = true
		_ = resv.Commit(context.Background(), t)
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
		// The signed bytes MAY have reached the mempool, so the reservation must NOT
		// be released (over-counting is the safe direction): keep it (committed gate),
		// and let orphan reconciliation commit it once the journal shows `broadcast`.
		settled = true
		committed = true
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
	for _, d := range broadcastBackoff {
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
			// already-known reject => accepted; the caller fills art.txid since the node
			// echoes no txid here.
			return outcomeAccepted, "", nil
		}
		if !retry {
			return outcomeRejected, "", mapped
		}
	}
	return outcomeTransportExhausted, "", lastErr
}

// classifyBroadcastErr maps a backend broadcast error to an outcome + a mapped
// domain error + whether it is transport-retryable. It reads the error string
// (Core sendrawtransaction reject reasons + Esplora 400 bodies) and the
// backend.unreachable/rpc_error class.
//
// CONSERVATIVE policy (KNOWN-2/TXR-1/TXR-2/CB-2): a tx is terminalized as `failed`
// ONLY on a POSITIVELY-MATCHED permanent consensus/policy reject (the bad-txns /
// min-relay / dust set below). A node that merely ANSWERED with an error
// (backend.rpc_error), a recognised-transient string (warmup/-28/503/rate-limit),
// or any UNMATCHED/novel error is treated as transport-exhausted (the record stays
// `signed`, recoverable, and is rebroadcast on the next send-lock / `tx wait`).
// Fail-open toward recoverability: it is far safer to keep a possibly-live tx
// trackable than to wrongly declare it dead.
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

	// TRANSIENT-FIRST (CLS-1/KNOWN-2): classify positively-transient signals BEFORE
	// the permanent-reject substring scan. A node that merely TIMED OUT, was
	// UNREACHABLE, ANSWERED-with-an-error, or returned a 5xx/-28/rate-limit envelope
	// has NOT proven the tx invalid — even if the surrounding transport/HTML body or a
	// redacted URL happens to contain a permanent-reject substring (e.g. an HTTP 503
	// proxy page that mentions "scriptpubkey", or a `backend.rpc_error` whose detail
	// echoes "dust"/"non-final"). Terminalizing those would strand a possibly-live tx.
	// A GENUINE consensus reject arrives as a node answer with NO transient marker
	// (e.g. `RPC error -25: bad-txns-inputs-missingorspent`) and still falls through to
	// the permanent scan below.
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return outcomeTransportExhausted, domain.Wrap(domain.CodeBackendUnreachable, "broadcast transport failure", err), true
	}
	if de := domain.AsError(err); de != nil && de.Code == domain.CodeBackendUnreachable {
		return outcomeTransportExhausted, de, true
	}
	if looksTransientBroadcast(msg) {
		// An rpc_error wrapper or an untyped string carrying a transient marker: a
		// warming node (-28), a 5xx, a rate-limit, a dial/transport failure — all
		// retryable. Leave the record recoverable rather than terminalizing a possibly
		// live tx (TXR-1/TXR-2). The 5xx test is explicit (no fragile Contains(msg,"5")).
		return outcomeTransportExhausted, domain.Wrap(domain.CodeBackendUnreachable, "broadcast transport failure", err), true
	}

	// Permanent rejects (NOT a rebroadcast-the-same-bytes class). ONLY these
	// positively-matched consensus/policy reject reasons terminalize the record, and
	// ONLY after the transient signals above were ruled out.
	switch {
	case strings.Contains(msg, "bad-txns-inputs-missingorspent") || strings.Contains(msg, "missing inputs") || strings.Contains(msg, "missing-inputs"):
		return outcomeRejected, domain.Wrap(domain.CodeTxInputSpent, "broadcast rejected: an input was already spent", err), false
	case strings.Contains(msg, "min relay fee not met") || strings.Contains(msg, "mempool min fee not met") || strings.Contains(msg, "insufficient fee") || strings.Contains(msg, "fee too low") || strings.Contains(msg, "min-relay"):
		return outcomeRejected, domain.Wrap(domain.CodeTxFeeTooLow, "broadcast rejected: fee below the relay floor", err), false
	case strings.Contains(msg, "dust") || strings.Contains(msg, "scriptpubkey") || strings.Contains(msg, "non-mandatory-script-verify") || strings.Contains(msg, "non-final") || strings.Contains(msg, "bad-txns"):
		return outcomeRejected, domain.Wrap(domain.CodeTxBroadcastRejected, "broadcast rejected by the network", err), false
	}

	// A typed `backend.rpc_error` with no transient marker AND no permanent-reject
	// substring: the node answered with something we cannot positively classify as a
	// consensus reject — leave it recoverable (TXR-1). A real consensus reject from
	// Core carries a bad-txns/min-relay/dust string and was caught above.
	if de := domain.AsError(err); de != nil && de.Code == domain.CodeBackendRPCError {
		return outcomeTransportExhausted, domain.Wrap(domain.CodeBackendUnreachable, "broadcast transport failure (backend answered with an error)", err), true
	}

	// An UNMATCHED/novel error string: fail-open toward recoverability. Leave the
	// record `signed` (recoverable) rather than terminalizing a possibly-live tx —
	// the KNOWN-2 conservative default. A genuinely-permanent reject not in the set
	// above costs at most one harmless rebroadcast (the node re-rejects it).
	return outcomeTransportExhausted, domain.Wrap(domain.CodeBackendUnreachable, "broadcast transport failure (unclassified backend error)", err), true
}

// looksTransientBroadcast reports whether a lowercased broadcast error string
// carries a POSITIVE transient marker: a dial/transport failure, a warming/loading
// node (-28), an HTTP 5xx class, a rate-limit, or a generic "unavailable". The 5xx
// classes are matched explicitly (no fragile Contains(msg,"5") digit match — TXR-2).
// It is consulted BEFORE the permanent-reject scan so a transient envelope that also
// embeds a permanent substring is NOT wrongly terminalized (CLS-1).
func looksTransientBroadcast(msg string) bool {
	return strings.Contains(msg, "connection refused") || strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "no such host") || strings.Contains(msg, "eof") ||
		strings.Contains(msg, "connection reset") || strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "-28") || strings.Contains(msg, "in warmup") ||
		strings.Contains(msg, "warming up") || strings.Contains(msg, "loading") ||
		strings.Contains(msg, "initializing") || strings.Contains(msg, "try again") ||
		strings.Contains(msg, "rate limit") || strings.Contains(msg, "too many requests") ||
		strings.Contains(msg, "unavailable") || strings.Contains(msg, "503") ||
		strings.Contains(msg, "502") || strings.Contains(msg, "504")
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

	// Converge any interrupted admin-passphrase rotation (SI-1) FIRST: roll a
	// half-finished staged rotation forward (promote) or back (drop the staged key) so
	// the anchor + policy.json pair is single-key and verifiable before anything else
	// reads the seal. Best-effort, offline.
	s.reconcilePolicyRotation(ctx)

	// Reconcile orphaned policy spend reservations against the journal (a crash
	// between Reserve and Commit/Release): a reservation whose record reached
	// `broadcast` ⇒ commit; still `signed`/absent ⇒ release. Best-effort, offline.
	s.reconcilePolicyOrphans(ctx)
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
