package service

import (
	"bytes"
	"context"
	"encoding/hex"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/daxchain-io/daxib/internal/coinselect"
	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/journal"
	"github.com/daxchain-io/daxib/internal/keys"
	"github.com/daxchain-io/daxib/internal/policy"
)

// tx_replace.go is the RBF (BIP-125) pipeline: `tx speedup` and `tx cancel`. Both
// build a REPLACEMENT of an unconfirmed, RBF-signaling, wallet-originated send that
// reuses the SAME inputs (a same-or-superset, BIP-125 rule 2) and pays a HIGHER
// absolute fee AND a higher feerate (rules 3 & 4). A speedup keeps the same
// recipient and shrinks change to absorb the bump; a cancel redirects ALL funds to
// a fresh wallet change address (voiding the payment). The replacement is
// re-signed (BIP-143), policy-gated on ONLY the additional fee (no double-count of
// the original payment), broadcast through the SAME classified pipeline, and
// journaled LINKED to the original (original → StatusReplaced, ReplacedByID =
// replacement; replacement.ReplacesID = original).

// addrCoords is a wallet address's BIP-84 derivation coordinates, used to map a
// replacement input back to its signing key.
type addrCoords struct {
	branch domain.Branch
	index  uint32
}

// replaceReserveFn is the RBF policy chokepoint: buildReplacement constructs the
// mode-aware policy.Check (so the rolling-24h window is charged only the fee delta)
// and calls this to reserve the spend BEFORE signing. A non-nil error (a denial or
// seal failure) aborts the replacement before any signature exists.
type replaceReserveFn func(ctx context.Context, check policy.Check) error

// replaceMode selects the replacement shape.
type replaceMode int

const (
	modeSpeedup replaceMode = iota // same recipient, higher fee
	modeCancel                     // redirect all funds to self (void the payment)
)

// SpeedupTx builds + broadcasts a higher-fee replacement of an unconfirmed send
// (BIP-125), paying the SAME recipient.
func (s *Service) SpeedupTx(ctx context.Context, p domain.Principal, req domain.SpeedupRequest, sink domain.EventSink) (domain.TxResult, error) {
	return s.replaceTx(ctx, p, req.Wallet, req.Txid, modeSpeedup, req.FeeRate, req.Yes, req.Wait, sink)
}

// CancelTx builds + broadcasts a replacement that redirects all funds to a
// wallet-owned change address (voiding the original payment) at a higher fee.
func (s *Service) CancelTx(ctx context.Context, p domain.Principal, req domain.CancelRequest, sink domain.EventSink) (domain.TxResult, error) {
	return s.replaceTx(ctx, p, req.Wallet, req.Txid, modeCancel, req.FeeRate, req.Yes, req.Wait, sink)
}

// replaceTx is the shared RBF lifecycle under the per-wallet send-lock. It mirrors
// SendTx's settle/abort guard so a post-acceptance SetState failure leaves the
// replacement `signed` (recoverable), never `failed`, and never strands the live
// replacement.
func (s *Service) replaceTx(ctx context.Context, p domain.Principal, wallet, txid string, mode replaceMode, feeRateStr string, yes bool, wait domain.WaitOpts, sink domain.EventSink) (domain.TxResult, error) {
	// No silent default: an RBF replacement is network-specific (journal keyed by
	// network, address decode per network). Fail before the confirmation gate.
	if err := s.requireNetwork(); err != nil {
		return domain.TxResult{}, err
	}
	// 0. Confirmation gate: a replacement is a mutating op. Non-TTY without --yes is a
	// clean confirmation-required error (never a prompt hang).
	if !yes {
		isTTY := s.secret.IsTTY != nil && s.secret.IsTTY()
		if !isTTY {
			return domain.TxResult{}, domain.New(domain.CodeUsageConfirmRequired,
				"a replacement requires confirmation: pass --yes to authorize this non-interactive RBF")
		}
	}

	// Validate the explicit --fee-rate early (a malformed value is a clean exit 2
	// before any dial).
	if feeRateStr != "" {
		if _, ferr := parseFeeRate(feeRateStr); ferr != nil {
			return domain.TxResult{}, ferr
		}
	}

	wallet, err := s.resolveWallet(ctx, wallet)
	if err != nil {
		return domain.TxResult{}, err
	}
	if err := s.assertWalletNetwork(ctx, wallet); err != nil {
		return domain.TxResult{}, err
	}

	client, _, _, err := s.dialActiveBackend(ctx)
	if err != nil {
		return domain.TxResult{}, err
	}
	defer client.Close()

	// 1. Look up the ORIGINAL record by txid.
	orig, err := s.journal.ByTxid(ctx, s.net, txid)
	if err != nil {
		return domain.TxResult{}, domain.Wrap(domain.CodeRefNotFound, "no journaled transaction with that txid", err)
	}
	if orig.Wallet != wallet {
		return domain.TxResult{}, domain.Newf(domain.CodeUsage+".wrong_wallet",
			"tx %s belongs to wallet %q, not %q", txid, orig.Wallet, wallet)
	}
	if orig.Status.IsTerminal() {
		// confirmed/failed/replaced are all already-resolved (tx.replaced, exit 9).
		return domain.TxResult{}, domain.Newf("tx.replaced",
			"tx %s is already resolved (status %s) and cannot be replaced", txid, orig.Status)
	}
	if orig.RawTx == "" {
		return domain.TxResult{}, domain.New(domain.CodeStateCorrupt, "the original record has no raw bytes to replace")
	}

	// 2. Decode the original + assert it signals RBF (BIP-125).
	otx, derr := decodeWireTx(orig.RawTx)
	if derr != nil {
		return domain.TxResult{}, domain.Wrap(domain.CodeStateCorrupt, "decoding the original tx", derr)
	}
	if !anyInputSignalsRBF(otx) {
		return domain.TxResult{}, domain.Newf("tx.replacement_rejected",
			"tx %s does not signal RBF (no input has nSequence < 0xfffffffe); it cannot be replaced", txid)
	}

	// 3. Backend re-poll: never replace a tx that already confirmed.
	if st, serr := client.TxStatus(ctx, txid); serr == nil && st.Confirmed {
		return domain.TxResult{}, domain.Newf("tx.replaced",
			"tx %s already confirmed (%d confirmations); it cannot be replaced", txid, st.Confirmations)
	}

	// 4. Resolve the new fee rate: strictly higher than the original.
	var est domain.FeeEstimates
	if feeRateStr == "" {
		est, _ = client.FeeEstimates(ctx) // best-effort; the bump floor still applies
	}
	newRate, err := resolveBumpRate(feeRateStr, orig.FeeRate, est)
	if err != nil {
		return domain.TxResult{}, err
	}
	if newRate <= orig.FeeRate {
		return domain.TxResult{}, domain.Newf("tx.replacement_rejected",
			"new fee-rate %d sat/vB must exceed the original %d sat/vB (BIP-125 rule 4)", newRate, orig.FeeRate)
	}

	// ── critical section ──────────────────────────────────────────────────────────
	unlock, err := s.acquireSendLock(ctx, s.net, wallet)
	if err != nil {
		return domain.TxResult{}, err
	}
	defer unlock()

	// Flush any prior `signed` record for this wallet (idempotent rebroadcast) and
	// recompute the reserved-outpoint set AFTER reconcile.
	s.reconcileWallet(ctx, client, wallet, sink)
	consumed := s.reservedOutpoints(ctx, wallet)

	// RBF-LENS-1 (TOCTOU): the terminality + confirmation checks above ran BEFORE the
	// send-lock. reconcileWallet may have just observed the original's replacement (or
	// its confirmation) and flipped it to a terminal state, and a concurrent
	// speedup/cancel that won the lock first could have replaced it. Re-fetch the
	// original UNDER the lock (post-reconcile) and re-assert it is still replaceable so
	// a second racing speedup aborts cleanly with tx.replaced rather than building a
	// doomed double-replacement.
	if fresh, ferr := s.journal.ByID(ctx, s.net, orig.ID); ferr == nil && fresh != nil {
		orig = fresh
		if orig.Status.IsTerminal() {
			return domain.TxResult{}, domain.Newf("tx.replaced",
				"tx %s is already resolved (status %s) and cannot be replaced", txid, orig.Status)
		}
	}
	if st, serr := client.TxStatus(ctx, txid); serr == nil && st.Confirmed {
		return domain.TxResult{}, domain.Newf("tx.replaced",
			"tx %s already confirmed (%d confirmations); it cannot be replaced", txid, st.Confirmations)
	}

	eng, perr := s.openPolicyEngine(ctx)
	if perr != nil {
		return domain.TxResult{}, perr
	}

	// 5. Build the replacement artifact (reuses the original inputs; adds confirmed
	// inputs only if needed to raise the fee). The policy reservation is taken inside
	// (after the tx is built, before signing).
	var resv policy.Reservation
	committed := false
	art, err := s.buildReplacement(ctx, wallet, client, orig, mode, newRate, consumed, func(rctx context.Context, check policy.Check) error {
		r, rerr := eng.Reserve(rctx, check)
		if rerr != nil {
			return rerr
		}
		resv = r
		return nil
	})
	if err != nil {
		_ = resv.Release(context.Background())
		return domain.TxResult{}, err
	}

	// 6. Journal the replacement as `signed` BEFORE broadcast, LINKED to the original.
	rec := s.journalRecord(p, wallet, art, newRate)
	rec.ReservationID = resv.ID()
	rec.ReplacesID = orig.ID
	if err := s.journal.Append(ctx, rec); err != nil {
		_ = resv.Release(context.Background())
		return domain.TxResult{}, err
	}
	emit(sink, "signed", "journaled replacement "+rec.ID+" (replaces "+orig.ID+")")

	settled := false
	defer func() {
		if !settled {
			s.abortSigned(context.Background(), rec.ID)
		}
		if !committed {
			_ = resv.Release(context.Background())
		}
	}()

	// 7. Broadcast (classified).
	outcome, txid2, berr := s.broadcastClassified(ctx, client, art.rawTx, sink)
	switch outcome {
	case outcomeAccepted:
		t := txid2
		if t == "" {
			t = art.txid
		}
		// The replacement is LIVE: mark settled+committed BEFORE the SetState writes so
		// a post-acceptance failure leaves the replacement `signed` (recoverable), never
		// `failed`.
		settled = true
		committed = true
		_ = resv.Commit(context.Background(), t)
		// Record the LIVE replacement FIRST, then flip the original → replaced. Order
		// matters: a crash between the two leaves the original `broadcast` (recoverable),
		// never an original flipped to replaced with no live replacement recorded.
		if err := s.journal.SetState(ctx, s.net, rec.ID, journal.StateMutation{Status: journal.StatusBroadcast, Txid: &t}); err != nil {
			res := s.replacementSignedResult(wallet, art, rec.ID, orig.Txid)
			res.Txid = t
			return res, domain.WithData(
				domain.Wrap(domain.CodeBackendUnreachable,
					"replacement accepted but recording it failed; it is journaled and will be reconciled on retry", err),
				map[string]any{"journal_id": rec.ID, "txid": t})
		}
		if err := s.journal.SetState(ctx, s.net, orig.ID, journal.StateMutation{Status: journal.StatusReplaced, ReplacedBy: &rec.ID}); err != nil {
			// The replacement is live + recorded; the original flip is best-effort. A
			// failure here leaves the original `broadcast` (the next reconcile/tx wait
			// observes the replacement and resolves it). Do NOT fail the whole op.
			emit(sink, "replace", "warning: could not mark the original replaced (it will reconcile)")
		}
		txid2 = t
		emit(sink, "broadcast", "replacement accepted "+t)

	case outcomeTransportExhausted:
		// The bytes MAY be live: keep the replacement `signed` (recoverable), keep the
		// reservation committed (over-count safe), and do NOT flip the original.
		settled = true
		committed = true
		res := s.replacementSignedResult(wallet, art, rec.ID, orig.Txid)
		return res, domain.WithData(
			domain.Wrap(domain.CodeBackendUnreachable,
				"replacement broadcast transport exhausted; it is journaled and will be rebroadcast on retry", berr),
			map[string]any{"journal_id": rec.ID, "txid": art.txid})

	case outcomeRejected:
		// A permanent reject: terminalize the REPLACEMENT only; the original is
		// untouched (still live/unresolved).
		reason := rejectReason(berr)
		if serr := s.journal.SetState(ctx, s.net, rec.ID, journal.StateMutation{Status: journal.StatusFailed, Error: &reason}); serr != nil {
			return domain.TxResult{}, serr
		}
		settled = true
		return domain.TxResult{}, mapReplacementRejectErr(berr)
	}

	// Accepted. Optional --wait.
	if wait.Enabled {
		unlock()
		res, werr := s.waitOnTxid(ctx, client, txid2, rec.ID, wait, sink)
		res.Replacement = true
		res.ReplacesTxid = orig.Txid
		return res, werr
	}
	return s.replacementResult(wallet, art, rec.ID, txid2, orig.Txid), nil
}

// buildReplacement builds + signs the replacement tx. It REUSES the original's exact
// inputs (BIP-125 same-or-superset) — never re-runs fresh coin selection — and for a
// speedup shrinks change to absorb the bump (adding one more confirmed, in-gap,
// non-reserved UTXO only when change cannot cover it). For a cancel it redirects all
// funds (minus the new fee) to a fresh wallet change address. `reserve` is the policy
// chokepoint, run after the tx is built and BEFORE signing.
func (s *Service) buildReplacement(ctx context.Context, wallet string, client interface {
	UTXOs(ctx context.Context, addrs []string) ([]domain.UTXO, error)
}, orig *journal.Record, mode replaceMode, newRate int64, consumed map[string]bool, reserve replaceReserveFn) (sendArtifact, error) {
	params := s.chainParams()

	// Map every wallet address in the gap window to its (branch, index) so each input
	// (and any added input) signs with the right key.
	_, scan, err := s.keys.ScanAddresses(ctx, wallet, s.net, gapWindow)
	if err != nil {
		return sendArtifact{}, err
	}
	byAddr := make(map[string]addrCoords, len(scan))
	for _, a := range scan {
		byAddr[a.Address] = addrCoords{branch: a.Branch, index: a.Index}
	}

	// Reuse the original inputs verbatim (same outpoints + values + addresses from the
	// journal record).
	baseInputs := make([]coinselect.Coin, 0, len(orig.Inputs))
	usedOutpoints := make(map[string]bool, len(orig.Inputs))
	for _, in := range orig.Inputs {
		c, ok := byAddr[in.Address]
		if !ok {
			// An input whose address is outside the wallet's scan/gap window: we cannot
			// derive its signing key. Refuse rather than sign with a wrong key.
			return sendArtifact{}, domain.Newf(domain.CodeStateCorrupt,
				"cannot map input %s:%d (address %s) to a wallet signing key; refusing to replace",
				in.Txid, in.Vout, in.Address)
		}
		op := in.Txid + ":" + domain.IndexString(in.Vout)
		baseInputs = append(baseInputs, coinselect.Coin{Outpoint: op, Branch: c.branch, Index: c.index, ValueSat: in.ValueSat})
		usedOutpoints[op] = true
	}

	// Recipient script (speedup keeps the original recipient; cancel pays self).
	var recipientAddr string
	var recipientScript []byte
	var recipSat int64

	// Always derive a fresh change address for this replacement.
	changeDA, derr := s.keys.DeriveNext(ctx, wallet, s.net, domain.BranchChange)
	if derr != nil {
		return sendArtifact{}, derr
	}
	changeScript, derr := scriptForAddress(changeDA.Address, params)
	if derr != nil {
		return sendArtifact{}, derr
	}

	if mode == modeSpeedup {
		recipientAddr = orig.RecipientAddr
		recipSat = orig.RecipientSat
		recipientScript, err = scriptForAddress(recipientAddr, params)
		if err != nil {
			return sendArtifact{}, err
		}
	} else {
		// Cancel: the recipient IS the fresh change address (all funds return to self).
		recipientAddr = changeDA.Address
		recipientScript = changeScript
		recipSat = 0 // the self output value is computed below as Σ(inputs) - newFee
	}

	// Compute the fee + change. Speedup keeps a recipient output + (maybe) a change
	// output; cancel emits a single self output.
	recipVB := coinselect.OutputVBytes(len(recipientScript))

	build := func(inputs []coinselect.Coin) (feeSat, changeSat, vsize int64, emitChange bool, ferr error) {
		var in int64
		for _, c := range inputs {
			in += c.ValueSat
		}
		if mode == modeSpeedup {
			// Try WITH a change output first.
			vsizeWithChange := coinselect.EstimateVSizeOut(len(inputs), recipVB, 1)
			feeWithChange := coinselect.FeeFor(vsizeWithChange, newRate)
			change := in - recipSat - feeWithChange
			if change >= coinselect.DustThresholdP2WPKH {
				return feeWithChange, change, vsizeWithChange, true, nil
			}
			// Change would be dust: drop it (changeless) and fold the surplus into the fee.
			vsizeNoChange := coinselect.EstimateVSizeOut(len(inputs), recipVB, 0)
			feeFloor := coinselect.FeeFor(vsizeNoChange, newRate)
			surplus := in - recipSat
			if surplus < feeFloor {
				return 0, 0, 0, false, errInsufficientReplacementInputs
			}
			// Changeless: the whole surplus over the recipient is the fee.
			return surplus, 0, vsizeNoChange, false, nil
		}
		// Cancel: one self output, no separate change.
		cancelVsize := coinselect.EstimateVSizeOut(len(inputs), recipVB, 0)
		fee := coinselect.FeeFor(cancelVsize, newRate)
		self := in - fee
		if self < coinselect.DustThresholdForScript(recipientScript) {
			return 0, 0, 0, false, domain.Newf(domain.CodeFundsInsufficient,
				"the new fee %d sat exceeds the recoverable value of the cancel (sum-in %d sat); cannot cancel without a dust output", fee, in)
		}
		return fee, self, cancelVsize, false, nil
	}

	inputs := baseInputs
	feeSat, changeSat, vsize, emitChange, berr := build(inputs)
	if berr == errInsufficientReplacementInputs {
		// Add one more confirmed, in-gap, non-reserved UTXO to raise the fee (superset).
		extra, eerr := s.pickExtraInput(ctx, client, byAddr, usedOutpoints, consumed)
		if eerr != nil {
			return sendArtifact{}, eerr
		}
		inputs = append(inputs, extra)
		usedOutpoints[extra.Outpoint] = true
		feeSat, changeSat, vsize, emitChange, berr = build(inputs)
	}
	if berr != nil {
		return sendArtifact{}, berr
	}

	// BIP-125 rule 3: the replacement's ABSOLUTE fee must strictly exceed the
	// original's (a higher feerate on a smaller tx could otherwise pay less).
	if feeSat <= orig.FeeSat {
		return sendArtifact{}, domain.Newf("tx.replacement_rejected",
			"replacement fee %d sat must exceed the original %d sat (BIP-125 rule 3)", feeSat, orig.FeeSat)
	}

	// Build the replacement wire tx (version 2, RBF sequence on every input).
	repl := wire.NewMsgTx(2)
	specs := make([]keys.InputSigningSpec, 0, len(inputs))
	inAddr := make(map[string]string, len(inputs))
	for i, c := range inputs {
		txidStr, vout := splitOutpoint(c.Outpoint)
		h, herr := chainhash.NewHashFromStr(txidStr)
		if herr != nil {
			return sendArtifact{}, domain.Wrap(domain.CodeStateCorrupt, "parsing input txid", herr)
		}
		txin := wire.NewTxIn(wire.NewOutPoint(h, vout), nil, nil)
		txin.Sequence = rbfSequence
		repl.AddTxIn(txin)

		addr := addressForCoin(c, orig, byAddr)
		prevScript, perr := scriptForAddress(addr, params)
		if perr != nil {
			return sendArtifact{}, perr
		}
		specs = append(specs, keys.InputSigningSpec{
			Index: i, Branch: c.Branch, AddrIndex: c.Index, PrevScript: prevScript, PrevValue: c.ValueSat,
		})
		inAddr[c.Outpoint] = addr
	}
	// Outputs: recipient first, then change (speedup only, when emitted).
	repl.AddTxOut(wire.NewTxOut(recipSat, recipientScript))
	if mode == modeCancel {
		// The single self output carries the recovered value.
		repl.TxOut[0].Value = changeSat
		recipSat = changeSat
	} else if emitChange {
		repl.AddTxOut(wire.NewTxOut(changeSat, changeScript))
	}

	changeAddrForResult := ""
	if mode == modeSpeedup && emitChange {
		changeAddrForResult = changeDA.Address
	}

	// POLICY CHOKEPOINT: reserve BEFORE signing. The Check is mode-aware so the
	// rolling-24h window is charged ONLY the additional fee (no double-count of the
	// original payment), while the per-tx cap still sees the full outflow:
	//   - speedup: AmountSat = the (unchanged) recipient amount, FeeSat = newFee,
	//     PriorSpentSat = origRecipient + origFee → windowCharge == newFee - origFee.
	//     The recipient is RE-EVALUATED so a now-denylisted/de-allowlisted dest is
	//     DENIED (RBF cannot launder a forbidden destination).
	//   - cancel: AmountSat = 0 (funds return to self), FeeSat = newFee,
	//     PriorSpentSat = origFee → windowCharge == newFee - origFee. The recipient IS
	//     the sealed change addr (Recipient + ChangeAddr both the self addr), so isSelf
	//     passes even when include_self is off — cancel-to-self is always permitted and
	//     cannot exfiltrate.
	//     NOTE (RPJ-2, intentional): the ORIGINAL payment amount stays committed in the
	//     rolling-24h window. The original's reservation (origRecipient + origFee) was
	//     committed at its broadcast and remains committed when it flips to `replaced`
	//     (reconcilePolicyOrphans keeps a `replaced` original counted — see policy.go),
	//     so a cancel leaves origRecipient counted even though those funds returned to
	//     self. This is a deliberate, conservative OVER-count (it can only TIGHTEN the
	//     limit, never loosen it); we do NOT release origRecipient on a cancel because
	//     under-counting the live window is the unsafe direction for an agent wallet.
	if reserve != nil {
		var check policy.Check
		switch mode {
		case modeSpeedup:
			check = policy.Check{
				Network:       string(s.net),
				Recipient:     recipientAddr,
				AmountSat:     recipSat,
				FeeSat:        feeSat,
				FeeRate:       newRate,
				ChangeAddr:    changeAddrForResult,
				PriorSpentSat: orig.RecipientSat + orig.FeeSat,
			}
		default: // modeCancel
			check = policy.Check{
				Network:       string(s.net),
				Recipient:     changeDA.Address,
				AmountSat:     0,
				FeeSat:        feeSat,
				FeeRate:       newRate,
				ChangeAddr:    changeDA.Address,
				PriorSpentSat: orig.FeeSat,
			}
		}
		if rerr := reserve(ctx, check); rerr != nil {
			return sendArtifact{}, rerr
		}
	}

	// Sign every input.
	pass, _, perr := s.acquireSendPassphrase()
	if perr != nil {
		return sendArtifact{}, perr
	}
	defer pass.Zero()
	if err := s.keys.SignInputs(ctx, wallet, s.net, pass, repl, specs); err != nil {
		return sendArtifact{}, err
	}

	var buf bytes.Buffer
	if err := repl.Serialize(&buf); err != nil {
		return sendArtifact{}, domain.Wrap(domain.CodeStateCorrupt, "serializing replacement", err)
	}
	raw := buf.Bytes()

	if actual := actualSignedVSize(repl); actual > vsize {
		return sendArtifact{}, domain.Newf(domain.CodeStateCorrupt,
			"replacement vsize estimate %d vB underpays the actual signed vsize %d vB", vsize, actual)
	}

	coins := make([]coinselect.Coin, len(inputs))
	copy(coins, inputs)
	return sendArtifact{
		rawTx:      raw,
		txid:       repl.TxHash().String(),
		feeSat:     feeSat,
		feeRate:    newRate,
		vsize:      vsize,
		inputs:     coins,
		inAddr:     inAddr,
		recipient:  recipientAddr,
		recipSat:   recipSat,
		changeSat:  changeSat,
		changeAddr: changeAddrForResult,
	}, nil
}

// errInsufficientReplacementInputs is the internal sentinel meaning the base inputs
// cannot cover a speedup's fee bump (change would go dust) — a superset input is
// needed.
var errInsufficientReplacementInputs = domain.New(domain.CodeFundsInsufficient+"_confirmed",
	"the original inputs cannot cover the higher fee; an additional confirmed input is required")

// pickExtraInput finds one confirmed, in-gap, non-reserved, not-already-used UTXO to
// add to a speedup (BIP-125 superset). It returns funds.insufficient_confirmed when
// none is available.
func (s *Service) pickExtraInput(ctx context.Context, client interface {
	UTXOs(ctx context.Context, addrs []string) ([]domain.UTXO, error)
}, byAddr map[string]addrCoords, used, consumed map[string]bool) (coinselect.Coin, error) {
	addrs := make([]string, 0, len(byAddr))
	for a := range byAddr {
		addrs = append(addrs, a)
	}
	utxos, err := client.UTXOs(ctx, addrs)
	if err != nil {
		return coinselect.Coin{}, err
	}
	for _, u := range utxos {
		if u.Confirmations <= 0 {
			continue
		}
		op := u.Txid + ":" + domain.IndexString(u.Vout)
		if used[op] || consumed[op] {
			continue
		}
		c, ok := byAddr[u.Address]
		if !ok {
			continue
		}
		return coinselect.Coin{Outpoint: op, Branch: c.branch, Index: c.index, ValueSat: u.ValueSat}, nil
	}
	return coinselect.Coin{}, domain.New(domain.CodeFundsInsufficient+"_confirmed",
		"no additional confirmed input is available to raise the replacement fee")
}

// addressForCoin resolves the wallet address a replacement input pays from: the
// original journal record's recorded input address (for a reused input), else a
// reverse lookup of (branch,index) in byAddr for an added input.
func addressForCoin(c coinselect.Coin, orig *journal.Record, byAddr map[string]addrCoords) string {
	for _, in := range orig.Inputs {
		if in.Txid+":"+domain.IndexString(in.Vout) == c.Outpoint {
			return in.Address
		}
	}
	for a, co := range byAddr {
		if co.branch == c.Branch && co.index == c.Index {
			return a
		}
	}
	return ""
}

// resolveBumpRate computes the replacement fee-rate: an explicit --fee-rate verbatim,
// else max(originalRate+1, backend fast estimate) clamped to the relay floor. It
// always returns a rate the caller still asserts is strictly > the original.
func resolveBumpRate(feeRateStr string, origRate int64, est domain.FeeEstimates) (int64, error) {
	if feeRateStr != "" {
		return parseFeeRate(feeRateStr)
	}
	bump := origRate + 1
	if est.Fast > bump {
		bump = est.Fast
	}
	if bump < minRelayFeeRate {
		bump = minRelayFeeRate
	}
	if bump > maxFeeRate {
		bump = maxFeeRate
	}
	return bump, nil
}

// anyInputSignalsRBF reports whether any input of tx signals opt-in RBF (BIP-125):
// an input with nSequence < 0xfffffffe.
func anyInputSignalsRBF(tx *wire.MsgTx) bool {
	for i := range tx.TxIn {
		if tx.TxIn[i].Sequence < 0xfffffffe {
			return true
		}
	}
	return false
}

// decodeWireTx deserializes a hex-encoded wire tx.
func decodeWireTx(rawHex string) (*wire.MsgTx, error) {
	raw, err := hex.DecodeString(rawHex)
	if err != nil {
		return nil, err
	}
	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(raw)); err != nil {
		return nil, err
	}
	return &tx, nil
}

// mapReplacementRejectErr maps a permanent broadcast reject of a REPLACEMENT to the
// tx.replacement_rejected / tx.fee_too_low domain code.
func mapReplacementRejectErr(err error) error {
	if de := domain.AsError(err); de != nil {
		switch de.Code {
		case domain.CodeTxFeeTooLow:
			return de // fee floor / min-relay — keep the precise code
		case domain.CodeTxInputSpent:
			return de
		}
	}
	return domain.Wrap("tx.replacement_rejected", "the replacement was rejected by the network", err)
}

// replacementResult is the accepted-replacement result.
func (s *Service) replacementResult(wallet string, art sendArtifact, journalID, txid, replacesTxid string) domain.TxResult {
	res := s.broadcastResult(wallet, art, journalID, txid)
	res.Replacement = true
	res.ReplacesTxid = replacesTxid
	return res
}

// replacementSignedResult is the transport-exhausted-replacement result (recoverable).
func (s *Service) replacementSignedResult(wallet string, art sendArtifact, journalID, replacesTxid string) domain.TxResult {
	res := s.signedResult(wallet, art, journalID)
	res.Replacement = true
	res.ReplacesTxid = replacesTxid
	return res
}
