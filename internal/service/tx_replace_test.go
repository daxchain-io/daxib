package service

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	fakebackend "github.com/daxchain-io/daxib/internal/backend/fake"
	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/journal"
)

// rbfFixture is a service over a fake backend with the vector wallet funded by two
// confirmed coins on receive-0, plus a captured-broadcast hook. It performs an
// initial send and returns the original TxResult so a speedup/cancel can replace it.
type rbfFixture struct {
	svc      *Service
	fake     *fakebackend.Client
	teardown func()
	// captured holds the most recent broadcast bytes.
	captured *[]byte
}

func newRBFFixture(t *testing.T) *rbfFixture {
	t.Helper()
	fake := fakebackend.New()
	fake.Tip = 800000
	// Two confirmed coins so a speedup that needs a superset input has one available.
	programUTXO(fake, canonicalReceive0, "aa"+strings.Repeat("0", 62), 0, 1_000_000)
	programUTXO(fake, canonicalReceive0, "aa"+strings.Repeat("0", 62), 1, 1_000_000)

	var captured []byte
	var mu sync.Mutex
	fake.BroadcastFn = func(_ context.Context, raw []byte) (string, error) {
		mu.Lock()
		captured = append([]byte(nil), raw...)
		mu.Unlock()
		tx := wire.NewMsgTx(2)
		if err := tx.Deserialize(bytes.NewReader(raw)); err != nil {
			return "", err
		}
		return tx.TxHash().String(), nil
	}
	svc, teardown := newSendService(t, fake)
	return &rbfFixture{svc: svc, fake: fake, teardown: teardown, captured: &captured}
}

// sendOriginal performs a happy-path send at the given fee-rate and returns the
// result (the tx to be replaced).
func (f *rbfFixture) sendOriginal(t *testing.T, amount string, feeRate string) domain.TxResult {
	t.Helper()
	res, err := f.svc.SendTx(context.Background(), domain.SendRequest{
		Wallet: "vec", To: extRecipient, Amount: amount, FeeRate: feeRate, Yes: true,
	}, nil)
	if err != nil {
		t.Fatalf("sendOriginal: %v", err)
	}
	return res
}

// engineVerify runs txscript.NewEngine(StandardVerifyFlags) on every input of tx,
// proving the signatures are real and spendable. prevValues/prevScripts index by
// input.
func engineVerify(t *testing.T, tx *wire.MsgTx, prevScripts [][]byte, prevValues []int64) {
	t.Helper()
	prevOuts := map[wire.OutPoint]*wire.TxOut{}
	for i := range tx.TxIn {
		prevOuts[tx.TxIn[i].PreviousOutPoint] = wire.NewTxOut(prevValues[i], prevScripts[i])
	}
	fetcher := txscript.NewMultiPrevOutFetcher(prevOuts)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)
	for i := range tx.TxIn {
		eng, err := txscript.NewEngine(prevScripts[i], tx, i, txscript.StandardVerifyFlags, nil, sigHashes, prevValues[i], fetcher)
		if err != nil {
			t.Fatalf("NewEngine input %d: %v", i, err)
		}
		if err := eng.Execute(); err != nil {
			t.Fatalf("engine.Execute input %d FAILED (unspendable): %v", i, err)
		}
	}
}

// prevForTx resolves the prevScripts+prevValues for a replacement tx from the
// fixture's known funded address (all inputs pay from canonicalReceive0 here).
func (f *rbfFixture) prevForTx(t *testing.T, tx *wire.MsgTx) ([][]byte, []int64) {
	t.Helper()
	script := scriptOf(t, canonicalReceive0)
	scripts := make([][]byte, len(tx.TxIn))
	values := make([]int64, len(tx.TxIn))
	for i := range tx.TxIn {
		scripts[i] = script
		values[i] = 1_000_000 // every funded coin in the fixture is 1,000,000 sat
	}
	return scripts, values
}

// TestSpeedupBuildsValidReplacement_EngineProof is the RBF correctness anchor: a
// speedup over a canonical-wallet signed original is engine-verified spendable on
// every input.
func TestSpeedupBuildsValidReplacement_EngineProof(t *testing.T) {
	f := newRBFFixture(t)
	defer f.teardown()

	orig := f.sendOriginal(t, "0.005", "5")

	res, err := f.svc.SpeedupTx(context.Background(), domain.SpeedupRequest{
		Wallet: "vec", Txid: orig.Txid, FeeRate: "20", Yes: true,
	}, nil)
	if err != nil {
		t.Fatalf("SpeedupTx: %v", err)
	}
	if !res.Replacement || res.ReplacesTxid != orig.Txid {
		t.Fatalf("result not marked as a replacement of %s: %+v", orig.Txid, res)
	}

	repl := wire.NewMsgTx(2)
	if err := repl.Deserialize(bytes.NewReader(*f.captured)); err != nil {
		t.Fatalf("deserialize replacement: %v", err)
	}
	scripts, values := f.prevForTx(t, repl)
	engineVerify(t, repl, scripts, values)
}

// TestSpeedupBIP125Rules asserts the BIP-125 invariants: the replacement's absolute
// fee AND feerate exceed the original's, the input set is same-or-superset, and
// every input signals RBF (nSequence 0xfffffffd).
func TestSpeedupBIP125Rules(t *testing.T) {
	f := newRBFFixture(t)
	defer f.teardown()

	orig := f.sendOriginal(t, "0.005", "5")
	origTx := wire.NewMsgTx(2)
	if err := origTx.Deserialize(bytes.NewReader(*f.captured)); err != nil {
		t.Fatalf("deserialize original: %v", err)
	}
	origOutpoints := map[wire.OutPoint]bool{}
	for _, in := range origTx.TxIn {
		origOutpoints[in.PreviousOutPoint] = true
	}

	res, err := f.svc.SpeedupTx(context.Background(), domain.SpeedupRequest{
		Wallet: "vec", Txid: orig.Txid, FeeRate: "20", Yes: true,
	}, nil)
	if err != nil {
		t.Fatalf("SpeedupTx: %v", err)
	}

	// Rule 3: absolute fee strictly higher.
	if res.FeeSat <= orig.FeeSat {
		t.Errorf("replacement fee %d must exceed original %d (BIP-125 rule 3)", res.FeeSat, orig.FeeSat)
	}
	// Rule 4: feerate strictly higher.
	if res.FeeRate <= orig.FeeRate {
		t.Errorf("replacement feerate %d must exceed original %d (BIP-125 rule 4)", res.FeeRate, orig.FeeRate)
	}

	repl := wire.NewMsgTx(2)
	if err := repl.Deserialize(bytes.NewReader(*f.captured)); err != nil {
		t.Fatalf("deserialize replacement: %v", err)
	}
	// Rule 2: same-or-superset inputs.
	for _, in := range origTx.TxIn {
		found := false
		for _, rin := range repl.TxIn {
			if rin.PreviousOutPoint == in.PreviousOutPoint {
				found = true
			}
		}
		if !found {
			t.Errorf("replacement dropped original input %v (must be same-or-superset)", in.PreviousOutPoint)
		}
	}
	// RBF signaled on every input.
	for i, in := range repl.TxIn {
		if in.Sequence != 0xfffffffd {
			t.Errorf("replacement input %d nSequence=%#x, want 0xfffffffd (RBF)", i, in.Sequence)
		}
	}
}

// TestCancelRedirectsToSelf_EngineProof: a cancel pays 100%-newFee to a wallet-owned
// change address; the original recipient output is absent and the sole output is
// wallet-owned. The replacement is engine-verified spendable.
func TestCancelRedirectsToSelf_EngineProof(t *testing.T) {
	f := newRBFFixture(t)
	defer f.teardown()

	orig := f.sendOriginal(t, "0.005", "5")

	res, err := f.svc.CancelTx(context.Background(), domain.CancelRequest{
		Wallet: "vec", Txid: orig.Txid, FeeRate: "20", Yes: true,
	}, nil)
	if err != nil {
		t.Fatalf("CancelTx: %v", err)
	}
	if !res.Replacement {
		t.Fatalf("cancel result not marked as a replacement: %+v", res)
	}

	repl := wire.NewMsgTx(2)
	if err := repl.Deserialize(bytes.NewReader(*f.captured)); err != nil {
		t.Fatalf("deserialize cancel: %v", err)
	}
	scripts, values := f.prevForTx(t, repl)
	engineVerify(t, repl, scripts, values)

	// The original recipient output must be ABSENT.
	recipScript := scriptOf(t, extRecipient)
	for _, o := range repl.TxOut {
		if bytes.Equal(o.PkScript, recipScript) {
			t.Fatalf("cancel still pays the original recipient — payment not voided")
		}
	}
	// Every output must be wallet-owned (a change-branch address).
	_, scan, _ := f.svc.keys.ScanAddresses(context.Background(), "vec", gapWindow)
	walletScripts := map[string]bool{}
	for _, a := range scan {
		walletScripts[string(scriptOf(t, a.Address))] = true
	}
	for _, o := range repl.TxOut {
		if !walletScripts[string(o.PkScript)] {
			t.Errorf("cancel output is not wallet-owned: %x", o.PkScript)
		}
	}
}

// TestJournalLinksOriginalToReplacement: after an accepted speedup the original is
// StatusReplaced with ReplacedByID == replacement.ID, the replacement's ReplacesID ==
// original.ID, the original is excluded from Unresolved() but present in List().
func TestJournalLinksOriginalToReplacement(t *testing.T) {
	f := newRBFFixture(t)
	defer f.teardown()

	orig := f.sendOriginal(t, "0.005", "5")
	origID := orig.JournalID

	res, err := f.svc.SpeedupTx(context.Background(), domain.SpeedupRequest{
		Wallet: "vec", Txid: orig.Txid, FeeRate: "20", Yes: true,
	}, nil)
	if err != nil {
		t.Fatalf("SpeedupTx: %v", err)
	}
	replID := res.JournalID

	ctx := context.Background()
	origRec, _ := f.svc.journal.ByID(ctx, domain.NetworkMainnet, origID)
	replRec, _ := f.svc.journal.ByID(ctx, domain.NetworkMainnet, replID)

	if origRec.Status != journal.StatusReplaced {
		t.Errorf("original status=%q, want replaced", origRec.Status)
	}
	if origRec.ReplacedByID != replID {
		t.Errorf("original ReplacedByID=%q, want %q", origRec.ReplacedByID, replID)
	}
	if replRec.ReplacesID != origID {
		t.Errorf("replacement ReplacesID=%q, want %q", replRec.ReplacesID, origID)
	}

	// The original is excluded from Unresolved (it is terminal) but kept in List.
	unresolved, _ := f.svc.journal.Unresolved(ctx, domain.NetworkMainnet)
	for _, r := range unresolved {
		if r.ID == origID {
			t.Errorf("replaced original still in Unresolved()")
		}
	}
	list, _ := f.svc.journal.List(ctx, domain.NetworkMainnet, "vec")
	var foundOrig bool
	for _, r := range list {
		if r.ID == origID {
			foundOrig = true
		}
	}
	if !foundOrig {
		t.Errorf("replaced original missing from List() history")
	}
}

// TestSpeedupRejectsConfirmedOriginal: the backend reports the original confirmed;
// speedup refuses with tx.replaced (exit 9) and makes no journal mutation.
func TestSpeedupRejectsConfirmedOriginal(t *testing.T) {
	f := newRBFFixture(t)
	defer f.teardown()

	orig := f.sendOriginal(t, "0.005", "5")

	f.fake.TxStatusFn = func(_ context.Context, txid string) (domain.TxStatus, error) {
		return domain.TxStatus{Txid: txid, Confirmed: true, Confirmations: 1, BlockHeight: 800001}, nil
	}
	_, err := f.svc.SpeedupTx(context.Background(), domain.SpeedupRequest{
		Wallet: "vec", Txid: orig.Txid, FeeRate: "20", Yes: true,
	}, nil)
	de := domain.AsError(err)
	if de == nil || de.Code != "tx.replaced" {
		t.Fatalf("err=%v, want tx.replaced (confirmed original)", err)
	}

	// The original record was NOT mutated to replaced.
	rec, _ := f.svc.journal.ByID(context.Background(), domain.NetworkMainnet, orig.JournalID)
	if rec.Status == journal.StatusReplaced {
		t.Errorf("confirmed original was wrongly flipped to replaced")
	}
}

// TestSpeedupRejectsTerminalOriginal: a failed/replaced original -> tx.replaced,
// no build.
func TestSpeedupRejectsTerminalOriginal(t *testing.T) {
	f := newRBFFixture(t)
	defer f.teardown()

	orig := f.sendOriginal(t, "0.005", "5")

	// First speedup succeeds; the original becomes terminal (replaced).
	if _, err := f.svc.SpeedupTx(context.Background(), domain.SpeedupRequest{
		Wallet: "vec", Txid: orig.Txid, FeeRate: "20", Yes: true,
	}, nil); err != nil {
		t.Fatalf("first speedup: %v", err)
	}
	// A second speedup of the now-replaced ORIGINAL txid must refuse.
	_, err := f.svc.SpeedupTx(context.Background(), domain.SpeedupRequest{
		Wallet: "vec", Txid: orig.Txid, FeeRate: "40", Yes: true,
	}, nil)
	de := domain.AsError(err)
	if de == nil || de.Code != "tx.replaced" {
		t.Fatalf("err=%v, want tx.replaced (terminal original)", err)
	}
}

// TestSpeedupNonTTYNoYesConfirmRequired: a replacement without --yes on a non-TTY is
// CodeUsageConfirmRequired (exit 2).
func TestSpeedupNonTTYNoYesConfirmRequired(t *testing.T) {
	f := newRBFFixture(t)
	defer f.teardown()

	orig := f.sendOriginal(t, "0.005", "5")
	_, err := f.svc.SpeedupTx(context.Background(), domain.SpeedupRequest{
		Wallet: "vec", Txid: orig.Txid, FeeRate: "20", Yes: false,
	}, nil)
	de := domain.AsError(err)
	if de == nil || de.Code != domain.CodeUsageConfirmRequired {
		t.Fatalf("err=%v, want usage.confirmation_required", err)
	}
}

// TestSpeedupAddsInputWhenChangeless: an original whose change was folded into the
// fee (changeless) cannot shrink change to cover a bump — the speedup must add a
// confirmed in-gap UTXO (superset, BIP-125 rule 2). The multi-input replacement is
// engine-verified.
func TestSpeedupAddsInputWhenChangeless(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	// One coin sized so the send leaves SUB-DUST surplus (changeless original), plus a
	// second coin available to add on speedup. A single-input P2WPKH→P2WPKH tx is
	// ~110-141 vB; at rate 1 a 400-sat surplus over the 500_000 amount goes to fee
	// (change candidate < the 294 dust threshold) ⇒ changeless.
	programUTXO(fake, canonicalReceive0, "cc"+strings.Repeat("0", 62), 0, 500_400)
	programUTXO(fake, canonicalReceive0, "cc"+strings.Repeat("0", 62), 1, 1_000_000)

	var captured []byte
	captureBroadcast(fake, &captured)
	svc, teardown := newSendService(t, fake)
	defer teardown()

	// Send an amount that leaves sub-dust change at rate 1 ⇒ changeless original.
	orig, err := svc.SendTx(context.Background(), domain.SendRequest{
		Wallet: "vec", To: extRecipient, Amount: "500000sat", FeeRate: "1", Yes: true,
	}, nil)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	origTx := wire.NewMsgTx(2)
	_ = origTx.Deserialize(bytes.NewReader(captured))
	if len(origTx.TxOut) != 1 {
		t.Fatalf("expected a changeless original (1 output), got %d", len(origTx.TxOut))
	}

	// Speed it up: the single input cannot cover a higher fee with a recipient that
	// consumes nearly all of it, so an extra input must be added.
	res, serr := svc.SpeedupTx(context.Background(), domain.SpeedupRequest{
		Wallet: "vec", Txid: orig.Txid, FeeRate: "10", Yes: true,
	}, nil)
	if serr != nil {
		t.Fatalf("speedup (changeless): %v", serr)
	}

	repl := wire.NewMsgTx(2)
	if err := repl.Deserialize(bytes.NewReader(captured)); err != nil {
		t.Fatalf("deserialize replacement: %v", err)
	}
	if len(repl.TxIn) <= len(origTx.TxIn) {
		t.Fatalf("changeless speedup did not add a superset input: orig %d inputs, repl %d", len(origTx.TxIn), len(repl.TxIn))
	}
	if res.FeeSat <= orig.FeeSat {
		t.Errorf("replacement fee %d must exceed original %d", res.FeeSat, orig.FeeSat)
	}

	// Engine-verify every input of the multi-input replacement. Both coins are on
	// canonicalReceive0; resolve each input's value by its outpoint vout.
	script := scriptOf(t, canonicalReceive0)
	valueByVout := map[uint32]int64{0: 500_400, 1: 1_000_000}
	scripts := make([][]byte, len(repl.TxIn))
	values := make([]int64, len(repl.TxIn))
	for i := range repl.TxIn {
		scripts[i] = script
		values[i] = valueByVout[repl.TxIn[i].PreviousOutPoint.Index]
	}
	engineVerify(t, repl, scripts, values)
}

// TestSpeedupTransportExhaustedLeavesReplacementSignedOriginalUnflipped: when the
// replacement broadcast transport-exhausts, the replacement stays `signed`, the
// original is NOT flipped to replaced, and the delta reservation is kept.
func TestSpeedupTransportExhaustedLeavesReplacementSignedOriginalUnflipped(t *testing.T) {
	f := newRBFFixture(t)
	defer f.teardown()

	orig := f.sendOriginal(t, "0.005", "5")

	origBackoff := broadcastBackoff
	broadcastBackoff = []time.Duration{0}
	defer func() { broadcastBackoff = origBackoff }()

	f.fake.BroadcastFn = func(_ context.Context, _ []byte) (string, error) {
		return "", domain.New(domain.CodeBackendUnreachable, "connection refused")
	}
	res, err := f.svc.SpeedupTx(context.Background(), domain.SpeedupRequest{
		Wallet: "vec", Txid: orig.Txid, FeeRate: "20", Yes: true,
	}, nil)
	if err == nil {
		t.Fatalf("expected a recoverable transport error")
	}

	ctx := context.Background()
	replRec, _ := f.svc.journal.ByID(ctx, domain.NetworkMainnet, res.JournalID)
	if replRec.Status != journal.StatusSigned {
		t.Errorf("replacement status=%q after transport exhaustion, want signed (recoverable)", replRec.Status)
	}
	origRec, _ := f.svc.journal.ByID(ctx, domain.NetworkMainnet, orig.JournalID)
	if origRec.Status == journal.StatusReplaced {
		t.Errorf("original was flipped to replaced despite the replacement not being live")
	}
}

// TestSpeedupRejectedDoesNotStrandOriginal: a permanent reject of the replacement
// terminalizes the REPLACEMENT (failed) and leaves the original untouched/live; the
// error is tx.replacement_rejected.
func TestSpeedupRejectedDoesNotStrandOriginal(t *testing.T) {
	f := newRBFFixture(t)
	defer f.teardown()

	orig := f.sendOriginal(t, "0.005", "5")

	f.fake.BroadcastFn = func(_ context.Context, _ []byte) (string, error) {
		return "", domain.New(domain.CodeBackendRPCError, "bad-txns-inputs-missingorspent")
	}
	res, err := f.svc.SpeedupTx(context.Background(), domain.SpeedupRequest{
		Wallet: "vec", Txid: orig.Txid, FeeRate: "20", Yes: true,
	}, nil)
	if err == nil {
		t.Fatalf("expected a reject error")
	}

	ctx := context.Background()
	replRec, _ := f.svc.journal.ByID(ctx, domain.NetworkMainnet, res.JournalID)
	if res.JournalID != "" && replRec != nil && replRec.Status != journal.StatusFailed {
		t.Errorf("rejected replacement status=%q, want failed", replRec.Status)
	}
	origRec, _ := f.svc.journal.ByID(ctx, domain.NetworkMainnet, orig.JournalID)
	if origRec.Status == journal.StatusReplaced {
		t.Errorf("original was wrongly flipped to replaced on a rejected replacement")
	}
	// The original is still live (broadcast) and tracked.
	if origRec.Status != journal.StatusBroadcast {
		t.Errorf("original status=%q, want broadcast (untouched/live)", origRec.Status)
	}
}

// TestDoubleSpeedupChainsReplacements: after a speedup, the user bumps AGAIN via the
// replacement's txid. The second replacement links to the first.
func TestDoubleSpeedupChainsReplacements(t *testing.T) {
	f := newRBFFixture(t)
	defer f.teardown()

	orig := f.sendOriginal(t, "0.005", "5")

	repl1, err := f.svc.SpeedupTx(context.Background(), domain.SpeedupRequest{
		Wallet: "vec", Txid: orig.Txid, FeeRate: "20", Yes: true,
	}, nil)
	if err != nil {
		t.Fatalf("speedup 1: %v", err)
	}
	// Bump again via the REPLACEMENT's txid (it is broadcast + RBF-signaling).
	repl2, err := f.svc.SpeedupTx(context.Background(), domain.SpeedupRequest{
		Wallet: "vec", Txid: repl1.Txid, FeeRate: "50", Yes: true,
	}, nil)
	if err != nil {
		t.Fatalf("speedup 2: %v", err)
	}

	ctx := context.Background()
	rec1, _ := f.svc.journal.ByID(ctx, domain.NetworkMainnet, repl1.JournalID)
	rec2, _ := f.svc.journal.ByID(ctx, domain.NetworkMainnet, repl2.JournalID)
	if rec1.Status != journal.StatusReplaced {
		t.Errorf("first replacement status=%q, want replaced", rec1.Status)
	}
	if rec2.ReplacesID != repl1.JournalID {
		t.Errorf("second replacement ReplacesID=%q, want %q", rec2.ReplacesID, repl1.JournalID)
	}
	if repl2.FeeSat <= repl1.FeeSat {
		t.Errorf("second replacement fee %d must exceed the first %d", repl2.FeeSat, repl1.FeeSat)
	}
}

// TestSpeedupNonExistentTxidNotFound: a txid with no journal record is ref.not_found
// (exit 10).
func TestSpeedupNonExistentTxidNotFound(t *testing.T) {
	f := newRBFFixture(t)
	defer f.teardown()
	_, err := f.svc.SpeedupTx(context.Background(), domain.SpeedupRequest{
		Wallet: "vec", Txid: strings.Repeat("ab", 32), FeeRate: "20", Yes: true,
	}, nil)
	de := domain.AsError(err)
	if de == nil || de.Code != domain.CodeRefNotFound {
		t.Fatalf("err=%v, want ref.not_found", err)
	}
}

// TestSpeedupRateNotAboveOriginalRejected: a --fee-rate not exceeding the original is
// tx.replacement_rejected (BIP-125 rule 4).
func TestSpeedupRateNotAboveOriginalRejected(t *testing.T) {
	f := newRBFFixture(t)
	defer f.teardown()
	orig := f.sendOriginal(t, "0.005", "10")
	_, err := f.svc.SpeedupTx(context.Background(), domain.SpeedupRequest{
		Wallet: "vec", Txid: orig.Txid, FeeRate: "10", Yes: true, // equal, not higher
	}, nil)
	de := domain.AsError(err)
	if de == nil || de.Code != "tx.replacement_rejected" {
		t.Fatalf("err=%v, want tx.replacement_rejected (rate must exceed original)", err)
	}
}

// TestSpeedupForeignInputRefusesStateCorrupt: a journal record whose input address is
// outside the wallet's scan/gap window cannot be mapped to a signing key — the
// speedup refuses with state.corrupt rather than signing with a wrong key.
func TestSpeedupForeignInputRefusesStateCorrupt(t *testing.T) {
	f := newRBFFixture(t)
	defer f.teardown()

	orig := f.sendOriginal(t, "0.005", "5")

	// Corrupt the journaled original's input address to one outside the gap window.
	ctx := context.Background()
	rec, _ := f.svc.journal.ByID(ctx, domain.NetworkMainnet, orig.JournalID)
	rec.Inputs[0].Address = "bc1qforeignaddressnotinthewalletgapwindowxxxxxxxxx"
	// Re-append the mutated record (latest-wins) so ByTxid sees it.
	rec.Seq = 0
	if err := f.svc.journal.Append(ctx, &journal.Record{
		ID: rec.ID, Network: rec.Network, Wallet: rec.Wallet, Status: rec.Status, Txid: rec.Txid,
		RawTx: rec.RawTx, FeeRate: rec.FeeRate, FeeSat: rec.FeeSat, Vsize: rec.Vsize,
		Inputs: rec.Inputs, Outputs: rec.Outputs, RecipientAddr: rec.RecipientAddr,
		RecipientSat: rec.RecipientSat, ChangeAddr: rec.ChangeAddr,
	}); err != nil {
		t.Fatalf("re-append: %v", err)
	}

	_, err := f.svc.SpeedupTx(ctx, domain.SpeedupRequest{
		Wallet: "vec", Txid: orig.Txid, FeeRate: "20", Yes: true,
	}, nil)
	de := domain.AsError(err)
	if de == nil || de.Code != domain.CodeStateCorrupt {
		t.Fatalf("foreign-input speedup: err=%v, want state.corrupt", err)
	}
}

// TestSpeedupTOCTOUReplacedUnderLock is the RBF-LENS-1 regression: the original's
// terminality is re-asserted UNDER the send-lock (after reconcile), not only at the
// pre-lock check. Here a concurrent replacement is simulated by flipping the
// original to StatusReplaced AFTER the pre-lock read but the re-fetch under the lock
// observes it, so the second speedup aborts cleanly with tx.replaced and never
// builds a doomed double-replacement.
func TestSpeedupTOCTOUReplacedUnderLock(t *testing.T) {
	f := newRBFFixture(t)
	defer f.teardown()

	orig := f.sendOriginal(t, "0.005", "5")
	ctx := context.Background()

	// Flip the original to replaced (as a racing speedup that won the lock would). The
	// under-lock re-fetch (journal.ByID post-reconcile) must catch this even though it
	// was not terminal at the top-of-function read in a real race.
	repl := journal.StatusReplaced
	by := "rival-replacement"
	if err := f.svc.journal.SetState(ctx, domain.NetworkMainnet, orig.JournalID,
		journal.StateMutation{Status: repl, ReplacedBy: &by}); err != nil {
		t.Fatalf("flip original->replaced: %v", err)
	}

	_, err := f.svc.SpeedupTx(ctx, domain.SpeedupRequest{
		Wallet: "vec", Txid: orig.Txid, FeeRate: "20", Yes: true,
	}, nil)
	de := domain.AsError(err)
	if de == nil || de.Code != "tx.replaced" {
		t.Fatalf("speedup of an already-replaced original: err=%v, want tx.replaced", err)
	}
}

// TestSpeedupTOCTOUConfirmedUnderLock proves the under-lock CONFIRMATION re-poll
// (RBF-LENS-1): the backend reports the original UNCONFIRMED on the pre-lock poll
// but CONFIRMED on the under-lock poll. The speedup must abort with tx.replaced from
// the second poll, never building a replacement of a now-mined tx.
func TestSpeedupTOCTOUConfirmedUnderLock(t *testing.T) {
	f := newRBFFixture(t)
	defer f.teardown()

	orig := f.sendOriginal(t, "0.005", "5")

	var polls int
	var mu sync.Mutex
	f.fake.TxStatusFn = func(_ context.Context, txid string) (domain.TxStatus, error) {
		mu.Lock()
		polls++
		n := polls
		mu.Unlock()
		if n == 1 {
			return domain.TxStatus{Txid: txid, Confirmed: false}, nil // pre-lock: still live
		}
		// under-lock re-poll: now confirmed.
		return domain.TxStatus{Txid: txid, Confirmed: true, Confirmations: 1, BlockHeight: 800001}, nil
	}

	_, err := f.svc.SpeedupTx(context.Background(), domain.SpeedupRequest{
		Wallet: "vec", Txid: orig.Txid, FeeRate: "20", Yes: true,
	}, nil)
	de := domain.AsError(err)
	if de == nil || de.Code != "tx.replaced" {
		t.Fatalf("speedup of an under-lock-confirmed original: err=%v, want tx.replaced", err)
	}
	mu.Lock()
	gotPolls := polls
	mu.Unlock()
	if gotPolls < 2 {
		t.Fatalf("expected at least 2 TxStatus polls (pre-lock + under-lock), got %d", gotPolls)
	}
	// The original must NOT have been flipped to replaced (no replacement was built).
	rec, _ := f.svc.journal.ByID(context.Background(), domain.NetworkMainnet, orig.JournalID)
	if rec.Status == journal.StatusReplaced {
		t.Errorf("under-lock-confirmed original wrongly flipped to replaced")
	}
}
