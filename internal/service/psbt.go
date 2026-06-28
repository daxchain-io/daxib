package service

import (
	"bytes"
	"context"

	"github.com/btcsuite/btcd/btcutil"
	btcpsbt "github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"

	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/journal"
	"github.com/daxchain-io/daxib/internal/keys"
	"github.com/daxchain-io/daxib/internal/policy"
	"github.com/daxchain-io/daxib/internal/psbt"
)

// psbt.go is the service-side PSBT (BIP-174) use cases — the ONLY layer that
// touches keys + policy + backend + journal + coinselect + the psbt leaf. The
// policy chokepoint lives in PSBTSign: it derives + re-verifies this wallet's NET
// outflow, runs the per-recipient deny/allow gate + the aggregate eng.Reserve
// BEFORE keys.SignInputs produces a single byte, exactly mirroring the send
// pipeline. PSBT is provably NOT a policy bypass (the lattice physically bars a
// frontend from reaching keys/psbt directly).
//
// P2WPKH/BIP-84 only: ownership is decided by matching an input's prevout script
// against the wallet's OWN derived scripts (never a counterparty Bip32Derivation),
// so a foreign Taproot/multisig/non-witness input is correctly left unsigned.

// PSBTCreate builds an UNSIGNED, fully-populated v2/RBF PSBT spending the wallet's
// confirmed UTXOs to To/Amount. It reuses buildUnsigned (the front half of the
// send build) then serializes a PSBT instead of signing/broadcasting. It
// authorizes nothing (an unsigned tx moves no funds): NO policy reservation, NO
// journal — it only advances the change watermark via DeriveNext (a created PSBT is
// a real intent to spend that change index out-of-band, so the index must be
// stable; the cost of an abandoned PSBT is one burned change index, same as an
// abandoned send).
func (s *Service) PSBTCreate(ctx context.Context, req domain.PSBTCreateRequest) (domain.PSBTResult, error) {
	if err := s.requireNetwork(); err != nil {
		return domain.PSBTResult{}, err
	}
	resolvedTo, rerr := s.resolveDestination(ctx, req.To)
	if rerr != nil {
		return domain.PSBTResult{}, rerr
	}
	req.To = resolvedTo

	sendReq := domain.SendRequest{Wallet: req.Wallet, To: req.To, Amount: req.Amount, FeeRate: req.FeeRate, Speed: req.Speed}
	if err := s.validateSendInputs(sendReq); err != nil {
		return domain.PSBTResult{}, err
	}
	wallet, err := s.resolveWallet(ctx, req.Wallet)
	if err != nil {
		return domain.PSBTResult{}, err
	}
	if err := s.assertWalletNetwork(ctx, wallet); err != nil {
		return domain.PSBTResult{}, err
	}

	client, _, _, err := s.dialActiveBackend(ctx)
	if err != nil {
		return domain.PSBTResult{}, err
	}
	defer client.Close()

	// Resolve the fee rate exactly like send (explicit --fee-rate verbatim, else the
	// backend estimate by --speed, clamped to the relay floor).
	var est domain.FeeEstimates
	if req.FeeRate == "" {
		est, err = client.FeeEstimates(ctx)
		if err != nil {
			return domain.PSBTResult{}, err
		}
	}
	feeRate, err := resolveFeeRate(req.FeeRate, req.Speed, est)
	if err != nil {
		return domain.PSBTResult{}, err
	}

	// Build the unsigned tx UNDER NO LOCK (create takes no reservation). dryRun=false
	// so the change index is DeriveNext'd (a created PSBT is a real intent to spend
	// it out-of-band). consumed=nil (no send-lock; create does not guard against an
	// in-flight send — the eventual psbt sign/broadcast re-derives + re-verifies).
	b, err := s.buildUnsigned(ctx, wallet, client, sendReq, feeRate, false, nil)
	if err != nil {
		return domain.PSBTResult{}, err
	}

	// Attach per-input WitnessUtxo + BIP-32 hint, and the change output's BIP-32 hint.
	inputMeta := make([]psbt.InputMeta, len(b.specs))
	for i, sp := range b.specs {
		pk, perr := s.keys.PubKeyAt(ctx, wallet, s.net, sp.Branch, sp.AddrIndex)
		if perr != nil {
			return domain.PSBTResult{}, perr
		}
		inputMeta[i] = psbt.InputMeta{
			PrevScript: sp.PrevScript,
			PrevValue:  sp.PrevValue,
			Bip32: psbt.InputBip32{
				PubKey: pk.PubKey, Fingerprint: pk.Fingerprint, Path: pk.PathIndices,
			},
		}
	}
	var ownedOuts []psbt.OutputBip32
	if b.changeIdx >= 0 {
		// The change output is the next CHANGE index DeriveNext just allocated, i.e.
		// NextChange-1. PubKeyAt re-derives it for the BIP-32 hint.
		ci, cerr := s.changeIndexFor(ctx, wallet, b.changeAddr)
		if cerr == nil {
			pk, perr := s.keys.PubKeyAt(ctx, wallet, s.net, domain.BranchChange, ci)
			if perr == nil {
				ownedOuts = append(ownedOuts, psbt.OutputBip32{
					Index: b.changeIdx,
					Bip32: psbt.InputBip32{PubKey: pk.PubKey, Fingerprint: pk.Fingerprint, Path: pk.PathIndices},
				})
			}
		}
	}

	pkt, err := psbt.BuildFromUnsigned(b.tx, inputMeta, ownedOuts)
	if err != nil {
		return domain.PSBTResult{}, err
	}
	b64, err := psbt.Encode(pkt)
	if err != nil {
		return domain.PSBTResult{}, err
	}
	res := s.psbtSummary(pkt, wallet)
	res.PSBT = b64
	res.FeeRate = feeRate
	return res, nil
}

// changeIndexFor finds the change index whose derived address equals addr (the
// address buildUnsigned just allocated). It scans the gap window — cheap and
// passphrase-free — so the BIP-32 hint on the change output is exact.
func (s *Service) changeIndexFor(ctx context.Context, wallet, addr string) (uint32, error) {
	_, scan, err := s.keys.ScanAddresses(ctx, wallet, s.net, gapWindow)
	if err != nil {
		return 0, err
	}
	for _, a := range scan {
		if a.Branch == domain.BranchChange && a.Address == addr {
			return a.Index, nil
		}
	}
	return 0, domain.New(domain.CodeStateCorrupt, "change address not found in the gap window")
}

// PSBTDecode is the read-only inspection verb: decode + annotate which inputs/
// outputs are wallet-owned, the fee/fee-rate/vsize, and which inputs are signed. No
// keystore/backend/policy.
func (s *Service) PSBTDecode(ctx context.Context, req domain.PSBTDecodeRequest) (domain.PSBTResult, error) {
	if err := s.requireNetwork(); err != nil {
		return domain.PSBTResult{}, err
	}
	pkt, err := psbt.Decode(req.PSBT)
	if err != nil {
		return domain.PSBTResult{}, err
	}
	wallet := req.Wallet
	if rw, rerr := s.resolveWallet(ctx, req.Wallet); rerr == nil {
		wallet = rw
	}
	res := s.psbtSummary(pkt, wallet)
	res.PSBT = req.PSBT
	return res, nil
}

// PSBTCombine merges N PSBTs sharing an identical unsigned tx. Pure leaf call.
func (s *Service) PSBTCombine(ctx context.Context, req domain.PSBTCombineRequest) (domain.PSBTResult, error) {
	if err := s.requireNetwork(); err != nil {
		return domain.PSBTResult{}, err
	}
	if len(req.PSBTs) == 0 {
		return domain.PSBTResult{}, domain.New(domain.CodePSBTRequired, "combine needs at least one PSBT")
	}
	parts := make([]*btcpsbt.Packet, 0, len(req.PSBTs))
	for _, b := range req.PSBTs {
		p, err := psbt.Decode(b)
		if err != nil {
			return domain.PSBTResult{}, err
		}
		parts = append(parts, p)
	}
	merged, err := psbt.Combine(parts)
	if err != nil {
		return domain.PSBTResult{}, err
	}
	b64, err := psbt.Encode(merged)
	if err != nil {
		return domain.PSBTResult{}, err
	}
	wallet := ""
	if rw, rerr := s.resolveWallet(ctx, ""); rerr == nil {
		wallet = rw
	}
	res := s.psbtSummary(merged, wallet)
	res.PSBT = b64
	return res, nil
}

// PSBTFinalize finalizes a PSBT (assembles FinalScriptWitness from PartialSigs).
// Pure. A still-incomplete result is reported as Complete=false (not an error — a
// co-signer may add more sigs).
func (s *Service) PSBTFinalize(ctx context.Context, req domain.PSBTFinalizeRequest) (domain.PSBTResult, error) {
	if err := s.requireNetwork(); err != nil {
		return domain.PSBTResult{}, err
	}
	pkt, err := psbt.Decode(req.PSBT)
	if err != nil {
		return domain.PSBTResult{}, err
	}
	if err := psbt.Finalize(pkt); err != nil {
		return domain.PSBTResult{}, err
	}
	b64, err := psbt.Encode(pkt)
	if err != nil {
		return domain.PSBTResult{}, err
	}
	wallet := ""
	if rw, rerr := s.resolveWallet(ctx, ""); rerr == nil {
		wallet = rw
	}
	res := s.psbtSummary(pkt, wallet)
	res.PSBT = b64
	return res, nil
}

// PSBTExtract finalizes-if-needed then extracts a COMPLETE PSBT to its raw network
// tx HEX. It is pure (no keystore/policy/backend) and does NOT re-derive a fee-rate
// estimate: extract takes no coinselect selection, so there is no build-time
// estimate to compare against. Relay-safety (a PSBT whose witnesses are larger than
// estimated would underpay) is enforced on the BUILD path (send.go) at create time
// and by the backend mempool's own relay-fee check at broadcast; an externally
// supplied PSBT is not second-guessed here.
func (s *Service) PSBTExtract(ctx context.Context, req domain.PSBTExtractRequest) (domain.PSBTResult, error) {
	if err := s.requireNetwork(); err != nil {
		return domain.PSBTResult{}, err
	}
	pkt, err := psbt.Decode(req.PSBT)
	if err != nil {
		return domain.PSBTResult{}, err
	}
	if !psbt.IsComplete(pkt) {
		// Try to finalize first (a single-sig operator may extract a signed-but-not-
		// finalized PSBT); a still-incomplete PSBT is a clean psbt.incomplete error.
		_ = psbt.Finalize(pkt)
	}
	rawHex, err := psbt.Extract(pkt)
	if err != nil {
		return domain.PSBTResult{}, err
	}
	res := domain.PSBTResult{RawTxHex: rawHex, Complete: true, Network: s.net}
	return res, nil
}

// PSBTSign is THE policy chokepoint (§2.7/§5.1). Order, fail-closed: requireNetwork
// → assertWalletNetwork → decode → ownership by SCRIPT match → re-verify owned
// prevout values against the backend → derive net outflow + classify outputs →
// per-distinct-external-recipient deny/allow eng.Check → one aggregate eng.Reserve
// → acquireSendLock → keys.SignInputs (verbatim) → lift each witness into a
// PartialSig → journal a `signed` record (PSBTBase64 + JInputs + ReservationID) and
// leave the reservation RESERVED (committed later by psbt broadcast). On any
// pre-signature failure the reservation is Released.
func (s *Service) PSBTSign(ctx context.Context, req domain.PSBTSignRequest, in PSBTSignInput) (domain.PSBTResult, error) {
	// (1) Network guards FIRST (mirroring MessageSign): a bound wallet cannot sign off
	// its locked network.
	if err := s.requireNetwork(); err != nil {
		return domain.PSBTResult{}, err
	}
	wallet, err := s.resolveWallet(ctx, req.Wallet)
	if err != nil {
		return domain.PSBTResult{}, err
	}
	if err := s.assertWalletNetwork(ctx, wallet); err != nil {
		return domain.PSBTResult{}, err
	}

	// A psbt sign produces an authorization that can leave the box, so it is a
	// money-authorizing op: non-TTY without --yes is a confirmation-required error.
	if !req.Yes {
		isTTY := s.secret.IsTTY != nil && s.secret.IsTTY()
		if !isTTY {
			return domain.PSBTResult{}, domain.New(domain.CodeUsageConfirmRequired,
				"signing a PSBT authorizes a spend: pass --yes to authorize this non-interactive sign")
		}
	}

	// (2) Decode.
	pkt, err := psbt.Decode(req.PSBT)
	if err != nil {
		return domain.PSBTResult{}, err
	}
	params := s.chainParams()

	// (3) OWNERSHIP: build the gap-window byScript map and mark each input OWNED by a
	// prevout-script match (never a counterparty Bip32Derivation).
	_, scan, err := s.keys.ScanAddresses(ctx, wallet, s.net, gapWindow)
	if err != nil {
		return domain.PSBTResult{}, err
	}
	type coords struct {
		branch domain.Branch
		index  uint32
		addr   string
	}
	byScript := make(map[string]coords, len(scan))
	addrs := make([]string, 0, len(scan))
	for _, a := range scan {
		ad, derr := btcutil.DecodeAddress(a.Address, params)
		if derr != nil {
			continue
		}
		sc, serr := txscript.PayToAddrScript(ad)
		if serr != nil {
			continue
		}
		byScript[psbt.ScriptHexKey(sc)] = coords{branch: a.Branch, index: a.Index, addr: a.Address}
		addrs = append(addrs, a.Address)
	}

	type ownedInput struct {
		idx       int
		branch    domain.Branch
		addrIndex uint32
		script    []byte
		address   string
		value     int64 // verified prevout value
		outpoint  string
	}
	var owned []ownedInput
	for i := range pkt.Inputs {
		script, val, ok := psbt.PrevScriptValue(pkt, i)
		if !ok {
			// No WitnessUtxo. Only a problem if the input IS ours (we cannot compute the
			// BIP-143 amount); a foreign input without a WitnessUtxo is simply not ours.
			continue
		}
		c, isOurs := byScript[psbt.ScriptHexKey(script)]
		if !isOurs {
			continue // FOREIGN input (a co-signer's) — leave unsigned.
		}
		op := pkt.UnsignedTx.TxIn[i].PreviousOutPoint
		owned = append(owned, ownedInput{
			idx: i, branch: c.branch, addrIndex: c.index,
			script: script, address: c.addr, value: val,
			outpoint: op.Hash.String() + ":" + domain.IndexString(op.Index),
		})
	}
	// An input without a WitnessUtxo cannot be valued for the BIP-143 witness amount,
	// so it is skipped above (it never enters `owned`). Ownership is decided PURELY by
	// the prevout-script match; a counterparty Bip32Derivation is never trusted (and
	// is not even read) to claim an un-valued input is ours. The safe direction is to
	// leave such an input unsigned — a foreign input legitimately has no WitnessUtxo,
	// and a genuinely wallet-owned input always carries one (every daxib-created PSBT
	// attaches it). If NO input is owned, the sign is a clean not_owned refusal.
	if len(owned) == 0 {
		return domain.PSBTResult{}, domain.New(domain.CodePSBTNotOwned,
			"this wallet owns none of the PSBT's inputs (nothing to sign): every input's prevout script is foreign to the wallet's gap window")
	}

	var warnings []string

	// (4) DERIVE NET WALLET OUTFLOW — re-verify each OWNED input's prevout VALUE
	// against the wallet's own UTXO view (never trust the PSBT's self-reported
	// WitnessUtxo.Value; a hostile PSBT could understate it to dodge a cap). Offline
	// (no backend), fall back to the PSBT value with a warning.
	ownedRefs := make([]psbtOwnedInput, len(owned))
	for i, o := range owned {
		ownedRefs[i] = psbtOwnedInput{Outpoint: o.outpoint, Value: o.value}
	}
	verified := s.verifyOwnedValues(ctx, addrs, ownedRefs, &warnings)

	var ownedInputSat int64
	for i := range owned {
		owned[i].value = verified[owned[i].outpoint]
		ownedInputSat += owned[i].value
	}

	// Classify outputs: wallet-owned (change/self) vs external by the same script
	// match. changeBackSat = Σ owned output values; externalOutSat = Σ external.
	var changeBackSat, externalOutSat int64
	var changeAddr string
	type extRecipient struct {
		addr      string
		scriptKey string // lowercase hex of the scriptPubKey (the dedup/identity key)
		sat       int64
	}
	var external []extRecipient
	for _, txout := range pkt.UnsignedTx.TxOut {
		_, isOurs := byScript[psbt.ScriptHexKey(txout.PkScript)]
		if isOurs {
			changeBackSat += txout.Value
			if changeAddr == "" {
				changeAddr = psbt.AddressFromScript(txout.PkScript, params)
			}
			continue
		}
		externalOutSat += txout.Value
		external = append(external, extRecipient{
			addr:      psbt.AddressFromScript(txout.PkScript, params),
			scriptKey: psbt.ScriptHexKey(txout.PkScript),
			sat:       txout.Value,
		})
	}

	// The policy charges EXACTLY this wallet's NET outflow (multisig-safe — a co-
	// signer's contributed value is never charged): netOut = ownedInputSat -
	// changeBackSat, split so AmountSat+FeeSat == netOut. AmountSat is the external
	// spend attributable to the wallet, capped at netOut (when a co-signer funds most
	// of the external value, externalOutSat exceeds the wallet's netOut, so charging
	// the full externalOutSat would over-count the co-signer's contribution); FeeSat
	// is the remainder (the wallet's share of the fee). Both are clamped >= 0.
	netOut := ownedInputSat - changeBackSat
	if netOut < 0 {
		netOut = 0
	}
	chargeAmount := externalOutSat
	if chargeAmount > netOut {
		chargeAmount = netOut
	}
	feeCharge := netOut - chargeAmount
	// The fee-rate cap must be evaluated from the BACKEND-VERIFIED owned-input values,
	// not the PSBT's self-reported WitnessUtxo.Value (a hostile PSBT could understate
	// an owned value to deflate the apparent rate and slip past the anti-fee-burn cap).
	// allOwned reports whether every input is wallet-owned; only then is the whole-tx
	// fee computable from verified values alone.
	allOwned := len(owned) == len(pkt.Inputs)
	feeRate := s.estimatePSBTFeeRate(pkt, ownedInputSat, changeBackSat, externalOutSat, allOwned)

	// (5)+(6) policy: per-distinct-external-recipient deny/allow eng.Check, then ONE
	// aggregate eng.Reserve. Take the send-lock around the whole reserve+sign section
	// so a psbt sign and a concurrent tx send cannot reserve against a stale window.
	unlock, lerr := s.acquireSendLock(ctx, s.net, wallet)
	if lerr != nil {
		return domain.PSBTResult{}, lerr
	}
	defer unlock()

	eng, perr := s.openPolicyEngine(ctx)
	if perr != nil {
		return domain.PSBTResult{}, perr
	}

	// Per-distinct external recipient deny/allow gate (a PSBT is atomic — ANY failing
	// recipient denies the whole sign). policy.Check carries a SINGLE Recipient, so we
	// run eng.Check once per DISTINCT external output before reserving.
	//
	// EVERY external leg is gated, including a NON-STANDARD output whose script does
	// not resolve to a single address (bare multisig, witness-v2, OP_RETURN, …):
	// such a leg is passed to eng.Check with an empty Recipient, which FAILS CLOSED
	// under an active allowlist/include_self (no allowlist/self/change match) — so an
	// un-allowlistable destination can never ride along ungated behind a legit
	// allowlisted external[0]. Dedup is keyed by the scriptPubKey (not the rendered
	// address) so distinct non-standard sinks are each gated.
	seen := map[string]bool{}
	for _, e := range external {
		if seen[e.scriptKey] {
			continue
		}
		seen[e.scriptKey] = true
		// This per-recipient Check is ONLY the destination deny/allow gate (Stages 1-2,
		// which key on Recipient, not amount). The per-tx/day/fee-rate AMOUNT caps are
		// enforced authoritatively once in the aggregate Reserve below over the wallet's
		// TRUE net outflow — so the amounts here are zeroed. (Charging e.sat per leg
		// would over-count a co-signer's contribution and falsely deny a multisig sign
		// the wallet only partly funds.)
		d, cerr := eng.Check(ctx, policy.Check{
			Network:    string(s.net),
			Recipient:  e.addr, // "" for a non-standard script: fails closed under an allowlist
			AmountSat:  0,
			FeeSat:     0,
			FeeRate:    feeRate,
			ChangeAddr: changeAddr,
		})
		if cerr != nil {
			return domain.PSBTResult{}, cerr
		}
		if !d.Allowed {
			e := domain.New(d.Code, d.Reason)
			if d.Data != nil {
				e = domain.WithData(e, d.Data)
			}
			return domain.PSBTResult{}, e
		}
	}

	// ONE aggregate Reserve for the per-tx/day/fee-rate caps (AmountSat+FeeSat ==
	// net outflow). ChangeAddr passes the include_self gate. A denial returns
	// policy.denied.* (exit 3) / fee_rate (exit 7) / seal (exit 8) and NO PartialSig
	// is ever produced.
	aggRecipient := ""
	if len(external) > 0 {
		// A single representative recipient for the aggregate Reserve's Check: the
		// per-recipient deny/allow gate already cleared EACH distinct external address,
		// so the aggregate only sums the per-tx/day/fee-rate caps. For a single-recipient
		// PSBT it IS the recipient.
		aggRecipient = external[0].addr
	}
	resv, rerr := eng.Reserve(ctx, policy.Check{
		Network:    string(s.net),
		Recipient:  aggRecipient,
		AmountSat:  chargeAmount, // capped at netOut: never charges a co-signer's contribution
		FeeSat:     feeCharge,
		FeeRate:    feeRate,
		ChangeAddr: changeAddr,
	})
	if rerr != nil {
		return domain.PSBTResult{}, rerr // BEFORE any signature exists
	}

	// (7) ONLY AFTER Reserve succeeds: build the signing specs for the owned inputs
	// (prevout script + VERIFIED value) and call keys.SignInputs VERBATIM over a COPY
	// of the unsigned tx (we lift the witnesses into PartialSigs; the PSBT carries
	// them, not the mutated MsgTx).
	specs := make([]keys.InputSigningSpec, len(owned))
	for i, o := range owned {
		specs[i] = keys.InputSigningSpec{
			Index: o.idx, Branch: o.branch, AddrIndex: o.addrIndex,
			PrevScript: o.script, PrevValue: o.value,
		}
	}
	signTx := pkt.UnsignedTx.Copy()
	// Seed the BIP-143 sighash fetcher with EVERY input's prevout (incl. FOREIGN
	// co-signer inputs): txscript.NewTxSigHashes iterates all inputs and would
	// nil-panic on a foreign prevout absent from the fetcher. The owned specs carry
	// the VERIFIED values and take precedence over these PSBT-reported ones.
	foreignPrevouts := psbt.AllPrevouts(pkt)
	pass, _, paerr := s.acquire(passphraseSpec(in.PassphraseStdin, in.PassphraseFile, false))
	if paerr != nil {
		_ = resv.Release(context.Background())
		return domain.PSBTResult{}, paerr
	}
	defer pass.Zero()
	if err := s.keys.SignInputsWithPrevouts(ctx, wallet, s.net, pass, signTx, specs, foreignPrevouts); err != nil {
		_ = resv.Release(context.Background())
		return domain.PSBTResult{}, err
	}

	// Lift witness[0]=sig, witness[1]=pubkey from each signed input into a PartialSig.
	for _, o := range owned {
		w := signTx.TxIn[o.idx].Witness
		if len(w) != 2 {
			_ = resv.Release(context.Background())
			return domain.PSBTResult{}, domain.Newf(domain.CodeStateCorrupt,
				"unexpected witness shape (%d items) signing PSBT input %d", len(w), o.idx)
		}
		if err := psbt.AttachPartialSig(pkt, o.idx, w[0], w[1]); err != nil {
			_ = resv.Release(context.Background())
			return domain.PSBTResult{}, err
		}
	}

	b64, err := psbt.Encode(pkt)
	if err != nil {
		_ = resv.Release(context.Background())
		return domain.PSBTResult{}, err
	}

	// (8) Journal a `signed` record (RawTx empty, PSBTBase64 set, JInputs = the
	// consumed owned outpoints, ReservationID cross-linked) and leave the reservation
	// RESERVED. A journal-write failure releases the reservation (no broadcast
	// possible, no commit).
	jInputs := make([]journal.JInput, len(owned))
	for i, o := range owned {
		t, v := splitOutpoint(o.outpoint)
		jInputs[i] = journal.JInput{Txid: t, Vout: v, ValueSat: o.value, Address: o.address}
	}
	rec := s.psbtSignedRecord(wallet, pkt, jInputs, feeCharge, feeRate, b64)
	rec.ReservationID = resv.ID()
	if jerr := s.journal.Append(ctx, rec); jerr != nil {
		_ = resv.Release(context.Background())
		return domain.PSBTResult{}, jerr
	}

	res := s.psbtSummary(pkt, wallet)
	res.PSBT = b64
	res.FeeSat = feeCharge
	res.FeeBTC = domain.SatsToBTC(feeCharge)
	res.FeeRate = feeRate
	res.Warnings = warnings
	return res, nil
}

// PSBTBroadcast finalizes-if-needed + extracts a PSBT then reuses the SendTx
// broadcast tail (send-lock, classified broadcast, commit-the-reservation on
// accept). It is the ONLY PSBT verb dialing the backend + writing the journal;
// --yes gated. Its policy charge already happened at sign — the journal
// ReservationID cross-link (recovered by the unsigned-tx txid) prevents
// double-charging.
func (s *Service) PSBTBroadcast(ctx context.Context, req domain.PSBTBroadcastRequest, sink domain.EventSink) (domain.TxResult, error) {
	if err := s.requireNetwork(); err != nil {
		return domain.TxResult{}, err
	}
	wallet, err := s.resolveWallet(ctx, req.Wallet)
	if err != nil {
		return domain.TxResult{}, err
	}
	if err := s.assertWalletNetwork(ctx, wallet); err != nil {
		return domain.TxResult{}, err
	}
	if !req.Yes {
		isTTY := s.secret.IsTTY != nil && s.secret.IsTTY()
		if !isTTY {
			return domain.TxResult{}, domain.New(domain.CodeUsageConfirmRequired,
				"broadcasting a PSBT moves funds: pass --yes to authorize this non-interactive broadcast")
		}
	}

	pkt, err := psbt.Decode(req.PSBT)
	if err != nil {
		return domain.TxResult{}, err
	}
	// (1) finalize-if-needed then extract; a finalize failure (missing co-signer sigs)
	// is a clean psbt.incomplete usage error.
	if !psbt.IsComplete(pkt) {
		_ = psbt.Finalize(pkt)
	}
	tx, err := psbt.ExtractTx(pkt)
	if err != nil {
		return domain.TxResult{}, err
	}
	var rawBuf bytes.Buffer
	if serr := tx.Serialize(&rawBuf); serr != nil {
		return domain.TxResult{}, domain.Wrap(domain.CodeStateCorrupt, "serializing the extracted tx", serr)
	}
	raw := rawBuf.Bytes()
	txid := tx.TxHash().String()

	client, _, _, err := s.dialActiveBackend(ctx)
	if err != nil {
		return domain.TxResult{}, err
	}
	defer client.Close()

	// (3) take the send-lock around the broadcast critical section.
	unlock, lerr := s.acquireSendLock(ctx, s.net, wallet)
	if lerr != nil {
		return domain.TxResult{}, lerr
	}
	defer unlock()

	// (2) recover the reservation this PSBT's unsigned-tx txid created at sign time.
	eng, perr := s.openPolicyEngine(ctx)
	if perr != nil {
		return domain.TxResult{}, perr
	}
	var resv policy.Reservation
	var rec *journal.Record
	if r, rerr := s.journal.ByTxid(ctx, s.net, txid); rerr == nil && r != nil {
		rec = r
		if r.ReservationID != "" {
			resv = eng.AdoptReservation(r.ReservationID, string(s.net))
		}
	}

	// (4) broadcast (classified).
	outcome, btxid, berr := s.broadcastClassified(ctx, client, raw, sink)
	switch outcome {
	case outcomeAccepted:
		t := btxid
		if t == "" {
			t = txid
		}
		if rec != nil {
			tt := t
			_ = s.journal.SetState(ctx, s.net, rec.ID, journal.StateMutation{Status: journal.StatusBroadcast, Txid: &tt})
		}
		_ = resv.Commit(context.Background(), t)
		emit(sink, "broadcast", "accepted "+t)
		res := s.psbtBroadcastResult(wallet, tx, t, raw)
		if rec != nil {
			res.JournalID = rec.ID
		}
		return res, nil
	case outcomeTransportExhausted:
		res := s.psbtBroadcastResult(wallet, tx, txid, raw)
		res.Status = domain.TxStateSigned
		res.Resume = "daxib psbt broadcast (retry)"
		if rec != nil {
			res.JournalID = rec.ID
		}
		return res, domain.WithData(
			domain.Wrap(domain.CodeBackendUnreachable,
				"broadcast transport exhausted; re-run psbt broadcast to retry", berr),
			map[string]any{"txid": txid})
	default: // outcomeRejected
		if rec != nil {
			reason := rejectReason(berr)
			_ = s.journal.SetState(ctx, s.net, rec.ID, journal.StateMutation{Status: journal.StatusFailed, Error: &reason})
		}
		_ = resv.Release(context.Background())
		return domain.TxResult{}, mapRejectErr(berr)
	}
}
