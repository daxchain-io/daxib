package service

import (
	"context"

	btcpsbt "github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"

	"github.com/daxchain-io/daxib/internal/coinselect"
	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/journal"
	"github.com/daxchain-io/daxib/internal/psbt"
)

// psbt_helpers.go holds the PSBT service-method helpers: the passphrase-channel
// input struct, the owned-value re-verification against the backend, the fee-rate
// estimate, the inspection summary (with ownership annotation), the `signed`
// journal record builder, and the broadcast TxResult builder.

// PSBTSignInput carries the keystore passphrase channels for `psbt sign` (the
// message-style input that does NOT travel as a request field — a secret). It
// mirrors MessageSignInput.
type PSBTSignInput struct {
	PassphraseStdin bool
	PassphraseFile  string
}

// ownedInputRef is the minimal per-owned-input data the helpers need (a structural
// echo of PSBTSign's local ownedInput, exported within the package via the methods
// below taking the concrete fields).

// verifyOwnedValues re-verifies each owned input's prevout VALUE against the
// wallet's own UTXO view (backend.UTXOs over the wallet's addresses), never
// trusting the PSBT's self-reported WitnessUtxo.Value (a hostile PSBT could
// understate it to dodge a cap). It returns outpoint -> verified value. When the
// backend is unreachable (offline air-gapped sign), it falls back to the PSBT value
// with a loud warning (reduced assurance). A foreign input's value is never checked
// here (it never counts toward this wallet's charge).
func (s *Service) verifyOwnedValues(ctx context.Context, walletAddrs []string, owned []psbtOwnedInput, warnings *[]string) map[string]int64 {
	out := make(map[string]int64, len(owned))
	for _, o := range owned {
		out[o.Outpoint] = o.Value // default to the PSBT-reported value
	}
	client, _, _, derr := s.dialActiveBackend(ctx)
	if derr != nil {
		*warnings = append(*warnings,
			"OFFLINE: could not reach a backend to re-verify owned input values; trusting the PSBT's self-reported amounts (reduced assurance — a hostile PSBT could understate a value to dodge a spend cap)")
		return out
	}
	defer client.Close()
	utxos, uerr := client.UTXOs(ctx, walletAddrs)
	if uerr != nil {
		*warnings = append(*warnings,
			"could not fetch the wallet's UTXOs to re-verify owned input values; trusting the PSBT's self-reported amounts (reduced assurance)")
		return out
	}
	live := make(map[string]int64, len(utxos))
	for _, u := range utxos {
		live[u.Txid+":"+domain.IndexString(u.Vout)] = u.ValueSat
	}
	for _, o := range owned {
		if v, ok := live[o.Outpoint]; ok {
			out[o.Outpoint] = v // the AUTHORITATIVE on-chain value
		} else {
			// An owned input not in the live UTXO set: already spent, or a chain-tip lag.
			// Keep the PSBT value but warn — the policy charge derives from it.
			*warnings = append(*warnings,
				"owned input "+o.Outpoint+" was not found in the wallet's current UTXO set; using the PSBT-reported value (the coin may already be spent)")
		}
	}
	return out
}

// psbtOwnedInput is the helper-facing view of one owned input (the PSBTSign-local
// ownedInput projected to the fields the helpers consume).
type psbtOwnedInput struct {
	Outpoint string
	Value    int64
}

// estimatePSBTFeeRate computes the fee rate (sat/vB) for the policy Check from the
// PSBT's net wallet outflow and an estimated SIGNED vsize (the coinselect P2WPKH
// model: every input is a 68-vB P2WPKH input, plus each output's real serialized
// size). This is the SAME pre-sign estimate the send path uses (a PSBT may carry
// foreign inputs, so the estimate uses the tx's total input/output counts — an
// over-estimate of vsize only LOWERS the rate, the safe direction for the cap). The
// fee charged to the cap is the WALLET's net outflow, but the fee-RATE the cap
// compares is the whole tx's rate (the anti-fee-burn cap is about the on-chain
// rate, identical for every co-signer).
func (s *Service) estimatePSBTFeeRate(pkt *btcpsbt.Packet, ownedInputSat, changeBackSat, externalOutSat int64, allOwned bool) int64 {
	// Whole-tx fee = Σ all input values - Σ all output values. When EVERY input is
	// wallet-owned we compute the fee from the BACKEND-VERIFIED owned-input sum (never
	// the PSBT's self-reported WitnessUtxo.Value, which a hostile PSBT could understate
	// to deflate the apparent fee-rate and slip past the anti-fee-burn cap): the
	// verified whole-tx fee is ownedInputSat - (changeBackSat + externalOutSat).
	vsize := estimatePSBTVSize(pkt)
	if vsize <= 0 {
		return 0
	}
	if allOwned {
		fee := ownedInputSat - changeBackSat - externalOutSat
		if fee < 0 {
			fee = 0
		}
		return fee / vsize
	}
	// A partially-owned (multisig) PSBT carries foreign inputs we cannot independently
	// value; trust the leaf's GetTxFee (an understated FOREIGN value only LOWERS the
	// apparent rate — the safe direction — and never reduces THIS wallet's charge).
	// If GetTxFee is uncomputable, fall back to the wallet's net outflow over the
	// estimated vsize (a conservative lower bound on the rate).
	if fee, ferr := pkt.GetTxFee(); ferr == nil && int64(fee) >= 0 {
		return int64(fee) / vsize
	}
	netOut := ownedInputSat - changeBackSat
	if netOut < 0 {
		netOut = 0
	}
	return netOut / vsize
}

// estimatePSBTVSize estimates the SIGNED vsize of the PSBT's tx using the coinselect
// model (every input a 68-vB P2WPKH input; each output its real serialized size).
func estimatePSBTVSize(pkt *btcpsbt.Packet) int64 {
	numInputs := len(pkt.UnsignedTx.TxIn)
	var recipientVB int64
	extraOuts := 0
	for i, txout := range pkt.UnsignedTx.TxOut {
		if i == 0 {
			recipientVB = coinselect.OutputVBytes(len(txout.PkScript))
		} else {
			extraOuts++
		}
	}
	return coinselect.EstimateVSizeOut(numInputs, recipientVB, extraOuts)
}

// psbtSummary decodes the PSBT into a domain.PSBTResult inspection view, annotating
// which inputs/outputs are wallet-owned (Mine) and which output is the wallet-owned
// change (Change), by matching prevout/output scripts against the wallet's gap-
// window scripts. signed_by_us counts inputs daxib has attached a PartialSig to.
func (s *Service) psbtSummary(pkt *btcpsbt.Packet, wallet string) domain.PSBTResult {
	params := s.chainParams()
	view := psbt.Summarize(pkt, params)

	// Build the wallet's byScript ownership set (best-effort; a missing wallet just
	// means nothing is annotated Mine).
	byScript := s.walletScripts(context.Background(), wallet)

	res := domain.PSBTResult{
		Network:  s.net,
		Complete: psbt.IsComplete(pkt),
		Vsize:    estimatePSBTVSize(pkt),
		Inputs:   make([]domain.PSBTInputView, len(view.Inputs)),
		Outputs:  make([]domain.PSBTOutputView, len(view.Outputs)),
	}
	if view.HasFee {
		res.FeeSat = view.FeeSat
		res.FeeBTC = domain.SatsToBTC(view.FeeSat)
		if v := res.Vsize; v > 0 {
			res.FeeRate = view.FeeSat / v
		}
	}
	signedByUs := 0
	for i, iv := range view.Inputs {
		mine := iv.Script != nil && byScript[psbt.ScriptHexKey(iv.Script)]
		res.Inputs[i] = domain.PSBTInputView{
			Outpoint: iv.Outpoint, Address: iv.Address, ValueSat: iv.ValueSat,
			Mine: mine, Signed: iv.Signed,
		}
		if mine && iv.Signed {
			signedByUs++
		}
	}
	res.SignedByUs = signedByUs
	changeSeen := false
	for i, ov := range view.Outputs {
		mine := byScript[psbt.ScriptHexKey(ov.Script)]
		change := false
		if mine && !changeSeen {
			// The first wallet-owned output is the change/self output (recipient is first,
			// then change, per the build order).
			change = i != 0
			if change {
				changeSeen = true
			}
		}
		res.Outputs[i] = domain.PSBTOutputView{
			Address: ov.Address, ValueSat: ov.ValueSat, Mine: mine, Change: change,
		}
	}
	return res
}

// walletScripts returns the wallet's gap-window scriptPubKeys keyed by lowercase
// hex (the ownership-annotation set). Best-effort: a resolution/derivation fault
// returns an empty set (nothing annotated Mine).
func (s *Service) walletScripts(ctx context.Context, wallet string) map[string]bool {
	out := map[string]bool{}
	if wallet == "" {
		return out
	}
	_, scan, err := s.keys.ScanAddresses(ctx, wallet, s.net, gapWindow)
	if err != nil {
		return out
	}
	params := s.chainParams()
	for _, a := range scan {
		sc, serr := scriptForAddress(a.Address, params)
		if serr != nil {
			continue
		}
		out[psbt.ScriptHexKey(sc)] = true
	}
	return out
}

// psbtSignedRecord builds the `signed` journal record `psbt sign` writes: RawTx
// empty (the PSBT may still need a co-signer), PSBTBase64 set, JInputs = the
// consumed owned outpoints (so coin-selection won't double-spend them), and the
// recipient/fee attribution. ReservationID is set by the caller.
func (s *Service) psbtSignedRecord(p domain.Principal, wallet string, pkt *btcpsbt.Packet, inputs []journal.JInput, feeSat, feeRate int64, b64 string) *journal.Record {
	outputs := make([]journal.JOutput, 0, len(pkt.UnsignedTx.TxOut))
	params := s.chainParams()
	byScript := s.walletScripts(context.Background(), wallet)
	for i, txout := range pkt.UnsignedTx.TxOut {
		addr := psbt.AddressFromScript(txout.PkScript, params)
		change := byScript[psbt.ScriptHexKey(txout.PkScript)] && i != 0
		outputs = append(outputs, journal.JOutput{Address: addr, ValueSat: txout.Value, Change: change})
	}
	return &journal.Record{
		Network:    string(s.net),
		Wallet:     wallet,
		Status:     journal.StatusSigned,
		Source:     sourceOf(p),
		Txid:       pkt.UnsignedTx.TxHash().String(),
		RawTx:      "", // a partial PSBT carries no broadcastable bytes yet
		FeeRate:    feeRate,
		FeeSat:     feeSat,
		Vsize:      estimatePSBTVSize(pkt),
		Inputs:     inputs,
		Outputs:    outputs,
		PSBTBase64: b64,
	}
}

// psbtBroadcastResult builds the accepted-broadcast TxResult for `psbt broadcast`
// (byte-shape-identical to a send result so the renderer is shared).
func (s *Service) psbtBroadcastResult(wallet string, tx *wire.MsgTx, txid string, raw []byte) domain.TxResult {
	return domain.TxResult{
		Txid:     txid,
		Network:  s.net,
		Wallet:   wallet,
		Status:   domain.TxStateBroadcast,
		Vsize:    actualSignedVSize(tx),
		RawTxHex: hexRaw(raw),
	}
}
