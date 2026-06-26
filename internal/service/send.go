package service

import (
	"bytes"
	"context"
	"encoding/hex"
	"sort"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"github.com/daxchain-io/daxib/internal/coinselect"
	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/keys"
	"github.com/daxchain-io/daxib/internal/secret"
)

// rbfSequence is the nSequence daxib sets on EVERY input: 0xfffffffd signals
// opt-in RBF (BIP-125) and is < 0xffffffff so a future `tx speedup` (M5) can bump
// the fee. The tx version is 2.
const rbfSequence = 0xfffffffd

// coinDustThreshold mirrors coinselect's P2WPKH dust limit so the early send-input
// validation rejects a sub-dust recipient amount before any backend dial.
const coinDustThreshold = coinselect.DustThresholdP2WPKH

// sendArtifact is the fully built + signed transaction plus everything the journal
// + result need. It is produced under NO lock (build is pure given the gathered
// UTXOs); the caller takes the send-lock around the journal+broadcast steps.
type sendArtifact struct {
	rawTx      []byte
	txid       string
	feeSat     int64
	feeRate    int64
	vsize      int64
	inputs     []coinselect.Coin // selected coins (with derivation coords + value)
	inAddr     map[string]string // outpoint -> address (for the journal)
	recipient  string
	recipSat   int64
	changeSat  int64
	changeAddr string // wallet-owned change address ("" when folded to fee)
}

// chainParams maps the active network to its btcd params (the send pipeline needs
// them for address decode + script build; keys owns the same map internally).
func (s *Service) chainParams() *chaincfg.Params {
	switch s.net {
	case domain.NetworkMainnet:
		return &chaincfg.MainNetParams
	case domain.NetworkTestnet:
		return &chaincfg.TestNet3Params
	case domain.NetworkSignet:
		return &chaincfg.SigNetParams
	case domain.NetworkRegtest:
		return &chaincfg.RegressionNetParams
	default:
		return &chaincfg.MainNetParams
	}
}

// buildAndSign gathers spendable UTXOs, runs coin selection, builds the recipient
// + change outputs, signs every input (BIP-143 P2WPKH) through the keystore, and
// returns the artifact. It does NO journaling or broadcast — the caller owns the
// lifecycle.
//
// For a REAL send the caller MUST hold the wallet send-lock and pass the set of
// outpoints already consumed by in-flight (non-terminal) journal records in
// `consumed`, so they are excluded from selection (no double-spend / double-select
// of a stranded send's inputs). The change output is allocated via DeriveNext (a
// NEW wallet-owned change address recorded in meta + watermark advanced) ONLY for a
// real send.
//
// For a DRY-RUN (dryRun=true) the change address is PEEKED (no watermark advance,
// no meta mutation) so a no-op preview has no durable side effect; the lock and the
// consumed set are not required (the caller passes nil).
//
// confirmedOnly is implicit: only confirmed UTXOs are selected (the default
// policy); the unconfirmed split mirrors balance.go's Confirmations>0.
func (s *Service) buildAndSign(ctx context.Context, wallet string, client interface {
	UTXOs(ctx context.Context, addrs []string) ([]domain.UTXO, error)
}, req domain.SendRequest, feeRate int64, dryRun bool, consumed map[string]bool) (sendArtifact, error) {
	params := s.chainParams()

	// 1. Parse + validate the amount and the destination address.
	amountSat, err := domain.ParseAmountToSats(req.Amount)
	if err != nil {
		return sendArtifact{}, err
	}
	if amountSat <= 0 {
		return sendArtifact{}, domain.Newf(domain.CodeUsageBadAmount, "send amount must be positive, got %q", req.Amount)
	}
	toAddr, err := btcutil.DecodeAddress(req.To, params)
	if err != nil || !toAddr.IsForNet(params) {
		return sendArtifact{}, domain.Newf(domain.CodeUsageBadAddress,
			"--to %q is not a valid %s address", req.To, s.net)
	}
	recipientScript, err := txscript.PayToAddrScript(toAddr)
	if err != nil {
		return sendArtifact{}, domain.Newf(domain.CodeUsageBadAddress, "--to %q cannot be paid to: %v", req.To, err)
	}

	// 2. Derive the wallet's gap-window address set and index it by address so a
	// selected UTXO maps to its (branch, index) for signing.
	_, scan, err := s.keys.ScanAddresses(ctx, wallet, gapWindow)
	if err != nil {
		return sendArtifact{}, err
	}
	type coords struct {
		branch domain.Branch
		index  uint32
	}
	byAddr := make(map[string]coords, len(scan))
	addrs := make([]string, len(scan))
	for i, a := range scan {
		addrs[i] = a.Address
		byAddr[a.Address] = coords{branch: a.Branch, index: a.Index}
	}

	// 3. Gather UTXOs; keep only CONFIRMED ones for selection (the default policy).
	utxos, err := client.UTXOs(ctx, addrs)
	if err != nil {
		return sendArtifact{}, err
	}
	var confirmedTotal, unconfirmedTotal int64
	candidates := make([]coinselect.Coin, 0, len(utxos))
	utxoByOutpoint := make(map[string]domain.UTXO, len(utxos))
	for _, u := range utxos {
		if u.Confirmations <= 0 {
			unconfirmedTotal += u.ValueSat
			continue
		}
		confirmedTotal += u.ValueSat
		c, ok := byAddr[u.Address]
		if !ok {
			// A UTXO on an address outside the gap window — skip (we cannot sign it).
			continue
		}
		op := u.Txid + ":" + domain.IndexString(u.Vout)
		if consumed[op] {
			// Already consumed by an in-flight (signed/broadcast) journal record for
			// this wallet — reserved until that record is terminal (confirmed/failed).
			// Excluding it here (under the send-lock) prevents re-selecting a stranded
			// send's inputs and double-broadcasting a conflicting tx.
			continue
		}
		candidates = append(candidates, coinselect.Coin{
			Outpoint: op,
			Branch:   c.branch,
			Index:    c.index,
			ValueSat: u.ValueSat,
		})
		utxoByOutpoint[op] = u
	}

	// 4. Coin selection. Thread the recipient output's REAL serialized vsize (from
	// its scriptPubKey) so the fee/selection math never assumes P2WPKH for a
	// Taproot/P2WSH/P2PKH/P2SH recipient (which would underpay relay). The change
	// output is always P2WPKH (handled inside Select).
	recipientVB := coinselect.OutputVBytes(len(recipientScript))
	sel, err := coinselect.Select(candidates, coinselect.Params{
		Target: amountSat, FeeRateSatVB: feeRate, RecipientVBytes: recipientVB,
	})
	if err != nil {
		// If only UNCONFIRMED funds would have covered it, surface the
		// confirmed-specific code so the agent knows to wait, not give up.
		if isInsufficient(err) && confirmedTotal+unconfirmedTotal >= amountSat && unconfirmedTotal > 0 {
			return sendArtifact{}, domain.WithData(
				domain.Newf("funds.insufficient_confirmed",
					"insufficient CONFIRMED funds: %d sat confirmed, %d sat unconfirmed (excluded); wait for confirmations or lower the amount",
					confirmedTotal, unconfirmedTotal),
				map[string]any{"confirmed_sat": confirmedTotal, "unconfirmed_sat": unconfirmedTotal, "target_sat": amountSat})
		}
		return sendArtifact{}, err
	}

	// 5. Allocate a change address (a wallet-owned internal/change address) only when
	// a change output will be emitted. A REAL send DeriveNext's it (records it in
	// meta + advances the watermark) — committed only because we are under the
	// send-lock about to journal+broadcast. A DRY-RUN PEEKs it (read-only, no
	// watermark advance) so a no-op preview never burns a change index.
	var changeAddr string
	var changeScript []byte
	if sel.HasChange {
		var da keys.DerivedAddress
		var derr error
		if dryRun {
			da, derr = s.keys.PeekNext(ctx, wallet, domain.BranchChange)
		} else {
			da, derr = s.keys.DeriveNext(ctx, wallet, domain.BranchChange)
		}
		if derr != nil {
			return sendArtifact{}, derr
		}
		changeAddr = da.Address
		ca, cerr := btcutil.DecodeAddress(changeAddr, params)
		if cerr != nil {
			return sendArtifact{}, domain.Wrap(domain.CodeStateCorrupt, "decoding change address", cerr)
		}
		changeScript, cerr = txscript.PayToAddrScript(ca)
		if cerr != nil {
			return sendArtifact{}, domain.Wrap(domain.CodeStateCorrupt, "building change script", cerr)
		}
	}

	// 6. Build the unsigned tx (version 2, RBF sequence on every input).
	tx := wire.NewMsgTx(2)
	specs := make([]keys.InputSigningSpec, 0, len(sel.Inputs))
	inAddr := make(map[string]string, len(sel.Inputs))
	for i, c := range sel.Inputs {
		u := utxoByOutpoint[c.Outpoint]
		h, herr := chainhash.NewHashFromStr(u.Txid)
		if herr != nil {
			return sendArtifact{}, domain.Wrap(domain.CodeStateCorrupt, "parsing input txid", herr)
		}
		txin := wire.NewTxIn(wire.NewOutPoint(h, u.Vout), nil, nil)
		txin.Sequence = rbfSequence
		tx.AddTxIn(txin)

		prevScript, perr := scriptForAddress(u.Address, params)
		if perr != nil {
			return sendArtifact{}, perr
		}
		specs = append(specs, keys.InputSigningSpec{
			Index:      i,
			Branch:     c.Branch,
			AddrIndex:  c.Index,
			PrevScript: prevScript,
			PrevValue:  c.ValueSat,
		})
		inAddr[c.Outpoint] = u.Address
	}
	// Recipient output, then change (if any). BIP-69 sorting is optional; we keep a
	// stable order (recipient first) and the change output identifiable by address.
	tx.AddTxOut(wire.NewTxOut(amountSat, recipientScript))
	if sel.HasChange {
		tx.AddTxOut(wire.NewTxOut(sel.ChangeSat, changeScript))
	}

	// 7. Sign every input through the keystore (acquires the passphrase via the
	// §3.6 resolver). The seed/keys never leave the keys package.
	pass, _, perr := s.acquireSendPassphrase()
	if perr != nil {
		return sendArtifact{}, perr
	}
	defer pass.Zero()
	if err := s.keys.SignInputs(ctx, wallet, pass, tx, specs); err != nil {
		return sendArtifact{}, err
	}

	// 8. Serialize + txid.
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return sendArtifact{}, domain.Wrap(domain.CodeStateCorrupt, "serializing signed tx", err)
	}
	raw := buf.Bytes()
	txid := tx.TxHash().String()

	// 8b. Relay-safety guard: the attached fee (sel.FeeSat) was computed from the
	// ESTIMATED vsize (sel.VSizeVB). Assert the ACTUAL signed vsize does not exceed
	// the estimate, so the effective feerate (feeSat/actualVsize) can never fall
	// below the requested rate / the relay floor. The estimator models a worst-case
	// 72-byte signature per input and the recipient output's real script size, so a
	// real tx is at most the estimate (occasionally 1 vB shorter per input). A
	// failure here means a vsize constant drifted; fail BEFORE broadcast rather than
	// underpay the network.
	if actual := actualSignedVSize(tx); actual > sel.VSizeVB {
		return sendArtifact{}, domain.Newf(domain.CodeStateCorrupt,
			"internal vsize estimate %d vB underpays the actual signed vsize %d vB; refusing to broadcast an underpaid tx",
			sel.VSizeVB, actual)
	}

	art := sendArtifact{
		rawTx:      raw,
		txid:       txid,
		feeSat:     sel.FeeSat,
		feeRate:    feeRate,
		vsize:      sel.VSizeVB,
		inputs:     sel.Inputs,
		inAddr:     inAddr,
		recipient:  req.To,
		recipSat:   amountSat,
		changeSat:  sel.ChangeSat,
		changeAddr: changeAddr,
	}
	return art, nil
}

// validateSendInputs parses + validates the --amount and --to fields against the
// active network WITHOUT touching a backend, so a malformed input is a clean
// usage error (exit 2) before any dial. It is a fast pre-check; buildAndSign
// re-parses the same values exactly.
func (s *Service) validateSendInputs(req domain.SendRequest) error {
	amountSat, err := domain.ParseAmountToSats(req.Amount)
	if err != nil {
		return err
	}
	if amountSat <= 0 {
		return domain.Newf(domain.CodeUsageBadAmount, "send amount must be positive, got %q", req.Amount)
	}
	if amountSat < coinDustThreshold {
		return domain.Newf(domain.CodeUsageDustOutput,
			"amount %d sat is below the dust threshold; the recipient output would be unspendable", amountSat)
	}
	params := s.chainParams()
	toAddr, derr := btcutil.DecodeAddress(req.To, params)
	if derr != nil || !toAddr.IsForNet(params) {
		return domain.Newf(domain.CodeUsageBadAddress, "--to %q is not a valid %s address", req.To, s.net)
	}
	// Validate the fee inputs HERE, before any backend dial, so a malformed
	// --fee-rate / --speed is a clean usage error (exit 2) rather than surfacing as a
	// backend.not_configured (exit 10) / backend.unreachable (exit 6) after the dial.
	if req.FeeRate != "" {
		if _, ferr := parseFeeRate(req.FeeRate); ferr != nil {
			return ferr
		}
	} else if err := validateSpeed(req.Speed); err != nil {
		return err
	}
	return nil
}

// validateSpeed checks an explicit --speed value (empty = the default tier). An
// unknown value is usage.speed (exit 2). It is the pre-dial gate mirrored by
// resolveFeeRate's switch so a malformed --speed fails fast and consistently.
func validateSpeed(speed string) error {
	switch speed {
	case "", "slow", "normal", "fast":
		return nil
	default:
		return domain.Newf(domain.CodeUsage+".speed",
			"unknown --speed %q: want one of slow, normal, fast", speed)
	}
}

// actualSignedVSize returns the network's vsize of a fully-signed tx:
// ceil(weight/4) where weight = base*3 + total (BIP-141). It reads the wire
// serialized sizes directly (no btcd blockchain/mempool import — those drag the
// validation tree in and threaten the offline build), so it is safe in production.
func actualSignedVSize(tx *wire.MsgTx) int64 {
	base := tx.SerializeSizeStripped()
	total := tx.SerializeSize()
	weight := int64(base*3 + total)
	return (weight + 3) / 4
}

// scriptForAddress decodes a bech32 address and returns its scriptPubKey.
func scriptForAddress(addr string, params *chaincfg.Params) ([]byte, error) {
	a, err := btcutil.DecodeAddress(addr, params)
	if err != nil {
		return nil, domain.Wrap(domain.CodeStateCorrupt, "decoding wallet address", err)
	}
	script, err := txscript.PayToAddrScript(a)
	if err != nil {
		return nil, domain.Wrap(domain.CodeStateCorrupt, "building input script", err)
	}
	return script, nil
}

// isInsufficient reports whether err is a funds.insufficient domain error.
func isInsufficient(err error) bool {
	de := domain.AsError(err)
	return de != nil && de.Code == domain.CodeFundsInsufficient
}

// hexRaw renders raw signed bytes as lowercase hex (no 0x prefix, Bitcoin
// convention) for the journal RawTx field and the result RawTxHex.
func hexRaw(raw []byte) string { return hex.EncodeToString(raw) }

// sortedInputRefs projects the artifact's inputs to domain.TxInputRef rows in a
// deterministic order for the result/journal.
func (a sendArtifact) sortedInputRefs() []domain.TxInputRef {
	refs := make([]domain.TxInputRef, 0, len(a.inputs))
	for _, c := range a.inputs {
		refs = append(refs, domain.TxInputRef{
			Outpoint: c.Outpoint,
			Address:  a.inAddr[c.Outpoint],
			ValueSat: c.ValueSat,
		})
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].Outpoint < refs[j].Outpoint })
	return refs
}

// acquireSendPassphrase resolves the keystore passphrase for a signing op through
// the §3.6 precedence (no send-specific flags; DAXIB_PASSPHRASE[_FILE] / TTY). It
// mirrors daxie's service-side passphrase acquisition for a send.
func (s *Service) acquireSendPassphrase() (*secret.Bytes, secret.Source, error) {
	return s.acquire(passphraseSpec(false, "", false))
}
