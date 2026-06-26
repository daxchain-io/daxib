package service

import (
	"encoding/hex"

	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/journal"
)

// tx_result.go holds the journal-record + TxResult builders shared by the send
// and wait/status paths, plus the tiny progress-emit and hex helpers.

// emit sends a progress event to the sink, guarding nil (a non-streaming command
// passes nil).
func emit(sink domain.EventSink, stage, msg string) {
	if sink != nil {
		sink(domain.Event{Stage: stage, Message: msg})
	}
}

// decodeHex decodes a journal RawTx hex string (no 0x prefix) to bytes.
func decodeHex(s string) ([]byte, error) { return hex.DecodeString(s) }

// itoa64 is a tiny int64->decimal for progress messages (avoids an int64→uint32
// narrowing for a confirmation count and keeps the service strconv-light).
func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// journalRecord builds the `signed` journal record for an artifact (written
// BEFORE broadcast). It records the consumed outpoints (the double-spend-avoidance
// record), the outputs, and the recipient/change attribution.
func (s *Service) journalRecord(wallet string, art sendArtifact, feeRate int64) *journal.Record {
	inputs := make([]journal.JInput, 0, len(art.inputs))
	for _, c := range art.inputs {
		u := art.inAddr[c.Outpoint]
		txid, vout := splitOutpoint(c.Outpoint)
		inputs = append(inputs, journal.JInput{
			Txid:     txid,
			Vout:     vout,
			ValueSat: c.ValueSat,
			Address:  u,
		})
	}
	outputs := []journal.JOutput{{Address: art.recipient, ValueSat: art.recipSat}}
	if art.changeAddr != "" {
		outputs = append(outputs, journal.JOutput{Address: art.changeAddr, ValueSat: art.changeSat, Change: true})
	}
	return &journal.Record{
		Network:       string(s.net),
		Wallet:        wallet,
		Status:        journal.StatusSigned,
		Source:        "cli",
		Txid:          art.txid, // also computable from RawTx; set early for ByTxid lookups
		RawTx:         hexRaw(art.rawTx),
		FeeRate:       feeRate,
		FeeSat:        art.feeSat,
		Vsize:         art.vsize,
		Inputs:        inputs,
		Outputs:       outputs,
		RecipientAddr: art.recipient,
		RecipientSat:  art.recipSat,
		ChangeAddr:    art.changeAddr,
	}
}

// baseResult builds the common TxResult fields from an artifact.
func (s *Service) baseResult(wallet string, art sendArtifact, journalID string) domain.TxResult {
	outs := []domain.TxOutputRef{{Address: art.recipient, ValueSat: art.recipSat}}
	if art.changeAddr != "" {
		outs = append(outs, domain.TxOutputRef{Address: art.changeAddr, ValueSat: art.changeSat, Change: true})
	}
	res := domain.TxResult{
		Txid:          art.txid,
		Network:       s.net,
		Wallet:        wallet,
		To:            art.recipient,
		AmountSat:     art.recipSat,
		AmountBTC:     domain.SatsToBTC(art.recipSat),
		FeeSat:        art.feeSat,
		FeeBTC:        domain.SatsToBTC(art.feeSat),
		FeeRate:       art.feeRate,
		Vsize:         art.vsize,
		ChangeSat:     art.changeSat,
		ChangeAddress: art.changeAddr,
		Inputs:        art.sortedInputRefs(),
		Outputs:       outs,
		JournalID:     journalID,
		RawTxHex:      hexRaw(art.rawTx),
	}
	if art.changeSat > 0 {
		res.ChangeBTC = domain.SatsToBTC(art.changeSat)
	}
	return res
}

// previewResult is the --dry-run result: built+estimated, NOT broadcast (Txid is
// cleared so the renderer prints the dry-run banner, DryRun=true).
func (s *Service) previewResult(wallet string, art sendArtifact) domain.TxResult {
	res := s.baseResult(wallet, art, "")
	res.Txid = ""
	res.Status = domain.TxStatePending
	res.DryRun = true
	return res
}

// signedResult is the transport-exhausted result: the bytes are journaled
// `signed`; the agent can resume with `tx wait <txid>`.
func (s *Service) signedResult(wallet string, art sendArtifact, journalID string) domain.TxResult {
	res := s.baseResult(wallet, art, journalID)
	res.Status = domain.TxStateSigned
	res.Resume = "daxib tx wait " + art.txid
	return res
}

// broadcastResult is the accepted (no --wait) result.
func (s *Service) broadcastResult(wallet string, art sendArtifact, journalID, txid string) domain.TxResult {
	res := s.baseResult(wallet, art, journalID)
	if txid != "" {
		res.Txid = txid
	}
	res.Status = domain.TxStateBroadcast
	return res
}

// splitOutpoint splits "txid:vout" into its parts.
func splitOutpoint(op string) (string, uint32) {
	for i := len(op) - 1; i >= 0; i-- {
		if op[i] == ':' {
			return op[:i], parseUint32(op[i+1:])
		}
	}
	return op, 0
}

// parseUint32 parses a decimal uint32 (no strconv on the hot path; defensive).
func parseUint32(s string) uint32 {
	var n uint32
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + uint32(c-'0')
	}
	return n
}
