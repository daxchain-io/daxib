package psbt

import (
	"bytes"

	"github.com/btcsuite/btcd/btcutil/psbt"

	"github.com/daxchain-io/daxib/internal/domain"
)

// combine.go hand-writes the PSBT combine operation: btcutil/psbt ships no Combine
// method, so daxib unions N PSBTs that share an IDENTICAL unsigned tx, merging each
// input's PartialSigs / Bip32Derivation / WitnessUtxo (and each output's
// Bip32Derivation). It is pure: no keystore, policy, or backend.
//
// The strict same-unsigned-tx guard (txid equality across every part) is a
// safety-critical precondition — combining PartialSigs that belong to DIFFERENT
// unsigned transactions would produce a meaningless, unfinalizable PSBT, so a
// mismatch is psbt.combine_mismatch (exit 2).

// Combine merges parts (>= 1) into a single PSBT. All parts MUST share the same
// unsigned tx (by txid); the merged result carries the union of every part's
// per-input PartialSigs/Bip32Derivation/WitnessUtxo and per-output Bip32Derivation.
// The first part is the base (CLONED via re-decode) onto which the rest are merged,
// so Combine is PURE: it never mutates any caller-supplied *psbt.Packet.
func Combine(parts []*psbt.Packet) (*psbt.Packet, error) {
	if len(parts) == 0 {
		return nil, domain.New(domain.CodePSBTRequired, "combine needs at least one PSBT")
	}
	base, err := clonePacket(parts[0])
	if err != nil {
		return nil, err
	}
	baseTxid := base.UnsignedTx.TxHash()
	for _, p := range parts[1:] {
		if p.UnsignedTx.TxHash() != baseTxid {
			return nil, domain.Newf(domain.CodePSBTCombineMismatch,
				"refusing to combine PSBTs with different unsigned transactions: %s != %s",
				baseTxid.String(), p.UnsignedTx.TxHash().String())
		}
		if len(p.Inputs) != len(base.Inputs) || len(p.Outputs) != len(base.Outputs) {
			// Same txid but a different input/output count is a structurally corrupt part.
			return nil, domain.New(domain.CodePSBTCombineMismatch,
				"refusing to combine PSBTs with mismatched input/output counts")
		}
		for i := range base.Inputs {
			mergeInput(&base.Inputs[i], &p.Inputs[i])
		}
		for i := range base.Outputs {
			mergeOutput(&base.Outputs[i], &p.Outputs[i])
		}
	}
	return base, nil
}

// clonePacket deep-copies a *psbt.Packet by serializing and re-decoding it, so
// Combine can merge into the clone without ever mutating the caller's first part.
func clonePacket(p *psbt.Packet) (*psbt.Packet, error) {
	var buf bytes.Buffer
	if err := p.Serialize(&buf); err != nil {
		return nil, domain.Wrap(domain.CodeStateCorrupt, "cloning the base PSBT", err)
	}
	clone, err := psbt.NewFromRawBytes(&buf, false)
	if err != nil {
		return nil, domain.Wrap(domain.CodeStateCorrupt, "re-decoding the base PSBT", err)
	}
	return clone, nil
}

// mergeInput unions src's PartialSigs/Bip32Derivation/WitnessUtxo into dst.
func mergeInput(dst, src *psbt.PInput) {
	if dst.WitnessUtxo == nil && src.WitnessUtxo != nil {
		dst.WitnessUtxo = src.WitnessUtxo
	}
	if dst.NonWitnessUtxo == nil && src.NonWitnessUtxo != nil {
		dst.NonWitnessUtxo = src.NonWitnessUtxo
	}
	for _, ps := range src.PartialSigs {
		if !hasPartialSig(dst.PartialSigs, ps.PubKey) {
			dst.PartialSigs = append(dst.PartialSigs, ps)
		}
	}
	for _, d := range src.Bip32Derivation {
		if !hasBip32(dst.Bip32Derivation, d.PubKey) {
			dst.Bip32Derivation = append(dst.Bip32Derivation, d)
		}
	}
	if dst.SighashType == 0 && src.SighashType != 0 {
		dst.SighashType = src.SighashType
	}
}

// mergeOutput unions src's Bip32Derivation into dst.
func mergeOutput(dst, src *psbt.POutput) {
	for _, d := range src.Bip32Derivation {
		if !hasBip32(dst.Bip32Derivation, d.PubKey) {
			dst.Bip32Derivation = append(dst.Bip32Derivation, d)
		}
	}
}

func hasPartialSig(set []*psbt.PartialSig, pub []byte) bool {
	for _, ps := range set {
		if bytes.Equal(ps.PubKey, pub) {
			return true
		}
	}
	return false
}

func hasBip32(set []*psbt.Bip32Derivation, pub []byte) bool {
	for _, d := range set {
		if bytes.Equal(d.PubKey, pub) {
			return true
		}
	}
	return false
}
