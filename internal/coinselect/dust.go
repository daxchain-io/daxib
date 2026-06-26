package coinselect

// DustThresholdP2WPKH is the P2WPKH dust limit in satoshis, pinned to btcd's
// mempool.GetDustThreshold for a witness-v0 output at the default min-relay fee
// (1000 sat/kvB). It is the value below which a change output is uneconomic to
// ever spend, so a change below it is dropped INTO THE FEE rather than emitted.
//
// Derivation (btcd GetDustThreshold): the output's total serialized+spend size is
// (txOut serialized size + the input that would spend it). For P2WPKH:
//
//	output size        = 8 + 1 + 22                 = 31 bytes
//	spending input     = 32+4+1+4 (base, 41) + ceil(witness=107/4≈27) ≈ 67
//	total              = 31 + 67                     = 98
//	dust threshold     = total * 3 * minRelay/1000   = 98 * 3 * 1000/1000 = 294
//
// btcd computes this with the witness-discounted spend size; the pin test in
// dust_test.go asserts DustThresholdP2WPKH == mempool.GetDustThreshold(p2wpkhOut)
// at mempool.DefaultMinRelayTxFee so this constant can never drift from btcd.
const DustThresholdP2WPKH int64 = 294

// IsDust reports whether a change-output value is below the P2WPKH dust
// threshold (so it must be absorbed into the fee instead of emitted).
func IsDust(valueSat int64) bool { return valueSat < DustThresholdP2WPKH }

// DustThresholdForScript returns btcd's mempool dust threshold (at the default
// 1000 sat/kvB min-relay fee) for an output paying to scriptPubKey of the given
// bytes. It inlines GetDustThreshold so a NON-P2WPKH recipient (Taproot/P2WSH 43-vB
// output, legacy P2PKH/P2SH) is gated against its OWN dust limit, not the P2WPKH
// 294 (CB-4): a small Taproot send would otherwise pass the 294 gate yet be a dust
// output the network bounces.
//
// btcd formula: totalSize = txOut.SerializeSize() + 41 (the spending input
// preamble) + (witness ? 107/4 : 107); threshold = 3 * totalSize. txOut.SerializeSize
// = 8 (value) + varint(scriptLen) + scriptLen. A standard scriptPubKey is far below
// 0xfd so varint is 1.
func DustThresholdForScript(script []byte) int64 {
	outSize := 8 + varIntSize(int64(len(script))) + int64(len(script))
	totalSize := outSize + 41
	if isWitnessProgramBytes(script) {
		totalSize += 107 / 4 // witness-discounted spend size (WitnessScaleFactor=4)
	} else {
		totalSize += 107
	}
	return 3 * totalSize
}

// isWitnessProgramBytes reports whether script is a BIP-141 witness program: a
// single version opcode (OP_0 / OP_1..OP_16) followed by a canonical data push of
// 2..40 bytes, with the total length 4..42. This mirrors txscript.IsWitnessProgram
// without importing the heavy txscript package into the coinselect leaf.
func isWitnessProgramBytes(script []byte) bool {
	if len(script) < 4 || len(script) > 42 {
		return false
	}
	op0 := script[0]
	// OP_0 (0x00) or OP_1..OP_16 (0x51..0x60).
	if op0 != 0x00 && (op0 < 0x51 || op0 > 0x60) {
		return false
	}
	pushLen := int(script[1]) // canonical small push opcode == the byte count
	if pushLen < 2 || pushLen > 40 {
		return false
	}
	return len(script) == 2+pushLen
}
