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
