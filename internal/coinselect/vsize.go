// Package coinselect is daxib's pure-value coin-selection + vsize/fee provider
// (the Bitcoin sibling of daxie's fee math). It is a provider leaf: it imports
// ONLY internal/domain + stdlib (sort, errors). It does NO I/O, holds no clock,
// and pulls in NO btcd heavy dependency — the btcd vsize/dust formulas are
// INLINED as integer constants here and pinned to btcd's own GetTransactionWeight
// / GetDustThreshold math by cross-check tests (vsize_test.go, dust_test.go) so
// they can never silently drift.
//
// Why inline and not import github.com/btcsuite/btcd/blockchain or .../mempool in
// PRODUCTION code: those packages drag the full validation/chainstate dependency
// tree in, threatening the CGO_ENABLED=0 + GOOS=windows offline build (M4 binding
// decision). Only txscript/wire/btcutil/btcec are sanctioned for production; the
// blockchain/mempool packages appear ONLY in this package's _test.go cross-checks.
//
// Every satoshi value is int64 (the domain no-float rule); the fee rate is int64
// sat/vByte. All arithmetic is integer.
package coinselect

// P2WPKH vsize model (whole vByte, conservative — never underpay relay).
//
// A vByte is ceil(weight/4) where a base byte weighs 4 and a witness byte weighs
// 1 (BIP-141 witness scale factor). The marginal-cost constants below are the
// per-input / per-output vsize for native-SegWit v0 P2WPKH (the only address type
// M2 produces), pinned to btcd's blockchain.GetTransactionWeight by the matrix
// test in vsize_test.go.
const (
	// p2wpkhInputVBytes is the marginal vsize of one P2WPKH input. Base: 32 (prev
	// txid) + 4 (vout) + 1 (empty scriptSig len) + 4 (sequence) = 41 bytes × 4 =
	// 164 weight units. Witness: 1 (item count) + 1 (sig len) + ~72 (DER sig, low-S
	// worst case incl. sighash byte) + 1 (pubkey len) + 33 (compressed pubkey) =
	// 108 weight units. Total 272 wu → ceil/4 = 68 vB.
	p2wpkhInputVBytes = 68
	// p2wpkhOutputVBytes is the marginal vsize of one P2WPKH output. 8 (value) + 1
	// (scriptPubKey len) + 22 (OP_0 <20-byte program>) = 31 bytes, no witness → 31
	// vB. It is the size of the CHANGE output (always P2WPKH, the only type M2
	// produces). The RECIPIENT output may be any standard type, so its size is
	// computed from the real scriptPubKey via OutputVBytes and threaded into Select.
	p2wpkhOutputVBytes = 31
	// txOverheadVBytes is the fixed per-tx overhead. 4 (version) + 4 (locktime) + 1
	// (vin count, ≤252) + 1 (vout count) = 10 base bytes × 4 = 40 wu, plus the 2
	// segwit marker+flag bytes at witness weight (2 wu) = 42 wu → ceil/4 = 10.5,
	// rounded UP to 11 vB for a conservative fee (never underpay).
	txOverheadVBytes = 11
)

// EstimateVSize returns the predicted SIGNED vsize in whole vBytes for a tx with
// numInputs P2WPKH inputs and numOutputs P2WPKH outputs. It is an exact closed
// form (not an estimate that must be re-fed): the fee↔selection loop recomputes
// the fee from the FINAL input count, so it always matches the built tx.
//
// EVERY output is modelled as a P2WPKH output (31 vB). That is correct for the
// change output (always P2WPKH) but UNDERSHOOTS a larger recipient script
// (Taproot/P2WSH = 43 vB, P2PKH = 34, P2SH = 32). The send path therefore uses
// EstimateVSizeOut, which takes the recipient output's real serialized size; this
// closed form is kept for the equal-size case (P2WPKH→P2WPKH) and the tests.
func EstimateVSize(numInputs, numOutputs int) int64 {
	if numOutputs < 0 {
		numOutputs = 0
	}
	return EstimateVSizeOut(numInputs, p2wpkhOutputVBytes, numOutputs-1)
}

// EstimateVSizeOut returns the predicted SIGNED vsize for a tx with numInputs
// P2WPKH inputs, ONE recipient output of recipientVBytes serialized vBytes, plus
// extraP2WPKHOuts additional P2WPKH outputs (the change output; 0 or 1 in M4).
// Threading the recipient's REAL output size in means the fee/selection math never
// underpays relay for a non-P2WPKH recipient (Taproot/P2WSH/P2PKH/P2SH). A
// non-positive recipientVBytes falls back to the P2WPKH size.
func EstimateVSizeOut(numInputs int, recipientVBytes int64, extraP2WPKHOuts int) int64 {
	if numInputs < 0 {
		numInputs = 0
	}
	if recipientVBytes <= 0 {
		recipientVBytes = p2wpkhOutputVBytes
	}
	if extraP2WPKHOuts < 0 {
		extraP2WPKHOuts = 0
	}
	return txOverheadVBytes +
		int64(numInputs)*p2wpkhInputVBytes +
		recipientVBytes +
		int64(extraP2WPKHOuts)*p2wpkhOutputVBytes
}

// OutputVBytes returns the serialized vsize of one TxOut whose scriptPubKey is
// scriptLen bytes: 8 (value) + varIntSize(scriptLen) + scriptLen. An output has no
// witness, so its serialized size IS its vsize. This lets the send path compute the
// recipient output's REAL size from its scriptPubKey (P2WPKH 31, P2SH 32, P2PKH 34,
// P2TR/P2WSH 43) rather than assume P2WPKH.
func OutputVBytes(scriptLen int) int64 {
	if scriptLen < 0 {
		scriptLen = 0
	}
	return 8 + varIntSize(int64(scriptLen)) + int64(scriptLen)
}

// varIntSize returns the number of bytes a Bitcoin CompactSize (varint) of value n
// serializes to: 1 for <0xfd, 3 for ≤0xffff, 5 for ≤0xffffffff, else 9. A standard
// scriptPubKey is far below 0xfd, so this is 1 in practice, but the general form
// keeps OutputVBytes exact for any script.
func varIntSize(n int64) int64 {
	switch {
	case n < 0xfd:
		return 1
	case n <= 0xffff:
		return 3
	case n <= 0xffffffff:
		return 5
	default:
		return 9
	}
}

// FeeFor returns vsize*feerate (sat), the exact fee for a known whole-vByte
// vsize. vsize is already rounded up to whole vB (btcd vsize = ceil(weight/4)),
// so there is no further ceil-divide: the multiply IS the fee. A negative input
// is clamped to 0 (defensive; a fee is never negative).
func FeeFor(vsizeVB, feerateSatPerVB int64) int64 {
	if vsizeVB < 0 || feerateSatPerVB < 0 {
		return 0
	}
	return vsizeVB * feerateSatPerVB
}
