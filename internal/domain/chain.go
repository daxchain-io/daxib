package domain

// chain.go holds the Bitcoin chain-read value types the backend provider returns
// and the service aggregates: a single UTXO, the fee-estimate table, and a tx's
// confirmation status. These are the M3 analogs of daxie's account-balance /
// receipt shapes, reframed for the UTXO model (docs/ARCHITECTURE.md §3.1). They carry NO
// float field — every amount is an integer count of satoshis (the domain no-float
// rule), and fee rates are sat/vByte carried as integers keyed by confirmation
// target.

// UTXO is one unspent transaction output owned by a wallet address. It is the
// atom of the Bitcoin balance/coin-control model: a spend consumes whole UTXOs.
// ValueSat is the output amount in satoshis (never a float). Height is the block
// the output was confirmed in (0 = still unconfirmed / in the mempool);
// Confirmations is tip_height - Height + 1 for a confirmed output, 0 when
// unconfirmed. Address is the bech32 address the output pays to (so a balance can
// attribute each coin back to a receive/change address).
type UTXO struct {
	Txid          string `json:"txid"`
	Vout          uint32 `json:"vout"`
	Address       string `json:"address"`
	ValueSat      int64  `json:"value_sat"`
	Height        int64  `json:"height"`        // 0 = unconfirmed
	Confirmations int64  `json:"confirmations"` // 0 when unconfirmed
}

// FeeEstimates is the sat/vByte fee table by confirmation target, returned by the
// backend's estimator (docs/ARCHITECTURE.md §3.8). It is plumbed by a later tx milestone;
// M3 only proves both backends populate it. ByTarget maps a confirmation target
// (in blocks) to the estimated fee rate in sat/vByte (rounded to an integer — the
// domain holds no float). Slow/Normal/Fast are convenience projections the fee
// engine selects by --speed.
type FeeEstimates struct {
	ByTarget map[int]int64 `json:"by_target"` // blocks -> sat/vByte
	Slow     int64         `json:"slow"`      // ~6-block target
	Normal   int64         `json:"normal"`    // ~3-block target
	Fast     int64         `json:"fast"`      // ~1-block target
}

// TxStatus is a transaction's confirmation state, returned by the backend
// (docs/ARCHITECTURE.md §3.8 / later tx milestone). Confirmed is true once the tx is in a
// block; BlockHeight/Confirmations are then populated. A still-mempool or unknown
// tx reports Confirmed=false with zeroed heights.
type TxStatus struct {
	Txid          string `json:"txid"`
	Confirmed     bool   `json:"confirmed"`
	BlockHeight   int64  `json:"block_height,omitempty"`
	Confirmations int64  `json:"confirmations,omitempty"`
}

// satPerBTC is the fixed integer scale: 100_000_000 sats == 1 BTC. A daxib value
// type never carries a float64 BTC amount; BTC is only ever a rendered decimal
// STRING produced by SatsToBTC, so an amount round-trips through JSON exactly.
const satPerBTC = 100_000_000

// SatsToBTC renders an integer satoshi amount as an exact BTC decimal string with
// eight fractional digits and no float arithmetic (e.g. 150000 -> "0.00150000",
// -2_100_000_000 -> "-21.00000000"). The whole and fractional parts are formatted
// by integer division/modulo so there is never any binary-float rounding drift.
func SatsToBTC(sats int64) string {
	neg := sats < 0
	if neg {
		sats = -sats
	}
	whole := sats / satPerBTC
	frac := sats % satPerBTC
	// frac is always < 1e8, so an 8-digit zero-padded fractional field is exact.
	var fb [8]byte
	for i := 7; i >= 0; i-- {
		fb[i] = byte('0' + frac%10)
		frac /= 10
	}
	out := utoa64(whole) + "." + string(fb[:])
	if neg {
		return "-" + out
	}
	return out
}

// utoa64 is a tiny dependency-free uint64-ish decimal for the whole-BTC part
// (domain avoids strconv on its value paths, mirroring utoa32/itoa).
func utoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
