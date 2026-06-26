package backend

import (
	"encoding/hex"
	"errors"
	"strings"
)

// amount.go holds the float-free BTC↔sat conversion the Core adapter needs.
// bitcoind reports amounts as JSON numbers (e.g. 0.00150000). Parsing them via
// float64 risks binary-rounding drift (0.1 BTC is not exactly representable), so
// scantxoutset amounts are decoded as json.Number and converted by exact decimal
// string arithmetic here — the domain no-float discipline reaching into the wire.

// errNonIntegerSat is returned when a BTC amount has sub-satoshi precision (more
// than 8 fractional digits), which a valid Bitcoin amount never does.
var errNonIntegerSat = errors.New("amount has sub-satoshi precision")

// decimalBTCToSats converts an exact BTC decimal STRING (as json.Number carries
// it) to integer satoshis with no float arithmetic. It accepts an optional
// leading '-', a whole part, and up to 8 fractional digits; more than 8 fractional
// digits (sub-satoshi) is an error. Examples: "0.00150000" -> 150000,
// "21" -> 2_100_000_000, "-0.5" -> -50_000_000.
func decimalBTCToSats(s string) (int64, error) {
	s = strings.TrimSpace(s)
	neg := false
	if strings.HasPrefix(s, "-") {
		neg = true
		s = s[1:]
	} else if strings.HasPrefix(s, "+") {
		s = s[1:]
	}
	whole, frac, _ := strings.Cut(s, ".")
	if len(frac) > 8 {
		// Tolerate trailing zeros beyond 8 places; reject real sub-satoshi digits.
		for _, c := range frac[8:] {
			if c != '0' {
				return 0, errNonIntegerSat
			}
		}
		frac = frac[:8]
	}
	// Right-pad the fractional part to exactly 8 digits.
	frac = frac + strings.Repeat("0", 8-len(frac))

	var sats int64
	for _, part := range []string{whole, frac} {
		for i := 0; i < len(part); i++ {
			c := part[i]
			if c < '0' || c > '9' {
				return 0, errNonIntegerSat
			}
			sats = sats*10 + int64(c-'0')
		}
	}
	if neg {
		return -sats, nil
	}
	return sats, nil
}

// hexEncode renders raw bytes as lowercase hex (the Esplora POST /tx body form).
func hexEncode(b []byte) string { return hex.EncodeToString(b) }
