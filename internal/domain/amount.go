package domain

import "strings"

// amount.go is the float-free amount parser for the tx-send surface (`--amount
// <btc|sat>`). It mirrors backend/amount.go's decimalBTCToSats discipline but
// lives in domain so the service can call it without importing the backend
// provider (the arch matrix forbids service→…→backend re-export of a parser, and
// the backend helper is unexported). Every amount is an integer count of
// satoshis (the domain no-float rule); BTC is only ever a decimal STRING.

// maxMoneySat is the Bitcoin money cap: 21e6 BTC = 2_100_000_000_000_000 sat. An
// amount above this is rejected (no valid Bitcoin amount exceeds it) and it keeps
// every downstream int64 multiply (vsize*feerate, sums) far from overflow.
const maxMoneySat int64 = 21_000_000 * satPerBTC

// ParseAmountToSats parses a `--amount` value into integer satoshis with NO float
// arithmetic. The accepted forms (case-insensitive suffixes):
//
//   - "<n>sat"      → integer satoshis (e.g. "150000sat" → 150000)
//   - "<n>sats"     → integer satoshis
//   - "<d>btc"      → BTC decimal → sats (e.g. "0.001btc" → 100000)
//   - "<d>"         → a BARE number is interpreted as BTC (e.g. "0.001" → 100000,
//     "1" → 100000000). This matches the bitcoind/`sendtoaddress` convention where
//     a bare amount is BTC; a sat amount MUST carry the explicit "sat" suffix.
//
// A leading '+' is accepted; a leading '-' (or any negative result), a
// non-numeric body, sub-satoshi precision (>8 fractional digits with a non-zero
// digit), or a value above the 21e6-BTC money cap is usage.bad_amount (exit 2). A
// zero amount is permitted by the parser (the dust gate rejects it later with the
// dust-specific code, so the message is label-aware).
func ParseAmountToSats(s string) (int64, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return 0, New(CodeUsageBadAmount, "an amount is required (e.g. 0.001 or 150000sat)")
	}
	lower := strings.ToLower(raw)

	// Negative amounts are never valid (a send cannot move negative value).
	if strings.HasPrefix(lower, "-") {
		return 0, Newf(CodeUsageBadAmount, "amount %q must not be negative", s)
	}

	switch {
	case strings.HasSuffix(lower, "sats"):
		return parseSatSuffix(s, lower[:len(lower)-4])
	case strings.HasSuffix(lower, "sat"):
		return parseSatSuffix(s, lower[:len(lower)-3])
	case strings.HasSuffix(lower, "btc"):
		return parseBTCBody(s, lower[:len(lower)-3])
	default:
		// A bare number is BTC (the sendtoaddress convention).
		return parseBTCBody(s, lower)
	}
}

// AmountUnit is the canonical source unit an amount string carries: UnitSat for an
// explicit "sat"/"sats" suffix, UnitBTC for a "btc" suffix OR a bare number (the
// sendtoaddress convention ParseAmountToSats encodes). It is the one place the
// unit-detection rule lives so `convert` and the parser agree on what a string
// means.
type AmountUnit string

const (
	UnitSat AmountUnit = "sat"
	UnitBTC AmountUnit = "btc"
)

// Other returns the opposite unit (sat↔btc). It is the default `convert` target
// when no explicit to-unit is given.
func (u AmountUnit) Other() AmountUnit {
	if u == UnitSat {
		return UnitBTC
	}
	return UnitSat
}

// SourceUnit reports the unit an amount string denotes WITHOUT parsing the
// number: a "sat"/"sats" suffix is UnitSat, a "btc" suffix or a bare number is
// UnitBTC. It shares the exact suffix-precedence ladder ParseAmountToSats uses, so
// convert can echo the resolved source unit and pick the default target unit (the
// OTHER unit) consistently with how the value is parsed.
func SourceUnit(s string) AmountUnit {
	lower := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.HasSuffix(lower, "sats"), strings.HasSuffix(lower, "sat"):
		return UnitSat
	default:
		// "btc" suffix or a bare number both resolve to BTC.
		return UnitBTC
	}
}

// parseSatSuffix parses the integer-sat body of an "<n>sat" amount. Sats are
// whole integers — a decimal point is invalid here.
func parseSatSuffix(orig, body string) (int64, error) {
	body = strings.TrimPrefix(strings.TrimSpace(body), "+")
	if body == "" {
		return 0, Newf(CodeUsageBadAmount, "amount %q has no number before the sat suffix", orig)
	}
	if strings.ContainsRune(body, '.') {
		return 0, Newf(CodeUsageBadAmount, "amount %q is in sats and must be a whole number", orig)
	}
	var sats int64
	for i := 0; i < len(body); i++ {
		c := body[i]
		if c < '0' || c > '9' {
			return 0, Newf(CodeUsageBadAmount, "amount %q is not a valid satoshi number", orig)
		}
		sats = sats*10 + int64(c-'0')
		if sats > maxMoneySat {
			return 0, Newf(CodeUsageBadAmount, "amount %q exceeds the 21,000,000 BTC money cap", orig)
		}
	}
	return sats, nil
}

// parseBTCBody converts an exact BTC decimal STRING to integer satoshis with no
// float arithmetic. It accepts an optional leading '+', a whole part, and up to 8
// fractional digits; more than 8 fractional digits with a non-zero digit is
// sub-satoshi precision and an error.
func parseBTCBody(orig, body string) (int64, error) {
	body = strings.TrimPrefix(strings.TrimSpace(body), "+")
	if body == "" || body == "." {
		return 0, Newf(CodeUsageBadAmount, "amount %q is not a valid BTC number", orig)
	}
	whole, frac, _ := strings.Cut(body, ".")
	if len(frac) > 8 {
		for _, c := range frac[8:] {
			if c != '0' {
				return 0, Newf(CodeUsageBadAmount, "amount %q has sub-satoshi precision (more than 8 decimal places)", orig)
			}
		}
		frac = frac[:8]
	}
	frac += strings.Repeat("0", 8-len(frac))

	// whole may be empty (".5btc") — treat as zero whole part.
	var sats int64
	for _, part := range []string{whole, frac} {
		for i := 0; i < len(part); i++ {
			c := part[i]
			if c < '0' || c > '9' {
				return 0, Newf(CodeUsageBadAmount, "amount %q is not a valid BTC number", orig)
			}
			sats = sats*10 + int64(c-'0')
			if sats > maxMoneySat {
				return 0, Newf(CodeUsageBadAmount, "amount %q exceeds the 21,000,000 BTC money cap", orig)
			}
		}
	}
	return sats, nil
}
