package domain

// convert.go is the wire contract for `daxib convert <amount>` — the one pure,
// signing-free, provider-free utility use case (the Bitcoin sibling of daxie's
// eth/gwei/wei convert). It crosses the boundary as STRINGS only (no float on the
// wire, the §2.5 no-float rule); the value math reuses the float-free
// ParseAmountToSats + SatsToBTC the send pipeline already trusts.

// ConvertRequest is the input to `daxib convert <amount> [<to-unit>]`. Amount
// carries its source unit as a suffix ("0.001btc", "150000sat") or is a bare
// number (interpreted as BTC, the sendtoaddress convention amount.go encodes); To
// names the target unit ("sat"|"sats"|"btc"). An empty To converts to the OTHER
// unit (sat→btc, btc→sat) so a bare `convert 0.001btc` is meaningful with no
// second argument.
type ConvertRequest struct {
	Amount string `json:"amount" jsonschema:"value with optional unit suffix, e.g. \"0.001btc\" or \"150000sat\" or a bare BTC number"`
	To     string `json:"to,omitempty" jsonschema:"target unit: sat|sats|btc; omit to convert to the other unit"`
}

// ConvertResult is the output of a conversion. Every numeric field is an exact
// string (no float): Sat is the canonical integer-satoshi value, BTC is the exact
// 8-dp decimal, and Value is the result rendered in the To unit (the bare scalar
// the human path prints so `$(daxib convert …)` captures it cleanly).
type ConvertResult struct {
	Input string `json:"input"` // echoed normalized input, e.g. "0.00100000 btc"
	Sat   string `json:"sat"`   // canonical satoshis as a decimal integer string
	BTC   string `json:"btc"`   // canonical BTC as an exact 8-dp decimal string
	From  string `json:"from"`  // resolved source unit: "sat" | "btc"
	To    string `json:"to"`    // target unit: "sat" | "btc"
	Value string `json:"value"` // result in To units, exact string (no float)
}
