package service

import (
	"context"
	"strconv"
	"strings"

	"github.com/daxchain-io/daxib/internal/domain"
)

// convert.go is daxib's one signing-free, provider-free utility use case: sat↔BTC
// unit conversion so agents never hand-roll the 10^8 satoshi math (the Bitcoin
// sibling of daxie's eth/gwei/wei convert). It is PURE — no provider, no clock, no
// I/O — and delegates ALL value math to domain.ParseAmountToSats + domain.SatsToBTC
// (the float-free helpers the send pipeline already trusts), so a convert can
// never disagree with how a `tx send --amount` is parsed.

// Convert parses the amount (which carries its own source unit as a suffix, or is
// a bare BTC number) into canonical satoshis, then renders both the satoshi and
// the exact-BTC forms plus the value in the requested To unit. An empty To
// converts to the OTHER unit (sat→btc, btc→sat) so a bare `convert 0.001btc` is
// meaningful with no second argument. A bad To unit is usage.convert.bad_unit
// (exit 2); a malformed amount surfaces the parser's own usage.bad_amount (exit 2).
func (s *Service) Convert(ctx context.Context, req domain.ConvertRequest) (domain.ConvertResult, error) {
	_ = ctx // pure: no provider, no clock — kept for signature symmetry with the other use cases.

	from := domain.SourceUnit(req.Amount)

	// Resolve the target unit: an explicit To wins; an empty To is "the other unit".
	to := from.Other()
	if t := strings.TrimSpace(req.To); t != "" {
		parsed, err := parseConvertUnit(t)
		if err != nil {
			return domain.ConvertResult{}, err
		}
		to = parsed
	}

	// Parse to canonical satoshis with the SAME float-free parser the send pipeline
	// uses (so the unit semantics never drift from `tx send --amount`).
	sats, err := domain.ParseAmountToSats(req.Amount)
	if err != nil {
		return domain.ConvertResult{}, err
	}

	btc := domain.SatsToBTC(sats)
	satStr := strconv.FormatInt(sats, 10)

	value := satStr
	if to == domain.UnitBTC {
		value = btc
	}
	input := satStr + " sat"
	if from == domain.UnitBTC {
		input = btc + " btc"
	}

	return domain.ConvertResult{
		Input: input,
		Sat:   satStr,
		BTC:   btc,
		From:  string(from),
		To:    string(to),
		Value: value,
	}, nil
}

// parseConvertUnit canonicalizes a target-unit token to UnitSat / UnitBTC. It
// accepts the same spellings the amount suffixes use (sat|sats|btc,
// case-insensitive). Anything else is a usage error (exit 2).
func parseConvertUnit(u string) (domain.AmountUnit, error) {
	switch strings.ToLower(strings.TrimSpace(u)) {
	case "sat", "sats":
		return domain.UnitSat, nil
	case "btc":
		return domain.UnitBTC, nil
	default:
		return "", domain.Newf("usage.convert.bad_unit", "unknown unit %q (want sat or btc)", u)
	}
}
