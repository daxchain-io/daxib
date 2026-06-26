package service

import (
	"context"

	"github.com/daxchain-io/daxib/internal/domain"
)

// minRelayFeeRate is the 1 sat/vByte min-relay floor. Every recommendation and
// resolved send fee rate is clamped up to this so daxib never produces a
// non-relayable sub-1-sat/vB transaction.
const minRelayFeeRate int64 = 1

// maxFeeRate is the upper sanity bound on an explicit --fee-rate (sat/vByte). No
// real send needs anything close to this; the cap exists so an over-range value
// cannot silently int64-overflow during parsing or in a downstream fee multiply
// (vsize*rate, inputFee=68*rate). 10,000,000 sat/vB is ~10x the highest fee spikes
// ever seen and keeps 68*rate and (huge-vsize)*rate far from the int64 ceiling.
const maxFeeRate int64 = 10_000_000

// defaultSpeed is the fee tier used when --speed is unset.
const defaultSpeed = "normal"

// Fee implements the `fee` noun: dial the active backend, read its sat/vByte
// estimates, and return a per-speed recommendation with the 1 sat/vB floor
// applied. There is NO EIP-1559 base/tip split in Bitcoin — the backend's
// sat/vByte estimate IS the feerate; the only jobs here are picking the speed
// tier, applying the relay floor, and surfacing the per-target table.
func (s *Service) Fee(ctx context.Context, req domain.FeeRequest) (domain.FeeQuotesResult, error) {
	client, backendName, _, err := s.dialActiveBackend(ctx)
	if err != nil {
		return domain.FeeQuotesResult{}, err
	}
	defer client.Close()

	est, err := client.FeeEstimates(ctx)
	if err != nil {
		return domain.FeeQuotesResult{}, err
	}

	rec := func(v int64) int64 {
		if v < minRelayFeeRate {
			return minRelayFeeRate
		}
		return v
	}
	slow, normal, fast := rec(est.Slow), rec(est.Normal), rec(est.Fast)

	speed := req.Speed
	if speed == "" {
		speed = defaultSpeed
	}
	var selectedRate int64
	switch speed {
	case "slow":
		selectedRate = slow
	case "fast":
		selectedRate = fast
	case "normal":
		selectedRate = normal
	default:
		return domain.FeeQuotesResult{}, domain.Newf(domain.CodeUsage+".speed",
			"unknown --speed %q: want one of slow, normal, fast", speed)
	}

	return domain.FeeQuotesResult{
		Network:      s.net,
		Backend:      backendName,
		Slow:         slow,
		Normal:       normal,
		Fast:         fast,
		ByTarget:     est.ByTarget,
		FloorSatVB:   minRelayFeeRate,
		Selected:     speed,
		SelectedRate: selectedRate,
	}, nil
}

// resolveFeeRate resolves the send fee rate: an explicit --fee-rate (a positive
// integer sat/vByte, used verbatim) OR the backend estimate for the chosen speed
// tier, always clamped to the 1 sat/vB relay floor. A non-integer / non-positive
// --fee-rate is usage.bad_fee_rate (exit 2).
func resolveFeeRate(feeRateStr, speed string, est domain.FeeEstimates) (int64, error) {
	if feeRateStr != "" {
		rate, err := parseFeeRate(feeRateStr)
		if err != nil {
			return 0, err
		}
		return rate, nil
	}
	if speed == "" {
		speed = defaultSpeed
	}
	var rate int64
	switch speed {
	case "slow":
		rate = est.Slow
	case "fast":
		rate = est.Fast
	case "normal":
		rate = est.Normal
	default:
		return 0, domain.Newf(domain.CodeUsage+".speed",
			"unknown --speed %q: want one of slow, normal, fast", speed)
	}
	if rate < minRelayFeeRate {
		rate = minRelayFeeRate // backend gave nothing / a cold estimate → relay floor
	}
	return rate, nil
}

// parseFeeRate parses an explicit --fee-rate into a positive integer sat/vByte
// with no float arithmetic. A decimal point, a non-digit, a leading sign other
// than '+', or a non-positive value is usage.bad_fee_rate (exit 2).
func parseFeeRate(s string) (int64, error) {
	body := s
	if len(body) > 0 && body[0] == '+' {
		body = body[1:]
	}
	if body == "" {
		return 0, domain.Newf(domain.CodeUsageBadFeeRate, "invalid --fee-rate %q: want a positive integer sat/vByte", s)
	}
	var rate int64
	for i := 0; i < len(body); i++ {
		c := body[i]
		if c < '0' || c > '9' {
			return 0, domain.Newf(domain.CodeUsageBadFeeRate, "invalid --fee-rate %q: want a positive integer sat/vByte", s)
		}
		rate = rate*10 + int64(c-'0')
		// Bound every step (mirroring ParseAmountToSats' per-step maxMoneySat cap) so
		// an over-range value can never int64-wrap to a garbage positive feerate that
		// is silently accepted (and then overflows the downstream fee multiply).
		if rate > maxFeeRate {
			return 0, domain.Newf(domain.CodeUsageBadFeeRate,
				"--fee-rate %q exceeds the %d sat/vByte sanity cap", s, maxFeeRate)
		}
	}
	if rate < minRelayFeeRate {
		return 0, domain.Newf(domain.CodeUsageBadFeeRate, "--fee-rate %q is below the 1 sat/vByte relay floor", s)
	}
	return rate, nil
}
