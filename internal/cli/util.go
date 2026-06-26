package cli

import "github.com/daxchain-io/daxib/internal/domain"

// itoa is a tiny int->decimal helper for human table cells (the render package
// stays format-only; the cli does its own small conversions to avoid pulling
// strconv into every command).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// itoa64 is the int64 sibling of itoa for sat amounts and confirmation counts.
func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// flagNetwork returns the parsed --network, or "" when the flag is unset so the
// service applies its own DAXIB_NETWORK / default resolution. A bad --network
// value is surfaced as a clean usage error here, before the service call.
func flagNetwork(rs *rootState) (domain.Network, error) {
	if rs.flags.Network == "" {
		return "", nil
	}
	return domain.ParseNetwork(rs.flags.Network)
}

// flagNetworkOrDefault parses a command-local --network value (e.g. `backend add
// --network`), falling back to the global --network when the local one is empty.
// An empty result lets the service apply its active-network default. A bad value
// is a clean usage error before the service call.
func flagNetworkOrDefault(rs *rootState, local string) (domain.Network, error) {
	if local != "" {
		return domain.ParseNetwork(local)
	}
	return flagNetwork(rs)
}
