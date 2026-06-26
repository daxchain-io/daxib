package backend

import (
	"context"
	"net/http"

	"github.com/daxchain-io/daxib/internal/domain"
)

// Dial builds the adapter for Options.Type and verifies reachability by calling
// TipHeight once, so a dead or misconfigured endpoint fails fast and CLOSED
// (backend.unreachable, exit 6) instead of surfacing later mid-balance. It is the
// Bitcoin sibling of daxie's chain.Dial (whose guard probes eth_chainId); here
// TipHeight is the cheapest read that proves the backend is alive and speaks the
// expected protocol.
//
// The probe is bounded by ctx and by Options.Timeout (default 30s). An unknown
// Options.Type is an internal misconfiguration (the service validates the type
// before dialing).
func Dial(ctx context.Context, o Options) (Client, error) {
	hc := &http.Client{Timeout: o.timeout()}

	var c Client
	switch o.Type {
	case domain.BackendCore:
		c = newCoreClient(o, hc)
	case domain.BackendEsplora:
		c = newEsploraClient(o, hc)
	default:
		return nil, domain.Newf(domain.CodeInternal,
			"backend.Dial: unknown backend type %q (service must validate before dialing)", o.Type)
	}

	// Reachability probe: a single TipHeight. Bounded by ctx + Options.Timeout.
	probeCtx, cancel := context.WithTimeout(ctx, o.timeout())
	defer cancel()
	if _, err := c.TipHeight(probeCtx); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}
