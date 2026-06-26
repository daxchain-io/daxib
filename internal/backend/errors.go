package backend

import (
	"context"
	"errors"
	"strings"

	"github.com/daxchain-io/daxib/internal/domain"
)

// unreachableErr maps a dial/transport failure (nothing listening, DNS, 5xx,
// connection reset) to domain.CodeBackendUnreachable (exit 6, retryable). A
// context cancellation/deadline passes through verbatim so the caller's own
// timeout funnels correctly; an already-typed domain error is preserved. The
// MASKED display URL is used and any occurrence of the resolved URL is scrubbed
// from the cause, so an embedded credential never reaches a user/log-facing
// message (the §7.5 contract).
func unreachableErr(o Options, op string, cause error) error {
	if cause == nil {
		return nil
	}
	if errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		return cause
	}
	var de *domain.Error
	if errors.As(cause, &de) {
		return cause
	}
	disp := o.displayURL()
	return domain.WithData(
		domain.Wrap(
			domain.CodeBackendUnreachable,
			"bitcoin backend "+disp+" unreachable during "+op+": "+scrubURL(o, cause.Error()),
			cause,
		),
		map[string]any{"endpoint": disp, "op": op, "type": string(o.Type)},
	)
}

// rpcErr maps a backend that ANSWERED but reported an error (a JSON-RPC error
// object, a 4xx REST status, a malformed response body) to
// domain.CodeBackendRPCError (exit 6). It is distinct from unreachableErr so a
// misconfigured-but-live node is not reported as "down". The message is scrubbed
// of the resolved URL just like the unreachable path.
func rpcErr(o Options, op, detail string) error {
	disp := o.displayURL()
	return domain.WithData(
		domain.Newf(domain.CodeBackendRPCError,
			"bitcoin backend %s returned an error during %s: %s", disp, op, scrubURL(o, detail)),
		map[string]any{"endpoint": disp, "op": op, "type": string(o.Type)},
	)
}

// scrubURL removes any occurrence of the RESOLVED endpoint URL from a transport/
// response error string, replacing it with the masked display form, so a Go HTTP
// error that echoes the full request URL (with an embedded credential) never
// reaches a user/log-facing message (§7.5).
func scrubURL(o Options, msg string) string {
	if o.URL == "" {
		return msg
	}
	return strings.ReplaceAll(msg, o.URL, o.displayURL())
}
