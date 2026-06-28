package mcpserver

import (
	"context"
	"crypto/tls"
	"net/http"

	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// transport_http.go is the RESERVED HTTP + auth seam (planned — tracked in
// github.com/daxchain-io/daxib/issues/12; design in docs/ARCHITECTURE.md). It is
// declared NOW so an authenticator hook has a home and adding HTTP later is a body
// swap touching nothing above — a new file body + a new --transport enum value, not a
// refactor. Today no net/http server is started; ServeHTTP refuses with a
// forward-pointing domain.Error.
//
// Properties already in place make HTTP a drop-in (none built yet, only the seams):
// (1) service.Service is concurrency-safe (file locks hold under N HTTP sessions);
// (2) handlers keep zero per-connection state (one *mcp.Server serves every
// connection); (3) progressSink + the SDK's NotifyProgress already deliver over HTTP
// transparently; (4) the domain.Principal seam (issue #11) is already threaded
// through every service method, so the Authenticator fills the Principal from the
// request's bearer token and the handlers pass it straight through — a value
// change, not a refactor (the journal Source attribution falls out for free). The
// remaining piece is per-principal auth + policy, which threads through the
// Authenticator below.

// HTTPOptions is the reserved HTTP listener config. The Authenticator turns a request
// into the agent identity bound to a per-principal policy; a nil Authenticator means
// "refuse non-loopback" (the planned default). The fields are unused today — their
// presence is the whole point: wiring auth later is a body change here, not a plumbing
// change above.
type HTTPOptions struct {
	Addr          string
	Authenticator func(r *http.Request) error // nil ⇒ refuse non-loopback
	TLS           *tls.Config
}

// ServeHTTP is the reserved HTTP entry point. Today it refuses: NO net/http server is
// started. The body lands later (mcp.NewStreamableHTTPHandler + the Authenticator
// middleware), touching nothing in server.go. The blank parameters keep the future
// signature stable while documenting what HTTP binds.
func ServeHTTP(_ context.Context, _ *mcp.Server, _ HTTPOptions) error {
	return domain.New("usage.unsupported",
		"the http transport is not yet available; use --transport stdio")
}
