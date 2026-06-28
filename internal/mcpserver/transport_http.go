package mcpserver

import (
	"context"
	"crypto/tls"
	"net/http"

	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// transport_http.go is the RESERVED v1.1 HTTP + auth seam (docs/ARCHITECTURE.md §6.8). It is
// declared NOW so an authenticator hook has a home and v1.1 is a body swap touching
// nothing above — a new file body + a new --transport enum value, not a refactor. In
// v1 no net/http server is started; ServeHTTP refuses with a forward-pointing
// domain.Error.
//
// Three properties already in place make HTTP a drop-in (none built in v1, only the
// seams): (1) service.Service is concurrency-safe (file locks hold under N HTTP
// sessions); (2) handlers keep zero per-connection state (one *mcp.Server serves every
// connection); (3) progressSink + the SDK's NotifyProgress already deliver over HTTP
// transparently. v1's single-tenant local model means a per-principal policy is the
// only piece v1.1 adds, and it threads through the Authenticator below.

// HTTPOptions is the reserved v1.1 HTTP listener config. The Authenticator turns a
// request into the agent identity v1.1 will bind to a per-principal policy; a nil
// Authenticator means "refuse non-loopback" (the v1.1 default). The fields are unused
// in v1 — their presence is the whole point: wiring auth in v1.1 is a body change here,
// not a plumbing change above.
type HTTPOptions struct {
	Addr          string
	Authenticator func(r *http.Request) error // nil ⇒ refuse non-loopback (v1.1)
	TLS           *tls.Config
}

// ServeHTTP is the v1.1 entry point. In v1 it refuses: NO net/http server is started.
// v1.1 lands the body here (mcp.NewStreamableHTTPHandler + the Authenticator
// middleware), touching nothing in server.go. The blank parameters keep the v1.1
// signature stable while documenting what v1.1 binds.
func ServeHTTP(_ context.Context, _ *mcp.Server, _ HTTPOptions) error {
	return domain.New("usage.unsupported",
		"the http transport ships in v1.1; use --transport stdio")
}
