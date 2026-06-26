package backend

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/daxchain-io/daxib/internal/domain"
)

// TestMaskResolvedURL proves a RESOLVED URL is reduced to its credential-free
// locator (scheme://host[:port] only). The path/query/userinfo are dropped
// unconditionally so no entropy heuristic can be evaded (KNOWN-1): a host:port
// Core endpoint with no path is untouched, but any path or userinfo collapses.
func TestMaskResolvedURL(t *testing.T) {
	cases := map[string]string{
		"http://127.0.0.1:8332":    "http://127.0.0.1:8332",
		"https://node.example/api": "https://node.example",
		"https://node.example/v2/abcdef0123456789abcdef0123456789deadbeef": "https://node.example",
		// A lowercase low-entropy key that the old heuristic missed — now dropped.
		// (Deliberately NOT a real provider key prefix, so secret scanners don't flag
		// this fixture; redaction drops the whole path regardless of the value.)
		"https://node.example/apikey_lowentropy_0123456789abcdefxyz": "https://node.example",
		// userinfo credentials collapse to scheme://host.
		"https://user:hunter2@node.example/path": "https://node.example",
		"https://node.example:443":               "https://node.example:443",
	}
	for in, want := range cases {
		if got := maskResolvedURL(in); got != want {
			t.Errorf("maskResolvedURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestDisplayURL_CollapsesLiteralDisplayURL is the SECLEAK-1 defense-in-depth
// regression: even when a (stale/heuristic) caller supplies a non-empty DisplayURL
// that STILL carries a literal credential-bearing tail, Options.displayURL() must
// collapse it to scheme://host so the error path cannot leak the key. A DisplayURL
// that is already scheme://host, masked with "***", or a pure ${…} reference is
// shown verbatim.
func TestDisplayURL_CollapsesLiteralDisplayURL(t *testing.T) {
	leak := map[string]string{ // DisplayURL -> fragment that must NOT survive
		"https://node.example/v2/myShortKey":                      "myShortKey",
		"https://node.example/v2/dashed-api-key-value-here":       "dashed-api-key-value-here",
		"https://node.example/v2/a.b.c.dotcontaining.secretvalue": "dotcontaining",
		"https://node.example/v2/alllowercasenodigitsapikeyhere":  "alllowercasenodigitsapikeyhere",
		"https://alice:hunter2supersecret@node.example/path":      "hunter2supersecret",
	}
	for disp, frag := range leak {
		o := Options{DisplayURL: disp}
		got := o.displayURL()
		if strings.Contains(got, frag) {
			t.Errorf("displayURL(%q) leaked %q: %q", disp, frag, got)
		}
	}
	// scheme://host and host:port are verbatim. Any DisplayURL carrying literal
	// path/query content — even harmless path words like `v2`/`api` next to a "***"
	// or ${env:} ref — collapses to scheme://host (the safe over-collapse: a literal
	// low-entropy key is indistinguishable from a path word, so the error path drops
	// the whole tail). The friendly `/v2/***` form is only used by `backend
	// list/show`, which never routes through displayURL().
	wantKeep := map[string]string{
		"https://node.example":                    "https://node.example",
		"https://node.example/v2/***":             "https://node.example",
		"https://node.example/api?key=${env:KEY}": "https://node.example",
		"127.0.0.1:8332":                          "127.0.0.1:8332",
	}
	for disp, want := range wantKeep {
		o := Options{DisplayURL: disp}
		if got := o.displayURL(); got != want {
			t.Errorf("displayURL(%q) = %q, want %q", disp, got, want)
		}
	}
}

// TestDial_Unreachable_DoesNotLeakSecret proves the §7.5/KNOWN-1 contract: an
// embedded credential in the resolved URL never appears in the unreachable error
// OR its data.endpoint, even without a service-supplied DisplayURL (backend's own
// fallback masking). It covers the cases the old entropy heuristic missed: an
// all-lowercase low-entropy key, a user:pass@host userinfo credential, and a URL
// that ended in a trailing slash (the Esplora base-trim gap, CB-3).
func TestDial_Unreachable_DoesNotLeakSecret(t *testing.T) {
	srv := httptest.NewServer(nil)
	base := srv.URL
	srv.Close()

	cases := []struct {
		name   string
		url    string
		secret string
	}{
		{"high-entropy-path", base + "/v2/abcdef0123456789abcdef0123456789deadbeef", "abcdef0123456789abcdef0123456789deadbeef"},
		{"lowercase-low-entropy", base + "/v2/sklivelowercaseapikeyabcdefxyz", "sklivelowercaseapikeyabcdefxyz"},
		{"userinfo", strings.Replace(base, "://", "://user:hunter2supersecret@", 1) + "/v2/path", "hunter2supersecret"},
		{"trailing-slash", base + "/v2/trailingslashkeyabcdef0123456789/", "trailingslashkeyabcdef0123456789"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Dial(context.Background(), Options{
				Type:    domain.BackendEsplora,
				URL:     tc.url,
				Network: domain.NetworkMainnet,
				Timeout: secondsTimeout,
			})
			if err == nil {
				t.Fatal("expected an unreachable error")
			}
			if strings.Contains(err.Error(), tc.secret) {
				t.Fatalf("error leaked the secret %q: %v", tc.secret, err)
			}
			var de *domain.Error
			if errors.As(err, &de) {
				if ep, _ := de.Data["endpoint"].(string); strings.Contains(ep, tc.secret) {
					t.Fatalf("data.endpoint leaked the secret: %q", ep)
				}
			}
		})
	}
}
