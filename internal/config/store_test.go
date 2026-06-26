package config

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/daxchain-io/daxib/internal/domain"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir()) // Open takes the config DIRECTORY; it joins config.toml inside
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

// TestRoundTrip proves an endpoint survives add -> list -> use -> get, the default
// marker tracks, and remove clears the default.
func TestRoundTrip(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	_, err := s.AddEndpoint(ctx, "localcore", Endpoint{
		Network:    string(domain.NetworkRegtest),
		Type:       string(domain.BackendCore),
		URLRef:     "http://127.0.0.1:18443",
		RPCUserRef: "x",
		RPCPassRef: "${env:DAXIB_RPCPASS}",
	}, false)
	if err != nil {
		t.Fatalf("AddEndpoint: %v", err)
	}

	views, err := s.ListEndpoints("")
	if err != nil {
		t.Fatalf("ListEndpoints: %v", err)
	}
	if len(views) != 1 || views[0].Name != "localcore" || views[0].Default {
		t.Fatalf("list = %+v, want one non-default localcore", views)
	}

	network, err := s.UseEndpoint(ctx, "localcore")
	if err != nil {
		t.Fatalf("UseEndpoint: %v", err)
	}
	if network != string(domain.NetworkRegtest) {
		t.Fatalf("UseEndpoint network = %q, want regtest", network)
	}
	def, _ := s.DefaultForNetwork(string(domain.NetworkRegtest))
	if def != "localcore" {
		t.Fatalf("default = %q, want localcore", def)
	}

	// The stored refs are RAW (unresolved) so the service resolves them at dial.
	ep, err := s.GetEndpoint("localcore")
	if err != nil {
		t.Fatalf("GetEndpoint: %v", err)
	}
	if ep.RPCPassRef != "${env:DAXIB_RPCPASS}" {
		t.Fatalf("rpcpassword stored = %q, want the RAW ref", ep.RPCPassRef)
	}

	clearedFor, err := s.RemoveEndpoint(ctx, "localcore")
	if err != nil {
		t.Fatalf("RemoveEndpoint: %v", err)
	}
	if clearedFor != string(domain.NetworkRegtest) {
		t.Fatalf("clearedFor = %q, want regtest", clearedFor)
	}
	if def, _ := s.DefaultForNetwork(string(domain.NetworkRegtest)); def != "" {
		t.Fatalf("default after remove = %q, want empty", def)
	}
}

// TestAddDuplicate proves a duplicate name is backend.exists (exit 2).
func TestAddDuplicate(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ep := Endpoint{Network: "mainnet", Type: "esplora", URLRef: "https://mempool.space/api"}
	if _, err := s.AddEndpoint(ctx, "m", ep, false); err != nil {
		t.Fatalf("first add: %v", err)
	}
	_, err := s.AddEndpoint(ctx, "m", ep, false)
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != domain.CodeBackendExists {
		t.Fatalf("dup add err = %v, want backend.exists", err)
	}
}

// TestGetUnknown proves an unknown name is backend.not_found (exit 10).
func TestGetUnknown(t *testing.T) {
	s := newStore(t)
	_, err := s.GetEndpoint("nope")
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != domain.CodeBackendNotFound {
		t.Fatalf("err = %v, want backend.not_found", err)
	}
	if de.Exit != domain.ExitNotFound {
		t.Fatalf("exit = %d, want %d", de.Exit, domain.ExitNotFound)
	}
}

// TestResolveSecretRefs proves ${env:} resolution + the missing-var error +
// the literal/escape passthrough.
func TestResolveSecretRefs(t *testing.T) {
	env := map[string]string{"DAXIB_RPCPASS": "hunter2"}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }

	got, err := ResolveSecretRefs("${env:DAXIB_RPCPASS}", lookup)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != "hunter2" {
		t.Fatalf("resolved = %q, want hunter2", got)
	}

	// A missing var is secret.unresolved (exit 4 AUTH).
	_, err = ResolveSecretRefs("${env:DAXIB_MISSING}", lookup)
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != "secret.unresolved" {
		t.Fatalf("missing-var err = %v, want secret.unresolved", err)
	}
	if de.Exit != domain.ExitAuth {
		t.Fatalf("exit = %d, want %d (auth)", de.Exit, domain.ExitAuth)
	}

	// A plain literal passes through; the $${ escape becomes ${.
	if v, _ := ResolveSecretRefs("plain", lookup); v != "plain" {
		t.Fatalf("literal = %q, want plain", v)
	}
	if v, _ := ResolveSecretRefs("$${env:X}", lookup); v != "${env:X}" {
		t.Fatalf("escape = %q, want ${env:X}", v)
	}
}

// TestMaskKeepsRefDropsLiteral proves masking keeps a ${…} reference verbatim and
// reduces an embedded literal credential to "***".
func TestMaskKeepsRefDropsLiteral(t *testing.T) {
	if got := MaskSecretRefs("https://node/api?key=${env:KEY}"); got != "https://node/api?key=${env:KEY}" {
		t.Errorf("masking a ref changed it: %q", got)
	}
	got := MaskSecretRefs("https://node.example/v2/abcdef0123456789abcdef0123456789deadbeef")
	if got != "https://node.example/v2/***" {
		t.Errorf("literal secret not masked: %q", got)
	}
}

// TestMaskRedactsUserinfo is the SEC-2 regression: a literal user:pass@host
// credential must be redacted in the masked list/show output, in both the path and
// no-path cases — but a ${env:}/${file:} reference passes through verbatim (the
// reference is not the secret).
func TestMaskRedactsUserinfo(t *testing.T) {
	cases := map[string]string{
		"https://alice:hunter2@node.example/path": "https://alice:***@node.example/path",
		"https://alice:hunter2@node.example":      "https://alice:***@node.example",
		// A bare-password userinfo (no user) still redacts.
		"https://:onlypass@node.example/path": "https://:***@node.example/path",
		// An ${env:} reference in the URL stays verbatim (not a literal credential).
		"https://${env:USER}:${env:PASS}@node.example/path": "https://${env:USER}:${env:PASS}@node.example/path",
	}
	for in, want := range cases {
		if got := MaskSecretRefs(in); got != want {
			t.Errorf("MaskSecretRefs(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestRedactURLForErrorCollapsesLiteralKey is the SECLEAK-1 regression: the
// error-facing redactor must NEVER leak a literal embedded key, including the four
// low-entropy gap shapes that MaskSecretRefs' entropy heuristic lets through
// (lowercase-no-digit, < 24 chars, dash-separated, dot-containing). Each must
// collapse to scheme://host with no trace of the key. References stay verbatim.
func TestRedactURLForErrorCollapsesLiteralKey(t *testing.T) {
	leaks := map[string]string{ // url -> the key fragment that must NOT survive
		"https://eth-mainnet.g.alchemy.com/v2/myShortKey":         "myShortKey",
		"https://host.example/v2/dashed-api-key-value-here":       "dashed-api-key-value-here",
		"https://host.example/v2/a.b.c.dotcontaining.secretvalue": "dotcontaining",
		"https://host.example/v2/alllowercasenodigitsapikeyhere":  "alllowercasenodigitsapikeyhere",
		// A genuine high-entropy hex key must also collapse (it already did via ***,
		// but the error path now collapses the whole locator).
		"https://node.example/v2/abcdef0123456789abcdef0123456789deadbeef": "abcdef0123456789",
		// A literal user:pass@ userinfo credential.
		"https://alice:hunter2supersecret@node.example/v2/path": "hunter2supersecret",
		// A literal query-embedded key.
		"https://node.example/api?apikey=sk-live-lowercasenodigitkey": "sk-live-lowercasenodigitkey",
	}
	for in, key := range leaks {
		got := RedactURLForError(in)
		if strings.Contains(got, key) {
			t.Errorf("RedactURLForError(%q) leaked key fragment %q: %q", in, key, got)
		}
		if !strings.HasPrefix(got, "https://") {
			t.Errorf("RedactURLForError(%q) = %q, want scheme://host form", in, got)
		}
		// The host must survive (operators still need to know which backend). It is
		// the first /?#-delimited token after scheme://, sans userinfo.
		host := strings.TrimPrefix(in, "https://")
		if i := strings.IndexAny(host, "/?#"); i >= 0 {
			host = host[:i]
		}
		if at := strings.LastIndexByte(host, '@'); at >= 0 {
			host = host[at+1:]
		}
		if !strings.Contains(got, host) {
			t.Errorf("RedactURLForError(%q) = %q dropped the host %q", in, got, host)
		}
	}

	// References are NOT secrets: a tail that is purely ${env:}/${file:} refs (no
	// literal path/query/userinfo at all) stays verbatim so the operator can audit
	// which var/file is used. (A URL mixing a literal path word with a ref still
	// collapses — the safe direction — because a low-entropy literal key is
	// indistinguishable from a harmless path word, which is the very gap KNOWN-1
	// closes.)
	keepVerbatim := []string{
		"https://${env:USER}:${env:PASS}@node.example", // ref userinfo, no literal tail
		"https://node.example",                         // scheme://host only
		"127.0.0.1:8332",                               // host:port Core endpoint, no scheme
	}
	for _, in := range keepVerbatim {
		if got := RedactURLForError(in); got != in {
			t.Errorf("RedactURLForError(%q) altered a reference-only URL: %q", in, got)
		}
	}

	// A URL whose tail mixes harmless path words with a ${…} reference collapses to
	// scheme://host (safe over-collapse; the reference visibility is sacrificed
	// because a literal key cannot be told apart from a path word).
	if got := RedactURLForError("https://node/api?key=${env:KEY}"); got != "https://node" {
		t.Errorf("mixed literal+ref URL = %q, want https://node (safe collapse)", got)
	}

	// A host:port Core endpoint (no scheme) carries no path secret; userinfo still
	// masks via the friendly masker.
	if got := RedactURLForError("127.0.0.1:8332"); got != "127.0.0.1:8332" {
		t.Errorf("RedactURLForError(host:port) = %q, want verbatim", got)
	}
}

// TestRedactURLForErrorThroughDisplayURL is the SECLEAK-1 end-to-end regression: a
// literal key supplied as the backend DisplayURL (the error-path locator) must not
// appear in a backend error string nor its data["endpoint"]. It exercises the gap
// the prior tests missed — TestDial_Unreachable_DoesNotLeakSecret only covered the
// no-DisplayURL fallback, and TestMaskSecretRefs only the high-entropy hex case.
func TestRedactURLForErrorThroughDisplayURL(t *testing.T) {
	for _, key := range []string{
		"myShortKey", "dashed-api-key-value-here", "dotcontaining", "alllowercasenodigitsapikeyhere",
	} {
		disp := RedactURLForError("https://node.example/v2/" + key)
		if strings.Contains(disp, key) {
			t.Fatalf("DisplayURL for key %q still leaks: %q", key, disp)
		}
	}
}

// TestDetectLiteralSecretUserinfoWithPath is the SEC-3 regression: a userinfo
// credential must be flagged by the add-time heuristic whether or not the URL also
// has a path (the userinfo check used to only fire in the no-path branch).
func TestDetectLiteralSecretUserinfoWithPath(t *testing.T) {
	cases := []struct {
		url  string
		warn bool
	}{
		{"https://alice:hunter2@node.example/path", true},
		{"https://alice:hunter2@node.example", true},
		{"https://node.example/path", false},
		{"https://${env:USER}:${env:PASS}@node.example/path", false},
	}
	for _, tc := range cases {
		got := urlHasLiteralSecret(tc.url)
		if got != tc.warn {
			t.Errorf("urlHasLiteralSecret(%q) = %v, want %v", tc.url, got, tc.warn)
		}
	}
}

// TestAddLiteralSecretWarns proves a literal rpcpassword produces a warning (not a
// hard error) when strict is off.
func TestAddLiteralSecretWarns(t *testing.T) {
	s := newStore(t)
	warnings, err := s.AddEndpoint(context.Background(), "core1", Endpoint{
		Network: "regtest", Type: "core", URLRef: "http://127.0.0.1:18443",
		RPCPassRef: "literalpassword",
	}, false)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if len(warnings) == 0 {
		t.Fatal("expected a literal-secret warning")
	}
}

// TestAddLiteralSecretStrictFails proves --strict-secrets hard-fails on a literal.
func TestAddLiteralSecretStrictFails(t *testing.T) {
	s := newStore(t)
	_, err := s.AddEndpoint(context.Background(), "core1", Endpoint{
		Network: "regtest", Type: "core", URLRef: "http://127.0.0.1:18443",
		RPCPassRef: "literalpassword",
	}, true)
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != domain.CodeUsage+".literal_secret" {
		t.Fatalf("strict add err = %v, want usage.literal_secret", err)
	}
}
