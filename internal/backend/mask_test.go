package backend

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/daxchain-io/daxib/internal/domain"
)

// TestMaskResolvedURL proves a long opaque path segment (a likely credential) is
// reduced to "***" while scheme/host/short path words survive.
func TestMaskResolvedURL(t *testing.T) {
	cases := map[string]string{
		"http://127.0.0.1:8332":    "http://127.0.0.1:8332",
		"https://node.example/api": "https://node.example/api",
		"https://node.example/v2/abcdef0123456789abcdef0123456789deadbeef": "https://node.example/v2/***",
	}
	for in, want := range cases {
		if got := maskResolvedURL(in); got != want {
			t.Errorf("maskResolvedURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestDial_Unreachable_DoesNotLeakSecret proves the §7.5 contract: an embedded
// credential in the resolved URL never appears in the unreachable error, even
// without a service-supplied DisplayURL (backend's own fallback masking).
func TestDial_Unreachable_DoesNotLeakSecret(t *testing.T) {
	srv := httptest.NewServer(nil)
	base := srv.URL
	srv.Close()

	const secret = "abcdef0123456789abcdef0123456789deadbeef"
	_, err := Dial(context.Background(), Options{
		Type:    domain.BackendEsplora,
		URL:     base + "/v2/" + secret,
		Network: domain.NetworkMainnet,
		Timeout: secondsTimeout,
	})
	if err == nil {
		t.Fatal("expected an unreachable error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked the secret: %v", err)
	}
	var de *domain.Error
	if errors.As(err, &de) {
		if ep, _ := de.Data["endpoint"].(string); strings.Contains(ep, secret) {
			t.Fatalf("data.endpoint leaked the secret: %q", ep)
		}
	}
}
