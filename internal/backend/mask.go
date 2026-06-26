package backend

import (
	"net/url"
	"strings"
)

// mask.go is backend's fail-safe URL masker. The service composition root
// supplies Options.DisplayURL (the masked RAW config ref) for every command dial,
// so a ${env:…}/${file:…} reference is shown verbatim and a literal/resolved
// secret segment is reduced to "***". But Dial may be called with only a resolved
// URL and no DisplayURL (a test harness, an exploratory probe). Rather than risk
// leaking a resolved credential into an error message (§7.5), Options.displayURL()
// falls back to maskResolvedURL here. It operates on a fully-resolved URL (no
// ${…} references remain by the time backend sees one) and is intentionally
// self-contained — backend must not import the config store.

// maskResolvedURL reduces a RESOLVED URL to its credential-free locator —
// scheme://host[:port] only — for use in a user/log-facing error message. The
// path, query, fragment, and ANY userinfo (user:pass@) are dropped, because any
// of them may carry an embedded API key/password (KNOWN-1). This is deliberately
// conservative: an Alchemy-style ...//host/v2/<KEY>, a lowercase opaque token, or
// a user:pass@host credential all collapse to scheme://host, so no entropy
// heuristic can be evaded. A string with no "://" is returned unchanged (it is not
// a URL — e.g. a host:port Core endpoint already carries no secret path).
func maskResolvedURL(s string) string {
	if !strings.Contains(s, "://") {
		return s
	}
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		return u.Scheme + "://" + u.Host
	}
	// Fall back to a manual scheme://host cut when net/url cannot parse it (an
	// embedded credential with odd bytes). Never return more than scheme://host.
	schemeEnd := strings.Index(s, "://") + 3
	rel := s[schemeEnd:]
	host := rel
	if i := strings.IndexAny(rel, "/?#"); i >= 0 {
		host = rel[:i]
	}
	// Drop any userinfo (user:pass@host -> host).
	if at := strings.LastIndexByte(host, '@'); at >= 0 {
		host = host[at+1:]
	}
	return s[:schemeEnd] + host
}
