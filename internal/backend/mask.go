package backend

import "strings"

// mask.go is backend's fail-safe URL masker. The service composition root
// supplies Options.DisplayURL (the masked RAW config ref) for every command dial,
// so a ${env:…}/${file:…} reference is shown verbatim and a literal/resolved
// secret segment is reduced to "***". But Dial may be called with only a resolved
// URL and no DisplayURL (a test harness, an exploratory probe). Rather than risk
// leaking a resolved credential into an error message (§7.5), Options.displayURL()
// falls back to maskResolvedURL here. It operates on a fully-resolved URL (no
// ${…} references remain by the time backend sees one) and is intentionally
// self-contained — backend must not import the config store.

// maskResolvedURL reduces a long, opaque, high-entropy path/query segment of a
// RESOLVED URL (a likely embedded credential) to "***", leaving the scheme, host,
// and human-readable path words intact. A string with no "://" is returned
// unchanged.
func maskResolvedURL(s string) string {
	if !strings.Contains(s, "://") {
		return s
	}
	schemeEnd := strings.Index(s, "://") + 3
	hostRel := strings.IndexAny(s[schemeEnd:], "/?#")
	if hostRel < 0 {
		return s // scheme+host only, no path/query to mask
	}
	hostEnd := schemeEnd + hostRel
	head := s[:hostEnd]
	tail := s[hostEnd:]

	var out strings.Builder
	var seg strings.Builder
	flush := func() {
		token := seg.String()
		if looksLikeOpaqueSecret(token) {
			out.WriteString("***")
		} else {
			out.WriteString(token)
		}
		seg.Reset()
	}
	for i := 0; i < len(tail); i++ {
		c := tail[i]
		if c == '/' || c == '?' || c == '&' || c == '=' || c == '#' {
			flush()
			out.WriteByte(c)
			continue
		}
		seg.WriteByte(c)
	}
	flush()
	return head + out.String()
}

// looksLikeOpaqueSecret reports whether a single URL segment is a long,
// high-entropy token (a likely credential) rather than a human-readable path
// word. Conservative thresholds (>=24 chars, mixed alnum) so host names and short
// path words are untouched.
func looksLikeOpaqueSecret(seg string) bool {
	if len(seg) < 24 {
		return false
	}
	digits, letters, hasUpper := 0, 0, false
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		switch {
		case c >= '0' && c <= '9':
			digits++
		case c >= 'a' && c <= 'z':
			letters++
		case c >= 'A' && c <= 'Z':
			letters++
			hasUpper = true
		case c == '-' || c == '_':
		default:
			return false // a non-token char means it is not a single opaque secret
		}
	}
	return digits > 0 && letters > 0 && (hasUpper || digits >= 4)
}
