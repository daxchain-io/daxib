package config

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/fsx"
)

// secretref.go is config's secret-reference machinery (§7.5): masking for the
// list/show views, the add-time literal-secret heuristic, and the ONLY
// config-side resolver. The config file stores the REFERENCE, never the resolved
// secret; resolution happens in-memory at dial time (called by service), so the
// result lives only inside the caller's frame and is never written back.

// ── resolution (called by service at dial time) ───────────────────────────────

// ResolveSecretRefs expands a stored value that may embed placeholders, returning
// the resolved string. Grammar (§7.5):
//
//	${env:NAME}     -> value of env var NAME (missing => secret.unresolved)
//	${file:/abs}    -> file contents, one trailing newline stripped, perms checked
//	${file:~/rel}   -> ~ expands to the home dir, then as ${file:}
//	$${             -> a literal "${" (the escape)
//
// An unknown scheme is a hard error. lookupEnv is injected (os.LookupEnv in
// production) so resolution is unit-testable without touching the process env.
func ResolveSecretRefs(s string, lookupEnv func(string) (string, bool)) (string, error) {
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if strings.HasPrefix(s[i:], "$${") {
			b.WriteString("${")
			i += 3
			continue
		}
		if strings.HasPrefix(s[i:], "${") {
			end := strings.IndexByte(s[i:], '}')
			if end < 0 {
				return "", domain.Newf("secret.unresolved",
					"unterminated secret reference in %q (missing '}')", MaskSecretRefs(s))
			}
			inner := s[i+2 : i+end]
			resolved, err := resolveOneRef(inner, lookupEnv)
			if err != nil {
				return "", err
			}
			b.WriteString(resolved)
			i += end + 1
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String(), nil
}

func resolveOneRef(inner string, lookupEnv func(string) (string, bool)) (string, error) {
	scheme, arg, ok := strings.Cut(inner, ":")
	if !ok {
		return "", domain.Newf("secret.unresolved",
			"secret reference ${%s} has no scheme (expected ${env:…} or ${file:…})", inner)
	}
	switch scheme {
	case "env":
		if arg == "" {
			return "", domain.New("secret.unresolved", "${env:} requires a variable name")
		}
		v, present := lookupEnv(arg)
		if !present || v == "" {
			return "", domain.Newf("secret.unresolved",
				"environment variable %q referenced by ${env:%s} is not set", arg, arg)
		}
		return v, nil
	case "file":
		return resolveFileRef(arg)
	default:
		return "", domain.Newf("secret.unresolved",
			"unknown secret-reference scheme %q in ${%s} (only env, file are supported)", scheme, inner)
	}
}

func resolveFileRef(path string) (string, error) {
	if path == "" {
		return "", domain.New("secret.unresolved", "${file:} requires a path")
	}
	expanded, err := expandHome(path)
	if err != nil {
		return "", err
	}
	if err := fsx.CheckPerms(expanded); err != nil {
		return "", err
	}
	data, err := os.ReadFile(expanded) // #nosec G304 -- operator-supplied ${file:} secret-ref path, perms-checked above
	if err != nil {
		return "", domain.Wrap("secret.unresolved", "reading ${file:"+path+"}: "+err.Error(), err)
	}
	return stripOneTrailingNewline(string(data)), nil
}

func expandHome(path string) (string, error) {
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", domain.Wrap("secret.unresolved", "expanding ~ in ${file:"+path+"}: "+err.Error(), err)
		}
		if path == "~" {
			return home, nil
		}
		return filepath.Join(home, path[2:]), nil
	}
	return path, nil
}

func stripOneTrailingNewline(s string) string {
	if strings.HasSuffix(s, "\r\n") {
		return s[:len(s)-2]
	}
	if strings.HasSuffix(s, "\n") {
		return s[:len(s)-1]
	}
	return s
}

// ── masking (for list/show views) ─────────────────────────────────────────────

// MaskSecretRefs renders a stored value for the list/show views. A ${env:…}/
// ${file:…} REFERENCE is kept verbatim (the reference is not the secret — the
// operator must see WHICH var/file is used); any other long opaque segment that
// looks like an embedded literal secret is reduced to "***". The escape "$${" is
// preserved.
func MaskSecretRefs(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if strings.HasPrefix(s[i:], "$${") {
			b.WriteString("$${")
			i += 3
			continue
		}
		if strings.HasPrefix(s[i:], "${") {
			end := strings.IndexByte(s[i:], '}')
			if end < 0 {
				b.WriteString(s[i:])
				break
			}
			b.WriteString(s[i : i+end+1])
			i += end + 1
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return maskLiteralSegments(b.String())
}

// maskLiteralSegments replaces a long opaque token in a URL path/query (a likely
// embedded credential, no ${…}) with "***", AND redacts any literal userinfo
// credential (user:pass@host -> ***@host). Host names and short path words are
// untouched. A ${env:}/${file:} reference is never reached here (it passes through
// MaskSecretRefs verbatim) — only a LITERAL credential is redacted (KNOWN-1).
func maskLiteralSegments(s string) string {
	if !strings.Contains(s, "://") {
		return s
	}
	schemeEnd := strings.Index(s, "://") + 3
	rel := s[schemeEnd:]
	hostRel := strings.IndexAny(rel, "/?#")
	// Redact userinfo in the host portion FIRST, in both the path and no-path cases
	// (SEC-2). The host portion is rel up to the first '/?#' (or all of rel when
	// there is no path), and userinfo is everything before the LAST '@' in it.
	hostPart := rel
	if hostRel >= 0 {
		hostPart = rel[:hostRel]
	}
	if at := strings.LastIndexByte(hostPart, '@'); at >= 0 {
		// Keep the literal "${…}" userinfo verbatim (it is a reference, not a secret);
		// otherwise reduce a literal user:pass to ***.
		if !strings.Contains(hostPart[:at], "${") {
			masked := "***"
			if user, _, ok := strings.Cut(hostPart[:at], ":"); ok && !strings.Contains(user, "${") {
				masked = user + ":***"
			}
			newHost := masked + hostPart[at:]
			rel = newHost + rel[len(hostPart):]
			s = s[:schemeEnd] + rel
			// Recompute the boundary after the substitution.
			hostRel = strings.IndexAny(rel, "/?#")
		}
	}
	if hostRel < 0 {
		return s
	}
	hostEnd := schemeEnd + hostRel
	head := s[:hostEnd]
	tail := s[hostEnd:]
	var out strings.Builder
	var seg strings.Builder
	flush := func() {
		token := seg.String()
		if looksLikeLiteralSecret(token) {
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

// looksLikeLiteralSecret reports whether a single segment is a long, opaque,
// high-entropy token (a likely credential). It never flags a ${…} reference.
func looksLikeLiteralSecret(seg string) bool {
	if strings.Contains(seg, "${") {
		return false
	}
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
			return false
		}
	}
	return digits > 0 && letters > 0 && (hasUpper || digits >= 4)
}

// RedactURLForError renders a stored URL ref for an ERROR MESSAGE or log line —
// the UNCONDITIONAL form mandated by KNOWN-1. Unlike MaskSecretRefs (which uses an
// entropy heuristic suitable for the friendlier `backend list/show` views), this
// NEVER relies on a token looking high-entropy: any LITERAL path/query/fragment/
// userinfo content collapses the whole locator to scheme://host, so a low-entropy
// embedded key (lowercase-only, < 24 chars, dash- or dot-separated) cannot survive.
//
// A ${env:…}/${file:…} REFERENCE is not a secret, so a URL whose entire tail is
// references (e.g. https://node/api?key=${env:KEY}) is shown verbatim via
// MaskSecretRefs. The moment ANY literal credential-bearing segment is present, the
// safe direction wins and only scheme://host (plus a ${…} userinfo/host, if any) is
// shown. This is the redactor the service routes Options.DisplayURL through for the
// error path (service/backend.go); list/show keep MaskSecretRefs.
func RedactURLForError(s string) string {
	if !strings.Contains(s, "://") {
		// Not a URL (e.g. a host:port Core endpoint) — no embedded path/query secret.
		// Still mask any literal userinfo / opaque token via the friendly masker.
		return MaskSecretRefs(s)
	}
	if !urlTailHasLiteral(s) {
		// The tail is pure structure + ${…} references (or empty): safe to show
		// verbatim (references are not secrets).
		return MaskSecretRefs(s)
	}
	return collapseToSchemeHost(s)
}

// urlTailHasLiteral reports whether a URL carries ANY literal (non-${…}) content in
// its userinfo, path, query, or fragment — i.e. anything past scheme://host that is
// not a structural separator and not a ${env:}/${file:} reference. scheme://host
// alone (no tail) is literal-free.
func urlTailHasLiteral(s string) bool {
	schemeEnd := strings.Index(s, "://") + 3
	rel := s[schemeEnd:]
	hostRel := strings.IndexAny(rel, "/?#")
	hostPart := rel
	tail := ""
	if hostRel >= 0 {
		hostPart = rel[:hostRel]
		tail = rel[hostRel:]
	}
	// Userinfo: a literal user[:pass]@ is a credential.
	if at := strings.LastIndexByte(hostPart, '@'); at >= 0 {
		if segmentHasLiteral(hostPart[:at]) {
			return true
		}
	}
	// Path / query / fragment: split on structural separators; any non-empty,
	// non-reference segment is literal credential-bearing content.
	for _, seg := range strings.FieldsFunc(tail, func(r rune) bool {
		return r == '/' || r == '?' || r == '&' || r == '=' || r == '#'
	}) {
		if segmentHasLiteral(seg) {
			return true
		}
	}
	return false
}

// segmentHasLiteral reports whether a URL segment contains literal (non-reference)
// characters. A segment that is wholly one or more ${…} references (possibly joined
// by reference-internal text) is treated as reference-only. Any other non-empty
// segment counts as literal.
func segmentHasLiteral(seg string) bool {
	if seg == "" {
		return false
	}
	if !strings.Contains(seg, "${") {
		return true
	}
	// Strip every ${…} reference; if anything non-trivial remains, it is literal.
	rest := seg
	for {
		open := strings.Index(rest, "${")
		if open < 0 {
			break
		}
		close := strings.IndexByte(rest[open:], '}')
		if close < 0 {
			break // malformed; treat the remainder as literal below
		}
		rest = rest[:open] + rest[open+close+1:]
	}
	return strings.TrimSpace(rest) != ""
}

// collapseToSchemeHost reduces a URL to scheme://host, preserving a ${…} userinfo
// or ${…} host reference verbatim (a reference is not a secret) but dropping every
// literal credential-bearing part. It mirrors backend.maskResolvedURL's contract on
// the config side so the error path never sees a literal path/query/userinfo.
func collapseToSchemeHost(s string) string {
	schemeEnd := strings.Index(s, "://") + 3
	rel := s[schemeEnd:]
	host := rel
	if i := strings.IndexAny(rel, "/?#"); i >= 0 {
		host = rel[:i]
	}
	// Keep a ${…} userinfo reference; drop a literal user:pass@.
	if at := strings.LastIndexByte(host, '@'); at >= 0 {
		if strings.Contains(host[:at], "${") {
			// reference userinfo — keep it
		} else {
			host = host[at+1:]
		}
	}
	return s[:schemeEnd] + host
}

// ── the add-time literal-secret heuristic ─────────────────────────────────────

// detectLiteralSecret returns human-readable locations where an endpoint embeds a
// LITERAL secret rather than a ${env:}/${file:} reference, so `backend add` can
// warn (or hard-fail under --strict-secrets). A value already using a reference is
// never flagged. The Core rpcpassword is the highest-risk field.
func detectLiteralSecret(e Endpoint) []string {
	var hits []string
	if urlHasLiteralSecret(e.URLRef) {
		hits = append(hits, "the URL")
	}
	// rpcpassword carrying a non-reference, non-empty value is a literal secret.
	if e.RPCPassRef != "" && !strings.Contains(e.RPCPassRef, "${") {
		hits = append(hits, "rpcpassword")
	}
	sort.Strings(hits)
	return hits
}

func urlHasLiteralSecret(url string) bool {
	if strings.Contains(url, "${") {
		return false
	}
	if !strings.Contains(url, "://") {
		return false
	}
	schemeEnd := strings.Index(url, "://") + 3
	rel := url[schemeEnd:]
	hostEnd := strings.IndexAny(rel, "/?#")

	// Check userinfo UNCONDITIONALLY (SEC-3): a user:pass@host credential is a
	// literal secret whether or not the URL also has a path. The host portion is rel
	// up to the first '/?#', or all of rel when there is no path; userinfo is
	// everything before the LAST '@' in it, and a non-empty password after ':' (or
	// any non-empty userinfo) is the credential.
	hostPart := rel
	if hostEnd >= 0 {
		hostPart = rel[:hostEnd]
	}
	if at := strings.LastIndexByte(hostPart, '@'); at >= 0 {
		if _, pass, ok := strings.Cut(hostPart[:at], ":"); ok && pass != "" {
			return true
		}
	}

	if hostEnd < 0 {
		return false
	}
	for _, seg := range strings.FieldsFunc(rel[hostEnd:], func(r rune) bool {
		return r == '/' || r == '?' || r == '&' || r == '=' || r == '#'
	}) {
		if looksLikeLiteralSecret(seg) {
			return true
		}
	}
	return false
}
