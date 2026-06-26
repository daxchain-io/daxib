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
// embedded credential, no ${…}) with "***". Host names and short path words are
// untouched.
func maskLiteralSegments(s string) string {
	if !strings.Contains(s, "://") {
		return s
	}
	schemeEnd := strings.Index(s, "://") + 3
	rel := s[schemeEnd:]
	hostRel := strings.IndexAny(rel, "/?#")
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
	if hostEnd < 0 {
		// userinfo credential (user:pass@host)?
		if at := strings.IndexByte(rel, '@'); at >= 0 {
			if _, pass, ok := strings.Cut(rel[:at], ":"); ok && pass != "" {
				return true
			}
		}
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
