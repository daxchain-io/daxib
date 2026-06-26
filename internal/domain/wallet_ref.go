package domain

import "strings"

// Bitcoin wallets in daxib are named HD wallets bound to a network at creation
// (§3.5). Unlike daxie's Ethereum account refs (which carry ENS names and raw
// 0x-addresses as first-class read-only shapes), daxib v1 addresses out of a
// keystore are always derived bech32 P2WPKH addresses keyed by branch/index, so
// the only user-facing "ref" is the wallet NAME plus an optional branch/index.
// This file mirrors daxie's account_ref.go parsing/validation idiom, swapping the
// Ethereum-specific shapes for Bitcoin's (name + receive/change branch + index).

// maxWalletNameLen bounds a wallet name (mirrors daxie's maxNameLen).
const maxWalletNameLen = 64

// Branch is the BIP-44/84 chain (change) level: 0 = external/receive, 1 =
// internal/change.
type Branch uint32

const (
	// BranchReceive is the external chain (branch 0): addresses handed out to
	// payers.
	BranchReceive Branch = 0
	// BranchChange is the internal chain (branch 1): change addresses.
	BranchChange Branch = 1
)

// String renders the branch as its on-path number ("0" / "1").
func (b Branch) String() string {
	if b == BranchChange {
		return "1"
	}
	return "0"
}

// ValidWalletName reports whether s is a well-formed wallet name: 1..64 chars,
// first char [a-z0-9], remaining [a-z0-9_-]. This is the same conservative
// grammar daxie applies to wallet/account names (§3.1) — lowercased so a
// wallet name never collides with an address/path separator and is safe in a
// filename. It deliberately rejects '/', '.', and '#', which are reference
// separators.
func ValidWalletName(s string) bool {
	if s == "" || len(s) > maxWalletNameLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case i > 0 && (c == '-' || c == '_'):
		default:
			return false
		}
	}
	return true
}

// AddressKey is the canonical meta.json key for a derived address: "<branch>/<index>"
// in decimal with no leading zeros, e.g. "0/0", "1/3". It is the Bitcoin analog of
// daxie's decimal-index account key.
func AddressKey(branch Branch, index uint32) string {
	return branch.String() + "/" + utoa32(index)
}

// IndexString renders a uint32 derivation index (or coin type) as canonical
// decimal with no leading zeros. Exported so the keys provider can render BIP-84
// path segments without importing strconv.
func IndexString(n uint32) string { return utoa32(n) }

// utoa32 is a tiny dependency-free uint32->decimal (domain holds no strconv on
// its hot paths, mirroring the exitcode itoa).
func utoa32(n uint32) string {
	if n == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// looksLikeAddressKey reports whether s is a canonical "<branch>/<index>" address
// key. Used by the keystore's watermark check to parse materialized keys.
func looksLikeAddressKey(s string) bool {
	i := strings.IndexByte(s, '/')
	if i <= 0 || i == len(s)-1 {
		return false
	}
	return isDecimal(s[:i]) && isDecimal(s[i+1:])
}

func isDecimal(s string) bool {
	if s == "" {
		return false
	}
	if len(s) > 1 && s[0] == '0' {
		return false // no leading zeros beyond a lone "0"
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
