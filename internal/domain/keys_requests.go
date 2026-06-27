package domain

// This file is the wire contract for the M2 keys surface: the request and result
// structs the cli/mcp frontends pass to (and receive from) the service for the
// wallet and address commands. They mirror daxie's keys_requests.go shapes,
// swapping Ethereum 0x-addresses for Bitcoin bech32 addresses and BIP-44 for
// BIP-84. No struct here holds a float; secrets are carried as separate
// *secret.Bytes outside the wire types (see service inputs), never serialized.

// ── wallet create ──────────────────────────────────────────────────────────

// WalletCreateRequest is the wire input for `wallet create`.
type WalletCreateRequest struct {
	Name    string  `json:"name"`
	Words   int     `json:"words,omitempty"` // 12 or 24; 0 => default (12)
	Network Network `json:"network"`         // display hint (agnostic) or lock target (bound)
	Bind    bool    `json:"bind,omitempty"`  // true => bound (locked) wallet; default agnostic
	Yes     bool    `json:"-"`               // frontend confirmation flag; not serialized
}

// WalletCreateResult is the wire output for `wallet create`. The mnemonic is
// shown ONCE: when present, Sensitive is true and the frontend must redact it
// from any later echo/log.
type WalletCreateResult struct {
	Name             string  `json:"name"`
	WalletID         string  `json:"wallet_id"`
	Scope            string  `json:"scope"`            // "agnostic" or "bound"
	Network          Network `json:"network"`          // displayed coin_type's network
	PathPrefix       string  `json:"path_prefix"`      // e.g. "m/84'/0'/0'"
	Receive0         string  `json:"receive0"`         // "<name>/0/0"
	Receive0Address  string  `json:"receive0_address"` // first receive bech32 address
	AccountXpub      string  `json:"account_xpub"`     // neutered account-level xpub
	Mnemonic         string  `json:"mnemonic,omitempty"`
	BIP39Passphrase  string  `json:"bip39_passphrase,omitempty"`
	Sensitive        bool    `json:"sensitive"`
	PassphraseFinger string  `json:"passphrase_fingerprint,omitempty"` // first-init only
}

// ── wallet import ──────────────────────────────────────────────────────────

// WalletImportRequest is the wire input for `wallet import`. The mnemonic itself
// never travels in this struct — it arrives via stdin/file (a *secret.Bytes the
// service acquires), never a flag value.
type WalletImportRequest struct {
	Name    string  `json:"name"`
	Network Network `json:"network"`        // display hint (agnostic) or lock target (bound)
	Bind    bool    `json:"bind,omitempty"` // true => bound (locked) wallet; default agnostic
	Yes     bool    `json:"-"`
}

// WalletImportResult is the wire output for `wallet import`.
type WalletImportResult struct {
	Name            string  `json:"name"`
	WalletID        string  `json:"wallet_id"`
	Scope           string  `json:"scope"`
	Network         Network `json:"network"`
	PathPrefix      string  `json:"path_prefix"`
	Receive0        string  `json:"receive0"`
	Receive0Address string  `json:"receive0_address"`
	AccountXpub     string  `json:"account_xpub"`
}

// ── wallet list / show ─────────────────────────────────────────────────────

// WalletListRequest is the wire input for `wallet list` (no fields yet).
type WalletListRequest struct{}

// WalletSummary is one row of `wallet list`.
type WalletSummary struct {
	Name      string  `json:"name"`
	WalletID  string  `json:"wallet_id"`
	Scope     string  `json:"scope"`     // "agnostic" or "bound"
	Network   Network `json:"network"`   // effective network (bound network, else active)
	CoinType  uint32  `json:"coin_type"` // active coin_type in view
	Addresses int     `json:"addresses"`
	Default   bool    `json:"default,omitempty"`
	CreatedAt string  `json:"created_at"`
}

// WalletListResult is the wire output for `wallet list`.
type WalletListResult struct {
	Wallets []WalletSummary `json:"wallets"`
	Default string          `json:"default,omitempty"`
}

// WalletShowRequest is the wire input for `wallet show <name>`.
type WalletShowRequest struct {
	Name string `json:"name"`
}

// WalletShowResult is the wire output for `wallet show`.
type WalletShowResult struct {
	Name        string  `json:"name"`
	WalletID    string  `json:"wallet_id"`
	Scope       string  `json:"scope"`     // "agnostic" or "bound"
	Network     Network `json:"network"`   // effective network (bound network, else active)
	CoinType    uint32  `json:"coin_type"` // active coin_type in view
	PathPrefix  string  `json:"path_prefix"`
	AccountXpub string  `json:"account_xpub"`
	NextReceive uint32  `json:"next_receive"`
	NextChange  uint32  `json:"next_change"`
	Addresses   int     `json:"addresses"`
	Default     bool    `json:"default"`
	CreatedAt   string  `json:"created_at"`
}

// ── wallet export ──────────────────────────────────────────────────────────

// WalletExportRequest is the wire input for `wallet export <name>`.
type WalletExportRequest struct {
	Name string `json:"name"`
	Yes  bool   `json:"-"`
}

// WalletExportResult is the wire output for `wallet export`. The mnemonic +
// bip39_passphrase are always sensitive.
type WalletExportResult struct {
	Name            string `json:"name"`
	WalletID        string `json:"wallet_id"`
	Mnemonic        string `json:"mnemonic"`
	BIP39Passphrase string `json:"bip39_passphrase,omitempty"`
	Sensitive       bool   `json:"sensitive"`
}

// ── wallet upgrade ─────────────────────────────────────────────────────────

// WalletUpgradeRequest is the wire input for `wallet upgrade <name>` (promote a
// bound/legacy wallet to network-agnostic).
type WalletUpgradeRequest struct {
	Name string `json:"name"`
	Yes  bool   `json:"-"`
}

// WalletUpgradeResult is the wire output for `wallet upgrade`.
type WalletUpgradeResult struct {
	Name      string  `json:"name"`
	WalletID  string  `json:"wallet_id"`
	Scope     string  `json:"scope"` // "agnostic" after upgrade
	Network   Network `json:"network"`
	CoinType  uint32  `json:"coin_type"`
	Addresses int     `json:"addresses"`
}

// ── address new ────────────────────────────────────────────────────────────

// AddressNewRequest is the wire input for `address new`. Change selects the
// internal (branch 1) chain; default is receive (branch 0).
type AddressNewRequest struct {
	Wallet string `json:"wallet"`
	Change bool   `json:"change,omitempty"`
}

// AddressNewResult is the wire output for `address new`.
type AddressNewResult struct {
	Wallet  string `json:"wallet"`
	Ref     string `json:"ref"`    // "<wallet>/<branch>/<index>"
	Branch  uint32 `json:"branch"` // 0 receive, 1 change
	Index   uint32 `json:"index"`
	Address string `json:"address"` // bech32
	Path    string `json:"path"`    // full BIP-84 path
}

// ── address list ───────────────────────────────────────────────────────────

// AddressListRequest is the wire input for `address list`.
type AddressListRequest struct {
	Wallet string `json:"wallet"`
}

// AddressSummary is one row of `address list`.
type AddressSummary struct {
	Ref       string `json:"ref"`
	Branch    uint32 `json:"branch"`
	Index     uint32 `json:"index"`
	Address   string `json:"address"`
	CreatedAt string `json:"created_at"`
}

// AddressListResult is the wire output for `address list`.
type AddressListResult struct {
	Wallet    string           `json:"wallet"`
	Network   Network          `json:"network"`
	Addresses []AddressSummary `json:"addresses"`
}
