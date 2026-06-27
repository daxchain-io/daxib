package domain

// contacts_requests.go is the wire contract for the `daxib contacts` noun (the
// local address book) and the `tx send --to` / `policy allow` name resolution it
// backs. A contact maps a name to a (network-specific) Bitcoin address; any
// destination position that accepts a raw address ALSO accepts a contact name,
// resolved to its pinned address by the service. Triple-duty (CLI flags, MCP
// schema, in-process call); no float anywhere.

// ContactView is one address-book entry as the frontends render it. It mirrors the
// contacts store's Contact so the cli never imports the contacts provider (the
// arch matrix forbids frontend→provider): the service re-exports this shape.
type ContactView struct {
	Name      string `json:"name"`
	Address   string `json:"address"`
	Network   string `json:"network,omitempty"`
	Label     string `json:"label,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
}

// ContactAddRequest adds a name→address contact. The address is bech32/for-network
// validated against the active network at add time and pinned as a snapshot; the
// name follows the wallet-name grammar. A duplicate name is a usage error (exit 2).
type ContactAddRequest struct {
	Name    string `json:"name" jsonschema:"contact name (1-64 chars [a-z0-9_-])"`
	Address string `json:"address" jsonschema:"a Bitcoin address valid for the active network"`
	Label   string `json:"label,omitempty" jsonschema:"optional operator note stored with the contact"`
}

// ContactAddResult echoes the stored contact.
type ContactAddResult struct {
	Contact ContactView `json:"contact"`
}

// ContactListRequest lists every contact (name-sorted). No filters in v1.
type ContactListRequest struct{}

// ContactListResult is the name-sorted address book.
type ContactListResult struct {
	Contacts []ContactView `json:"contacts"`
}

// ContactShowRequest shows one contact by name.
type ContactShowRequest struct {
	Name string `json:"name" jsonschema:"the contact name to show"`
}

// ContactShowResult carries the one resolved contact.
type ContactShowResult struct {
	Contact ContactView `json:"contact"`
}

// ContactRemoveRequest removes one contact by name (ref.not_found if unknown).
type ContactRemoveRequest struct {
	Name string `json:"name" jsonschema:"the contact name to remove"`
}

// ContactRemoveResult echoes the removed name.
type ContactRemoveResult struct {
	Name string `json:"name"`
}
