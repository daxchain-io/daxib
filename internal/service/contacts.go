package service

import (
	"context"

	"github.com/btcsuite/btcd/btcutil"

	"github.com/daxchain-io/daxib/internal/contacts"
	"github.com/daxchain-io/daxib/internal/domain"
)

// contacts.go is the service-side address-book composition root: the thin use
// cases backing `daxib contacts add|list|show|remove`, plus resolveDestination —
// the ONE place a `tx send --to` / `policy allow` name is mapped to a pinned
// address. service is the only layer that legally knows BOTH the contacts store
// (a provider leaf) and the active network's chain params (for bech32 validation),
// so the address is validated HERE on add and the name→address resolution lives
// HERE so the CLI and the MCP surfaces share one rule.

// ContactAdd validates the address for the active network (a bad address is a
// usage error, exit 2), then pins the name→address entry under the registry lock.
// A duplicate name is usage.duplicate (exit 2).
func (s *Service) ContactAdd(ctx context.Context, req domain.ContactAddRequest) (domain.ContactAddResult, error) {
	if err := s.validateAddress(req.Address); err != nil {
		return domain.ContactAddResult{}, err
	}
	// Refuse a NAME that itself parses as a valid address for the active network: a
	// contact whose name collides with the raw-address space could otherwise shadow a
	// literal `--to <addr>` and silently redirect funds (CONTACT-RESOLVE-SHADOW-1).
	// The registry must never hold such a name; resolveDestination also guards on read.
	if s.addressForNet(req.Name) {
		return domain.ContactAddResult{}, domain.Newf(domain.CodeUsage+".bad_name",
			"contact name %q is a valid %s address; choose a name, not an address", req.Name, s.net)
	}
	c, err := s.contacts.Add(ctx, contacts.Contact{
		Name:      req.Name,
		Address:   req.Address,
		Network:   string(s.net),
		Label:     req.Label,
		CreatedAt: s.clock().UTC().Format("2006-01-02T15:04:05Z07:00"),
	})
	if err != nil {
		return domain.ContactAddResult{}, err
	}
	return domain.ContactAddResult{Contact: contactView(c)}, nil
}

// ContactList returns the name-sorted address book.
func (s *Service) ContactList(ctx context.Context, _ domain.ContactListRequest) (domain.ContactListResult, error) {
	list, err := s.contacts.List(ctx)
	if err != nil {
		return domain.ContactListResult{}, err
	}
	out := domain.ContactListResult{Contacts: make([]domain.ContactView, 0, len(list))}
	for _, c := range list {
		out.Contacts = append(out.Contacts, contactView(c))
	}
	return out, nil
}

// ContactShow returns one contact by name (ref.not_found if unknown, exit 10).
func (s *Service) ContactShow(ctx context.Context, req domain.ContactShowRequest) (domain.ContactShowResult, error) {
	c, err := s.contacts.Show(ctx, req.Name)
	if err != nil {
		return domain.ContactShowResult{}, err
	}
	return domain.ContactShowResult{Contact: contactView(c)}, nil
}

// ContactRemove deletes one contact by name (ref.not_found if unknown, exit 10).
func (s *Service) ContactRemove(ctx context.Context, req domain.ContactRemoveRequest) (domain.ContactRemoveResult, error) {
	c, err := s.contacts.Remove(ctx, req.Name)
	if err != nil {
		return domain.ContactRemoveResult{}, err
	}
	return domain.ContactRemoveResult{Name: c.Name}, nil
}

// resolveDestination maps a `--to` / `policy allow` value to a raw Bitcoin
// address. Resolution order: try the value as a CONTACT name first; if a contact
// matches, return its pinned address (network-guarded — a contact pinned to a
// different network than the active one is refused rather than silently used);
// otherwise return the value unchanged (a raw address, validated downstream). A
// not-a-contact value falls through cleanly so every existing raw-address caller
// is unaffected. A nil contacts store (never the case in production) falls through.
func (s *Service) resolveDestination(ctx context.Context, dest string) (string, error) {
	// A literal valid address for the active network ALWAYS wins: never let a contact
	// whose name happens to equal a raw bech32 address shadow it (CONTACT-RESOLVE-
	// SHADOW-1 — a fund-redirection / policy-allow corruption hazard). Belt-and-
	// suspenders with the `contacts add` name-rejection above.
	if s.addressForNet(dest) {
		return dest, nil
	}
	if s.contacts == nil {
		return dest, nil
	}
	c, found, err := s.contacts.Resolve(ctx, dest)
	if err != nil {
		return "", err
	}
	if !found {
		return dest, nil
	}
	if c.Network != "" && c.Network != string(s.net) {
		return "", domain.Newf(domain.CodeUsageBadAddress,
			"contact %q is for network %q but the active network is %q; pass --network %s",
			c.Name, c.Network, s.net, c.Network)
	}
	return c.Address, nil
}

// addressForNet reports whether dest decodes as a valid address for the active
// network. It is the single predicate guarding the raw-address-wins rule in
// resolveDestination and the address-shaped-name rejection in ContactAdd.
func (s *Service) addressForNet(dest string) bool {
	params := s.chainParams()
	a, err := btcutil.DecodeAddress(dest, params)
	return err == nil && a.IsForNet(params)
}

// contactView maps a stored Contact to the wire view (the cli never imports the
// contacts provider, so the service re-exports the shape).
func contactView(c contacts.Contact) domain.ContactView {
	return domain.ContactView{
		Name:      c.Name,
		Address:   c.Address,
		Network:   c.Network,
		Label:     c.Label,
		CreatedAt: c.CreatedAt,
	}
}
