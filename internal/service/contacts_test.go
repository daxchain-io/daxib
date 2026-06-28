package service

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/wire"

	fakebackend "github.com/daxchain-io/daxib/internal/backend/fake"
	"github.com/daxchain-io/daxib/internal/contacts"
	"github.com/daxchain-io/daxib/internal/domain"
)

// contactRecipient is a known external P2WPKH address used as a contact target.
const contactRecipient = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"

// TestContactAddListShowRemove is the registry round-trip: add → show → list →
// remove, plus the duplicate-name + bad-address + unknown-name error paths.
func TestContactAddListShowRemove(t *testing.T) {
	svc, done := newSendService(t, fakebackend.New())
	defer done()
	ctx := context.Background()

	if _, err := svc.ContactAdd(ctx, domain.LocalCLI(), domain.ContactAddRequest{Name: "alice", Address: contactRecipient, Label: "friend"}); err != nil {
		t.Fatalf("ContactAdd: %v", err)
	}

	// Duplicate name is a usage error.
	if _, err := svc.ContactAdd(ctx, domain.LocalCLI(), domain.ContactAddRequest{Name: "alice", Address: contactRecipient}); err == nil {
		t.Fatal("ContactAdd duplicate: want error, got nil")
	} else if de := domain.AsError(err); de.Exit != domain.ExitUsage {
		t.Errorf("duplicate exit=%d; want %d (usage)", de.Exit, domain.ExitUsage)
	}

	// A bad address for the active network is a usage error.
	if _, err := svc.ContactAdd(ctx, domain.LocalCLI(), domain.ContactAddRequest{Name: "bob", Address: "not-an-address"}); err == nil {
		t.Fatal("ContactAdd bad address: want error, got nil")
	} else if de := domain.AsError(err); de.Exit != domain.ExitUsage {
		t.Errorf("bad-address exit=%d; want %d (usage)", de.Exit, domain.ExitUsage)
	}

	show, err := svc.ContactShow(ctx, domain.LocalCLI(), domain.ContactShowRequest{Name: "ALICE"}) // case-insensitive
	if err != nil {
		t.Fatalf("ContactShow: %v", err)
	}
	if show.Contact.Address != contactRecipient || show.Contact.Network != "mainnet" || show.Contact.Label != "friend" {
		t.Errorf("show = %+v; want addr/network/label populated", show.Contact)
	}

	list, err := svc.ContactList(ctx, domain.LocalCLI(), domain.ContactListRequest{})
	if err != nil {
		t.Fatalf("ContactList: %v", err)
	}
	if len(list.Contacts) != 1 || list.Contacts[0].Name != "alice" {
		t.Fatalf("list = %+v; want [alice]", list.Contacts)
	}

	if _, err := svc.ContactRemove(ctx, domain.LocalCLI(), domain.ContactRemoveRequest{Name: "alice"}); err != nil {
		t.Fatalf("ContactRemove: %v", err)
	}
	// Now show/remove of the gone name is ref.not_found (exit 10).
	if _, err := svc.ContactShow(ctx, domain.LocalCLI(), domain.ContactShowRequest{Name: "alice"}); err == nil {
		t.Fatal("ContactShow after remove: want not_found, got nil")
	} else if de := domain.AsError(err); de.Exit != domain.ExitNotFound {
		t.Errorf("not-found exit=%d; want %d", de.Exit, domain.ExitNotFound)
	}
}

// TestContactAddressShapedNameRejected proves CONTACT-RESOLVE-SHADOW-1's add-side
// guard: a contact NAME that itself parses as a valid address for the active network
// is refused (usage error), so the registry can never hold a name colliding with the
// raw-address space.
func TestContactAddressShapedNameRejected(t *testing.T) {
	svc, done := newSendService(t, fakebackend.New())
	defer done()
	ctx := context.Background()

	// The NAME is a valid mainnet P2WPKH address; the target is a different address.
	if _, err := svc.ContactAdd(ctx, domain.LocalCLI(), domain.ContactAddRequest{Name: contactRecipient, Address: canonicalReceive1}); err == nil {
		t.Fatal("ContactAdd accepted an address-shaped name (CONTACT-RESOLVE-SHADOW-1)")
	} else if de := domain.AsError(err); de.Exit != domain.ExitUsage {
		t.Errorf("address-shaped-name exit=%d; want %d (usage)", de.Exit, domain.ExitUsage)
	}
}

// TestContactCannotShadowRawAddress is THE CONTACT-RESOLVE-SHADOW-1 regression: even
// if a contact whose NAME equals a valid raw address somehow exists in the registry
// (planted directly here, bypassing the add-side guard), a literal `--to <address>`
// / `policy allow <address>` resolves to the ADDRESS ITSELF — never the contact's
// (potentially attacker-controlled) redirect target.
func TestContactCannotShadowRawAddress(t *testing.T) {
	svc, done := newSendService(t, fakebackend.New())
	defer done()
	ctx := context.Background()

	// Plant a hostile collision directly in the store: a contact NAMED after a valid
	// address but pinned to a DIFFERENT address (the redirect target). This bypasses
	// ContactAdd's name guard to prove resolveDestination's raw-address-wins guard
	// independently (belt-and-suspenders).
	if _, err := svc.contacts.Add(ctx, contacts.Contact{
		Name:    contactRecipient,  // a valid mainnet address used as the name
		Address: canonicalReceive1, // the (different) redirect the contact would force
		Network: string(svc.net),
	}); err != nil {
		t.Fatalf("planting the colliding contact: %v", err)
	}

	// A literal valid address in the --to / allow position must resolve to ITSELF.
	got, err := svc.resolveDestination(ctx, contactRecipient)
	if err != nil {
		t.Fatalf("resolveDestination(%q): %v", contactRecipient, err)
	}
	if got != contactRecipient {
		t.Fatalf("resolveDestination(%q) = %q; want the literal address (the contact must NOT shadow it)", contactRecipient, got)
	}
	if got == canonicalReceive1 {
		t.Fatal("FUND REDIRECTION: the literal address resolved to the contact's redirect target")
	}
}

// TestContactResolvesInSend is THE resolution proof: a `tx send --to <contact>`
// resolves the contact name to its pinned address and the broadcast tx pays THAT
// address — identical to a raw-address send.
func TestContactResolvesInSend(t *testing.T) {
	fake := fakebackend.New()
	var captured []byte
	captureBroadcast(fake, &captured)
	fake.Tip = 800000
	svc, done := newSendService(t, fake)
	defer done()
	ctx := context.Background()

	if _, err := svc.ContactAdd(ctx, domain.LocalCLI(), domain.ContactAddRequest{Name: "payee", Address: contactRecipient}); err != nil {
		t.Fatalf("ContactAdd: %v", err)
	}
	programUTXO(fake, canonicalReceive0, "11"+strings.Repeat("0", 62), 0, 1_000_000)

	// Send to the CONTACT NAME, not a raw address.
	res, err := svc.SendTx(ctx, domain.LocalCLI(), domain.SendRequest{
		Wallet: "vec", To: "payee", Amount: "0.005", FeeRate: "10", Yes: true,
	}, nil)
	if err != nil {
		t.Fatalf("SendTx --to payee: %v", err)
	}
	if res.Txid == "" {
		t.Fatal("no txid; the contact-named send did not broadcast")
	}

	tx := wire.NewMsgTx(2)
	if err := tx.Deserialize(bytes.NewReader(captured)); err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	recipScript := scriptOf(t, contactRecipient)
	var paidContact bool
	for _, o := range tx.TxOut {
		if bytes.Equal(o.PkScript, recipScript) && o.Value == 500_000 {
			paidContact = true
		}
	}
	if !paidContact {
		t.Fatalf("the broadcast tx does not pay the contact's address %s", contactRecipient)
	}

	// A raw address in --to still works unchanged (the fall-through path).
	programUTXO(fake, canonicalReceive0, "22"+strings.Repeat("0", 62), 1, 1_000_000)
	if _, err := svc.SendTx(ctx, domain.LocalCLI(), domain.SendRequest{
		Wallet: "vec", To: contactRecipient, Amount: "0.005", FeeRate: "10", Yes: true,
	}, nil); err != nil {
		t.Fatalf("SendTx --to <raw address> regressed: %v", err)
	}
}

// TestContactResolvesInPolicyAllow proves `policy allow <contact-name>` resolves
// the contact name to its pinned address and lands THAT address (not the name) in
// the sealed allowlist — verified through PolicyShow.
func TestContactResolvesInPolicyAllow(t *testing.T) {
	fake := fakebackend.New()
	fake.Tip = 800000
	svc, done := newPolicySendService(t, fake) // wires DAXIB_ADMIN_PASSPHRASE
	defer done()
	ctx := context.Background()

	if _, err := svc.ContactAdd(ctx, domain.LocalCLI(), domain.ContactAddRequest{Name: "trusted", Address: contactRecipient}); err != nil {
		t.Fatalf("ContactAdd: %v", err)
	}

	// Bootstrap a sealed policy (allowlist on) so `policy allow` has an anchor to pin
	// against. PolicySet derives the seal from the admin passphrase env.
	allowlistOn := true
	if _, err := svc.PolicySet(ctx, domain.LocalCLI(), PolicySetInput{AllowlistOn: &allowlistOn}); err != nil {
		t.Fatalf("PolicySet bootstrap: %v", err)
	}

	// Allow the CONTACT NAME — it must resolve to the contact's address and pin that.
	// The admin passphrase is resolved from the env channel newPolicySendService wired.
	if _, err := svc.PolicyAllow(ctx, domain.LocalCLI(), PolicyPinInput{Address: "trusted"}); err != nil {
		t.Fatalf("PolicyAllow trusted: %v", err)
	}

	show, err := svc.PolicyShow(ctx, domain.LocalCLI())
	if err != nil {
		t.Fatalf("PolicyShow: %v", err)
	}
	var pinned bool
	for _, a := range show.Allowlist {
		if a.Address == contactRecipient {
			pinned = true
		}
	}
	if !pinned {
		t.Fatalf("policy allowlist %+v does not contain the resolved contact address %s", show.Allowlist, contactRecipient)
	}
}
