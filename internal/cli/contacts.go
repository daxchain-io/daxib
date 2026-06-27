package cli

import (
	"context"
	"io"

	"github.com/daxchain-io/daxib/internal/cli/render"
	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/spf13/cobra"
)

// contacts.go is the `daxib contacts` noun (add/list/show/remove): the local
// address book mapping a name to a network-specific Bitcoin address. Any
// destination position that accepts a raw address ALSO accepts a contact name —
// `tx send --to <name>` and `policy allow <name>` resolve it to the pinned address
// in the service. It is a thin host over the Contact* use cases, same human +
// --json + exit-code discipline as the other nouns.
//
// Exit codes: 0 ok; 2 usage (bad name, duplicate, bad address on add); 10
// ref.not_found (show/remove of an unknown name) / read-only state mount.
func newContactsCmd(ctx context.Context, rs *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "contacts",
		Short: "Manage the local address book (name -> address)",
		Long: "A contact maps a name to a Bitcoin address valid for a given network. Any\n" +
			"`--to` (and `policy allow`) accepts a contact name in place of a raw address.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(
		newContactsAddCmd(ctx, rs),
		newContactsListCmd(ctx, rs),
		newContactsShowCmd(ctx, rs),
		newContactsRemoveCmd(ctx, rs),
	)
	return cmd
}

func newContactsAddCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var label string
	cmd := &cobra.Command{
		Use:   "add <name> <address>",
		Short: "Add a name -> address contact",
		Long: "Add a contact. The name follows the 1-64 char [a-z0-9_-] grammar; the address\n" +
			"is validated against the active --network and pinned. A duplicate name is a\n" +
			"usage error.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.ContactAdd(cmd.Context(), domain.ContactAddRequest{
				Name: args[0], Address: args[1], Label: label,
			})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "added contact %s -> %s", res.Contact.Name, res.Contact.Address)
			})
		},
	}
	cmd.Flags().StringVar(&label, "label", "", "optional operator note stored with the contact")
	return cmd
}

func newContactsListCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List contacts (name-sorted)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.ContactList(cmd.Context(), domain.ContactListRequest{})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				tbl := render.NewTable(w)
				if !m.Quiet {
					tbl.Row("NAME", "ADDRESS", "NETWORK", "LABEL")
				}
				for _, c := range res.Contacts {
					tbl.Row(c.Name, c.Address, c.Network, c.Label)
				}
				_ = tbl.Flush()
			})
		},
	}
}

func newContactsShowCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show one contact by name",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.ContactShow(cmd.Context(), domain.ContactShowRequest{Name: args[0]})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				c := res.Contact
				render.Line(w, m, "name:    %s", c.Name)
				render.Line(w, m, "address: %s", c.Address)
				if c.Network != "" {
					render.Line(w, m, "network: %s", c.Network)
				}
				if c.Label != "" {
					render.Line(w, m, "label:   %s", c.Label)
				}
			})
		},
	}
}

func newContactsRemoveCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove a contact by name",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.ContactRemove(cmd.Context(), domain.ContactRemoveRequest{Name: args[0]})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "removed contact %s", res.Name)
			})
		},
	}
}
