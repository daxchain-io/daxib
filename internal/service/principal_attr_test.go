package service

import (
	"context"
	"strings"
	"testing"

	fakebackend "github.com/daxchain-io/daxib/internal/backend/fake"
	"github.com/daxchain-io/daxib/internal/domain"
)

// TestSendSourceAttributedByPrincipal is the Phase A bug-fix proof (issue #11):
// the journal Source is no longer hardcoded "cli" — it is derived from the
// Principal the frontend supplies. An MCP-initiated send (domain.LocalMCP()) MUST
// record Source:"mcp"; a CLI-initiated one (domain.LocalCLI()) MUST record "cli".
// Before Phase A, both wrote "cli" and an agent fund-mover was mis-attributed.
func TestSendSourceAttributedByPrincipal(t *testing.T) {
	cases := []struct {
		name string
		p    domain.Principal
		want string
		txid string // a distinct funding txid per case (separate single-UTXO wallets)
	}{
		{"mcp", domain.LocalMCP(), "mcp", "e1"},
		{"cli", domain.LocalCLI(), "cli", "e2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := fakebackend.New()
			fake.Tip = 800000
			programUTXO(fake, canonicalReceive0, tc.txid+strings.Repeat("0", 62), 0, 1_000_000)
			fake.BroadcastFn = func(_ context.Context, raw []byte) (string, error) {
				return txidOf(raw), nil
			}

			svc, teardown := newSendService(t, fake)
			defer teardown()

			res, err := svc.SendTx(context.Background(), tc.p, sendReq(extRecipient, "0.005"), nil)
			if err != nil {
				t.Fatalf("SendTx(%s): %v", tc.name, err)
			}
			rec, jerr := svc.journal.ByID(context.Background(), domain.NetworkMainnet, res.JournalID)
			if jerr != nil {
				t.Fatalf("journal ByID: %v", jerr)
			}
			if rec.Source != tc.want {
				t.Fatalf("journal Source=%q, want %q (Principal %+v must drive attribution)", rec.Source, tc.want, tc.p)
			}
		})
	}
}
