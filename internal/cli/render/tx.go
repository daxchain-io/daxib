package render

import (
	"io"

	"github.com/daxchain-io/daxib/internal/domain"
)

// tx.go holds the human (non-JSON) renderers for the M4 tx/fee surface. They are
// format-only; --json emits the marshaled domain struct through Result. The txid
// (or the recommended fee rate) is the essential line that prints even under
// --quiet so a script can read it on stdout.

// TxResult renders a `tx send`/`tx status`/`tx wait` result. The txid line prints
// under --quiet; the rest is suppressed by Quiet via Line.
func TxResult(w io.Writer, m Mode, r domain.TxResult) {
	switch {
	case r.Txid != "":
		_, _ = io.WriteString(w, r.Txid+"\n")
	case r.DryRun:
		Line(w, m, "(dry-run — not broadcast)")
	}
	Line(w, m, "to:       %s", r.To)
	Line(w, m, "amount:   %s BTC (%s sat)", r.AmountBTC, itoa64(r.AmountSat))
	Line(w, m, "fee:      %s BTC (%s sat) @ %s sat/vB, vsize %s", r.FeeBTC, itoa64(r.FeeSat), itoa64(r.FeeRate), itoa64(r.Vsize))
	if r.ChangeSat > 0 {
		Line(w, m, "change:   %s BTC -> %s", r.ChangeBTC, r.ChangeAddress)
	}
	Line(w, m, "status:   %s", string(r.Status))
	if r.Confirmations > 0 {
		Line(w, m, "confirmations: %s", itoa64(r.Confirmations))
	}
	if r.JournalID != "" {
		Line(w, m, "journal:  %s", r.JournalID)
	}
	if r.Resume != "" {
		Line(w, m, "resume:   %s", r.Resume)
	}
}

// FeeQuotes renders the `fee` result. The selected recommendation prints under
// --quiet (a script reads the sat/vB on stdout).
func FeeQuotes(w io.Writer, m Mode, r domain.FeeQuotesResult) {
	Line(w, m, "network: %s via %s", r.Network, r.Backend)
	tbl := NewTable(w)
	if !m.Quiet {
		tbl.Row("SPEED", "SAT/VB", "TARGET_BLOCKS")
	}
	tbl.Row("slow", itoa64(r.Slow), "6")
	tbl.Row("normal", itoa64(r.Normal), "3")
	tbl.Row("fast", itoa64(r.Fast), "1")
	_ = tbl.Flush()
	// The selected recommendation prints even under --quiet (a script reads it).
	_, _ = io.WriteString(w, itoa64(r.SelectedRate)+"\n")
}

// TxRows renders a `tx list` table (newest-first).
func TxRows(w io.Writer, m Mode, rows []domain.TxRow) {
	tbl := NewTable(w)
	if !m.Quiet {
		tbl.Row("TXID", "STATUS", "TO", "AMOUNT_BTC", "FEE_SAT", "VSIZE", "CONFIRMATIONS")
	}
	for _, r := range rows {
		txid := r.Txid
		if txid == "" {
			txid = "(unbroadcast)"
		}
		tbl.Row(txid, string(r.Status), r.To, r.AmountBTC, itoa64(r.FeeSat), itoa64(r.Vsize), itoa64(r.Confirmations))
	}
	_ = tbl.Flush()
}

// itoa64 is a tiny int64->decimal helper (the render package stays strconv-free on
// its hot paths, mirroring the cli util helpers).
func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
