package render

import (
	"io"
	"strconv"

	"github.com/daxchain-io/daxib/internal/domain"
)

// psbt.go renders a domain.PSBTResult for the `psbt` noun (create/sign/combine/
// finalize/decode). The base64 PSBT (or, for extract, the raw tx hex) is the
// essential output: under --quiet it is printed bare (so a pipe `psbt create | psbt
// sign --psbt-stdin` carries one clean line); otherwise a table summarizes the
// inputs/outputs/fee/completeness and the PSBT trails on its own line.

// PSBT renders a PSBTResult to w in the active mode. essential is the bare value to
// print under --quiet (the base64 PSBT, or the raw tx hex for extract).
func PSBT(w io.Writer, m Mode, r domain.PSBTResult) {
	essential := r.PSBT
	if essential == "" {
		essential = r.RawTxHex
	}
	if m.Quiet {
		_, _ = io.WriteString(w, essential+"\n")
		return
	}
	for _, warn := range r.Warnings {
		_, _ = io.WriteString(w, "warning: "+warn+"\n")
	}
	tbl := NewTable(w)
	if r.Network != "" {
		tbl.Row("network", string(r.Network))
	}
	tbl.Row("complete", strconv.FormatBool(r.Complete))
	tbl.Row("signed_by_us", strconv.Itoa(r.SignedByUs))
	if r.Vsize > 0 {
		tbl.Row("vsize", strconv.FormatInt(r.Vsize, 10)+" vB")
	}
	if r.FeeSat > 0 {
		tbl.Row("fee", strconv.FormatInt(r.FeeSat, 10)+" sat ("+r.FeeBTC+" BTC)")
	}
	if r.FeeRate > 0 {
		tbl.Row("fee_rate", strconv.FormatInt(r.FeeRate, 10)+" sat/vB")
	}
	for _, in := range r.Inputs {
		label := in.Outpoint
		if in.Mine {
			label += " (mine)"
		}
		if in.Signed {
			label += " [signed]"
		}
		tbl.Row("input", label+"  "+strconv.FormatInt(in.ValueSat, 10)+" sat")
	}
	for _, out := range r.Outputs {
		label := out.Address
		if out.Change {
			label += " (change)"
		} else if out.Mine {
			label += " (mine)"
		}
		tbl.Row("output", label+"  "+strconv.FormatInt(out.ValueSat, 10)+" sat")
	}
	_ = tbl.Flush()
	if essential != "" {
		_, _ = io.WriteString(w, essential+"\n")
	}
}
