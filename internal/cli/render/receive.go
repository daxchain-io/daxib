package render

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/daxchain-io/daxib/internal/domain"
)

// receive.go builds the EventSink for `daxib receive`. It is the ONE command whose
// progress stream is the PRIMARY output on STDOUT — the single sanctioned exception
// to the single-object-on-stdout rule:
//
//   - the receiving ADDRESS is emitted UP FRONT (the first `listening` line) so a
//     counterparty can be handed it BEFORE the command blocks;
//   - under --json the stream is line-delimited NDJSON on stdout (one object per
//     line, amounts as decimal STRINGS, the terminal line carrying "exit"); under
//     human mode the same events render as short readable lines;
//   - the TERMINAL line is `complete` (exit 0) or `timeout` (exit 8).
//
// A nil writer yields a no-op sink.

// ReceiveStream returns the ReceiveEventSink the receive command hands to
// svc.Receive. stdout is the stream destination (NOT stderr). jsonMode selects
// NDJSON vs human-readable lines.
func ReceiveStream(stdout io.Writer, jsonMode bool) domain.ReceiveEventSink {
	if stdout == nil {
		return nil
	}
	if jsonMode {
		return func(ev domain.ReceiveEvent) {
			b, err := json.Marshal(ev)
			if err != nil {
				return // closed struct; a marshal failure is a programming bug, dropped to keep the stream pure
			}
			_, _ = stdout.Write(b)
			_, _ = io.WriteString(stdout, "\n")
		}
	}
	return func(ev domain.ReceiveEvent) {
		line := receiveHumanLine(ev)
		if line == "" {
			return
		}
		_, _ = io.WriteString(stdout, line+"\n")
	}
}

// receiveHumanLine renders one receive event as a short human STDOUT line. The
// listening line leads with the address (the up-front share value). An unrecognized
// kind yields "" (skipped).
func receiveHumanLine(ev domain.ReceiveEvent) string {
	switch ev.Kind {
	case domain.RecvListening:
		line := "listening: " + ev.Address
		if ev.Target != nil {
			if ev.Target.AmountSat > 0 {
				line += fmt.Sprintf(" (want %s BTC, %d conf)", ev.Target.AmountBTC, ev.Target.Confirmations)
			} else {
				line += fmt.Sprintf(" (any inbound, %d conf)", ev.Target.Confirmations)
			}
		}
		return line
	case domain.RecvDetected:
		return fmt.Sprintf("detected: %s:%d value=%s BTC (%d conf)", ev.Txid, ev.Vout, ev.ValueBTC, ev.Confirmations)
	case domain.RecvConfirmed:
		return fmt.Sprintf("confirmed: %s:%d value=%s BTC confirmed-total=%s BTC", ev.Txid, ev.Vout, ev.ValueBTC, ev.ConfirmedBTC)
	case domain.RecvComplete:
		return fmt.Sprintf("complete: received %s BTC (exit %d)", ev.ConfirmedBTC, exitOrZero(ev.Exit))
	case domain.RecvTimeout:
		// Label the remaining amount BTC (it is a BTC-valued decimal), consistent with
		// the "received %s BTC" on the same line (RECV-LABEL-1).
		return fmt.Sprintf("timeout: received %s BTC, remaining %s BTC (exit %d); re-run to resume",
			ev.ConfirmedBTC, domain.SatsToBTC(ev.RemainingSat), exitOrZero(ev.Exit))
	default:
		return ""
	}
}

// exitOrZero dereferences a terminal event's exit pointer (0 when nil).
func exitOrZero(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}
