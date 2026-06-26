package render

import (
	"encoding/json"
	"io"

	"github.com/daxchain-io/daxib/internal/domain"
)

// progress.go is the minimal §5.9 progress sink: the cli wires it on the
// long-running send/wait paths so the service streams human-readable progress to
// STDERR (never stdout, which carries the single result object). Under --json each
// event is one JSON object per line on stderr (an agent can tail it); otherwise it
// is a plain "daxib: <message>" line. A nil writer (or the no-op for non-streaming
// commands) drops events.

// StderrProgress returns a domain.EventSink that writes progress events to w. When
// jsonMode is true each event is a JSON object line; otherwise a plain text line.
// The result is safe to pass as nil's stand-in — callers that do not stream pass
// the domain nil sink directly instead.
func StderrProgress(w io.Writer, jsonMode bool) domain.EventSink {
	if w == nil {
		return nil
	}
	return func(ev domain.Event) {
		if jsonMode {
			enc := json.NewEncoder(w)
			enc.SetEscapeHTML(false)
			_ = enc.Encode(ev)
			return
		}
		_, _ = io.WriteString(w, "daxib: "+ev.Message+"\n")
	}
}
