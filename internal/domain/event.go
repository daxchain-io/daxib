package domain

// event.go is the minimal progress-streaming seam for the long-running send/wait
// paths (§5.9, M4-minimal). The service emits human-readable progress to an
// EventSink the frontend supplies; the sink writes to STDERR (never stdout, which
// carries the single result object). A nil sink is a no-op, so a command that
// does not stream (status/list) passes nil.

// Event is one progress record. Stage is a short machine tag ("signed",
// "broadcast", "confirm", "reconcile", "wait"); Message is the human line.
type Event struct {
	Stage   string `json:"stage"`
	Message string `json:"message"`
}

// EventSink is the streaming callback the core emits to. A nil sink is a no-op
// (the core guards every emit), so the frontend passes nil for non-streaming
// commands and a real sink for `tx send` / `tx wait`.
type EventSink func(Event)
