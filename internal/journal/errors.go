package journal

import (
	"errors"

	"github.com/daxchain-io/daxib/internal/domain"
)

// ErrNotFound is returned by the lookup queries (ByID/ByTxid) when no record
// matches on the given network. It is a sentinel (errors.Is-able) so the service
// can branch the §5.1 reconciliation without string-matching; it is NOT itself a
// typed domain.Error because "not found" is a normal control-flow outcome for the
// caller (e.g. a foreign txid), not a CLI exit.
var ErrNotFound = errors.New("journal: record not found")

// Canonical error-code strings the journal emits, named locally so call sites are
// greppable. The integers they project to via domain.ExitOf:
//
//	state.lock_timeout -> 11 (STATE; flock contention bounded by lockTimeout)
//	state.corrupt      -> 11 (STATE; an unrecoverable journal file / write)
const (
	// CodeStateLockTimeout is flock contention on the journal lock that exceeded
	// the bounded wait (→ exit 11).
	CodeStateLockTimeout = "state.lock_timeout"
	// CodeStateCorrupt is an unrecoverable journal file (e.g. a write that cannot
	// land, a read-only state dir). A torn LINE is NOT corrupt — it is tolerated;
	// this is for the whole-file failure.
	CodeStateCorrupt = "state.corrupt"
)

// errJournal builds a typed *domain.Error; the exit number derives from the code.
func errJournal(code, msg string) error { return domain.New(code, msg) }

// errWrap wraps a cause with a typed code, preserving it for errors.Is/As.
func errWrap(code, msg string, cause error) error { return domain.Wrap(code, msg, cause) }
