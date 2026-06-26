package journal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/daxchain-io/daxib/internal/fsx"
)

// lockTimeout bounds every journal flock acquisition. Exceeding it maps to
// state.lock_timeout (exit 11). The journal flock is held only for one fold+write,
// so this short internal bound is enough; the long-held wallet SEND-lock (in
// service) uses the caller-configured timeout.
const lockTimeout = 30 * time.Second

// Store is the per-process journal handle. It holds no long-lived fd: every
// mutation acquires the journal flock for the target network, opens the file
// fresh by path (O_APPEND), folds the current max seq, writes one line, fsyncs,
// and releases — the property that lets an append land in the live file even
// after another process compaction-renamed the old inode. Reads fold
// latest-per-id.
type Store struct {
	dir   string           // <stateDir>/journal
	locks string           // <stateDir>/locks
	clock func() time.Time // record timestamp source (the service's injected clock)

	// warn routes the non-fatal torn/corrupt-line diagnostics. It is per-Store (not
	// a package global) so the frontend can repoint it and parallel tests never race
	// on shared mutable state. A nil sink falls back to os.Stderr.
	warn io.Writer
}

// warnWriter returns the torn/corrupt-line warning sink, defaulting to os.Stderr.
func (s *Store) warnWriter() io.Writer {
	if s.warn != nil {
		return s.warn
	}
	return os.Stderr
}

// SetWarnSink repoints the torn/corrupt-line diagnostic sink. The frontend routes
// journal warnings into its stderr router; tests capture them. A nil writer
// restores os.Stderr.
func (s *Store) SetWarnSink(w io.Writer) { s.warn = w }

// Open binds the store to <stateDir>/journal and <stateDir>/locks. It is LAZY: it
// creates no directories or files until the first append (a fresh install reads
// as empty). clock supplies record timestamps; passing it in keeps `ts`
// deterministic under the service test clock. A nil clock defaults to time.Now.
func Open(stateDir string, clock func() time.Time) (*Store, error) {
	if stateDir == "" {
		return nil, errJournal(CodeStateCorrupt, "journal: empty state dir")
	}
	if clock == nil {
		clock = time.Now
	}
	return &Store{
		dir:   filepath.Join(stateDir, "journal"),
		locks: filepath.Join(stateDir, "locks"),
		clock: clock,
	}, nil
}

// Close is a no-op flush — the store keeps no long-lived fd. It exists for the
// Service.Close lifecycle symmetry.
func (s *Store) Close() error { return nil }

// ── path helpers ────────────────────────────────────────────────────────────────

// filePath is <stateDir>/journal/<network>.jsonl (one append-only file per
// network).
func (s *Store) filePath(net domain.Network) string {
	return filepath.Join(s.dir, string(net)+".jsonl")
}

// lockPath is the sidecar lock object for a network's journal file. fsx.Lock
// appends the ".lock" suffix itself, so this returns the BASE path it locks
// against. A dedicated sidecar under <stateDir>/locks (not the data file) keeps
// lock continuity across the compaction temp+rename.
func (s *Store) lockPath(net domain.Network) string {
	return filepath.Join(s.locks, "journal-"+string(net))
}

// ensureDirs creates <stateDir>/journal and <stateDir>/locks (owner-only) before
// the first write. A read-only target maps to state.corrupt — the journal is a
// state class whose unwritability is unrecoverable for a signing op (the caller
// surfaces it BEFORE any spend, since journal-before-broadcast ordering means an
// unwritable journal stops the spend rather than broadcasts-then-can't-record).
func (s *Store) ensureDirs() error {
	for _, d := range []string{s.dir, s.locks} {
		if err := fsx.MkdirAll(d, 0o700); err != nil {
			if fsx.IsReadOnly(err) {
				return errWrap(CodeStateCorrupt, "journal directory is read-only", err)
			}
			return errWrap(CodeStateCorrupt, "cannot create journal directory", err)
		}
	}
	return nil
}

// withLock runs fn while holding the EXCLUSIVE journal flock for net, bounded by
// lockTimeout. A timeout maps to state.lock_timeout (exit 11). Lock ordering is
// always wallet-send-lock → journal-lock (binding): every caller that also holds
// the send-lock takes it FIRST, so a status/list query (journal lock only) never
// deadlocks against an in-flight send.
func (s *Store) withLock(ctx context.Context, net domain.Network, fn func() error) error {
	if err := s.ensureDirs(); err != nil {
		return err
	}
	lctx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()
	unlock, err := fsx.Lock(lctx, s.lockPath(net))
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return errJournal(CodeStateLockTimeout, "timed out acquiring the journal lock; another daxib process may be holding it")
		}
		return errWrap(CodeStateLockTimeout, "cannot acquire the journal lock", err)
	}
	defer unlock()
	return fn()
}

// ── mutations ───────────────────────────────────────────────────────────────────

// Append writes rec as a new line under the journal flock for rec.Network,
// assigning rec.Seq = currentMaxSeq+1, rec.V, rec.ID (a fresh ULID if empty), and
// rec.TS from the clock (if empty). It is the §5.1 "journal.Append(signed,
// raw_tx)" call. The assigned id/seq are written back into rec.
func (s *Store) Append(ctx context.Context, rec *Record) error {
	if rec == nil {
		return errJournal(CodeStateCorrupt, "journal: nil record")
	}
	if rec.Network == "" {
		return errJournal(CodeStateCorrupt, "journal: record has no network")
	}
	net := domain.Network(rec.Network)
	return s.withLock(ctx, net, func() error {
		recs, maxSeq, err := s.readAll(net, true)
		if err != nil {
			return err
		}
		if rec.V == 0 {
			rec.V = recordVersion
		}
		if rec.ID == "" {
			id, ierr := newULID()
			if ierr != nil {
				return errWrap(CodeStateCorrupt, "journal: cannot generate record id", ierr)
			}
			rec.ID = id
		}
		if rec.TS == "" {
			rec.TS = s.clock().UTC().Format(time.RFC3339Nano)
		}
		rec.Seq = maxSeq + 1
		if err := s.appendLine(net, rec); err != nil {
			return err
		}
		return s.maybeCompact(net, recs, rec)
	})
}

// SetState appends a NEW line for an existing id carrying the transitioned fields
// (status + any non-nil mutation field). Every other field is copied from the
// prior latest record so a fold still reconstructs the full record. An unknown id
// is ErrNotFound.
func (s *Store) SetState(ctx context.Context, net domain.Network, id string, mut StateMutation) error {
	if id == "" {
		return errJournal(CodeStateCorrupt, "journal: empty id in SetState")
	}
	return s.withLock(ctx, net, func() error {
		recs, maxSeq, err := s.readAll(net, true)
		if err != nil {
			return err
		}
		prior, ok := foldLatest(recs)[id]
		if !ok {
			return fmt.Errorf("%w: id %s on network %s", ErrNotFound, id, net)
		}
		next := prior.clone()
		mut.applyTo(next)
		next.Seq = maxSeq + 1
		next.TS = s.clock().UTC().Format(time.RFC3339Nano)
		if err := s.appendLine(net, next); err != nil {
			return err
		}
		return s.maybeCompact(net, recs, next)
	})
}

// StateMutation is the set of fields a SetState transition may change; the rest
// are copied from the prior latest record. A nil pointer leaves that field
// unchanged. Status is always applied (a SetState always names the target
// status).
type StateMutation struct {
	Status        Status
	Txid          *string
	Confirmations *int64
	BlockHeight   *int64
	Error         *string
	// ReplacedBy stamps the original record's ReplacedByID when an RBF replacement is
	// accepted (the original transitions to StatusReplaced in the same append).
	ReplacedBy *string
}

// applyTo mutates dst with the non-nil fields of m. Status is always applied.
func (m StateMutation) applyTo(dst *Record) {
	if m.Status != "" {
		dst.Status = m.Status
	}
	if m.Txid != nil {
		dst.Txid = *m.Txid
	}
	if m.Confirmations != nil {
		dst.Confirmations = *m.Confirmations
	}
	if m.BlockHeight != nil {
		dst.BlockHeight = *m.BlockHeight
	}
	if m.Error != nil {
		dst.Error = m.Error
	}
	if m.ReplacedBy != nil {
		dst.ReplacedByID = *m.ReplacedBy
	}
}

// ── queries (all fold latest-per-id) ──────────────────────────────────────────────

// ByID returns the latest record for a journal id on net, or ErrNotFound. It
// backs the deferred-abort status re-read: the service holds the journal id and
// must learn whether settle already recorded a broadcast before deciding whether
// the abort may terminalize the record. Reads take only the journal flock.
func (s *Store) ByID(ctx context.Context, net domain.Network, id string) (*Record, error) {
	var found *Record
	err := s.read(ctx, net, func(latest map[string]*Record) {
		if r, ok := latest[id]; ok {
			found = r
		}
	})
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, fmt.Errorf("%w: id %s on network %s", ErrNotFound, id, net)
	}
	return found, nil
}

// ByTxid returns the latest record for a txid on net, or ErrNotFound. It backs
// `tx status`/`tx wait`. Comparison is exact (Bitcoin txids are canonical
// lowercase hex).
func (s *Store) ByTxid(ctx context.Context, net domain.Network, txid string) (*Record, error) {
	var found *Record
	err := s.read(ctx, net, func(latest map[string]*Record) {
		for _, r := range latest {
			if r.Txid == txid && r.Txid != "" {
				if found == nil || r.Seq > found.Seq {
					found = r
				}
			}
		}
	})
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, fmt.Errorf("%w: txid %s on network %s", ErrNotFound, txid, net)
	}
	return found, nil
}

// Unresolved returns every non-terminal record on net (status NOT in {confirmed,
// failed, replaced}) — the restart-reconciliation worklist. Newest-first by seq.
// A fresh/empty journal returns an empty slice, nil.
func (s *Store) Unresolved(ctx context.Context, net domain.Network) ([]*Record, error) {
	var out []*Record
	err := s.read(ctx, net, func(latest map[string]*Record) {
		for _, r := range latest {
			if !r.Status.IsTerminal() {
				out = append(out, r)
			}
		}
	})
	if err != nil {
		return nil, err
	}
	sortBySeqDesc(out)
	return out, nil
}

// List returns latest-per-id records on net filtered by wallet ("" = all wallets),
// newest-first — it backs `tx list`. Terminal records are KEPT (the journal IS the
// history). A fresh/empty journal returns an empty slice, nil.
func (s *Store) List(ctx context.Context, net domain.Network, wallet string) ([]*Record, error) {
	var out []*Record
	err := s.read(ctx, net, func(latest map[string]*Record) {
		for _, r := range latest {
			if wallet == "" || r.Wallet == wallet {
				out = append(out, r)
			}
		}
	})
	if err != nil {
		return nil, err
	}
	sortBySeqDesc(out)
	return out, nil
}

// read folds the network's journal under a SHARED journal lock and hands the
// latest-per-id map to fn. A missing file (fresh install) folds to empty. The
// shared lock means a concurrent compaction's temp+rename never tears a read.
func (s *Store) read(ctx context.Context, net domain.Network, fn func(latest map[string]*Record)) error {
	if err := s.ensureDirs(); err != nil {
		return err
	}
	lctx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()
	unlock, err := fsx.RLock(lctx, s.lockPath(net))
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return errJournal(CodeStateLockTimeout, "timed out acquiring the journal read lock")
		}
		return errWrap(CodeStateLockTimeout, "cannot acquire the journal read lock", err)
	}
	defer unlock()
	recs, _, rerr := s.readAll(net, false)
	if rerr != nil {
		return rerr
	}
	fn(foldLatest(recs))
	return nil
}

// foldLatest reduces a seq-ordered slice of records to the latest line per id
// (last-wins-per-id). A higher seq always wins, so a torn mid-file line that was
// skipped only costs at most one transition (re-derivable from backend.TxStatus).
func foldLatest(recs []*Record) map[string]*Record {
	latest := make(map[string]*Record, len(recs))
	for _, r := range recs {
		if cur, ok := latest[r.ID]; !ok || r.Seq >= cur.Seq {
			latest[r.ID] = r
		}
	}
	return latest
}

// sortBySeqDesc orders records newest-first (highest seq first), the stable order
// `tx list` / Unresolved present.
func sortBySeqDesc(rs []*Record) {
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].Seq > rs[j].Seq })
}
