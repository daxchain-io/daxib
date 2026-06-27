package keys

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/daxchain-io/daxib/internal/fsx"
	"github.com/daxchain-io/daxib/internal/secret"
)

// passphrase.go is the keystore's atomic re-encryption (change-passphrase) and the
// read-only info summary. It is a faithful port of daxie's keys §3.8 two-phase
// rotation, ADAPTED to daxib's stdlib AES-256-GCM envelope (codec.go) instead of
// daxie's geth-v3 envelope: each secret file's plaintext is re-sealed under the
// new passphrase with a FRESH per-file salt + nonce.
//
// The rotation is crash-safe: a kill at any point leaves either the all-OLD or the
// all-NEW keystore, never a mix. The on-disk protocol is
//
//	STAGE  : write each re-encryption as "<file>.new" (fresh salts/nonces). Until
//	         the marker exists, none of these matters — a crash rolls them BACK.
//	COMMIT : atomically write the ROTATE-COMMIT marker listing every staged file.
//	         This is the irrevocable instant: the marker's presence means
//	         "roll FORWARD".
//	SWAP   : rename each "<file>.new" -> "<file>", then delete the marker.
//
// recoverRotation runs at every keys.Open under the exclusive lock: with the
// marker present it finishes the swaps (forward); with only orphaned ".new" files
// it deletes them (backward). It is idempotent.

// rotation artifact names (§3.8 parity). The marker is the commit point.
const (
	rotateMarkerName = "ROTATE-COMMIT"
	stagedSuffix     = ".new"
)

// rotateMarker is the committed list of staged files. Each entry is a keystore-dir
// relative (slash) path whose "<path>.new" must be renamed onto "<path>" to
// complete the swap.
type rotateMarker struct {
	Files []string `json:"files"`
}

// faultHook lets tests inject a crash at a named point in ChangePassphrase. In
// production it is nil. A non-nil return aborts the operation there, simulating a
// process kill that leaves the on-disk artifacts in whatever state the prior steps
// produced. Test-only; never set in prod code.
var faultHook func(point string) error

func fireFault(point string) error {
	if faultHook == nil {
		return nil
	}
	return faultHook(point)
}

// ChangePassphrase re-encrypts the verifier + every wallet blob from oldPass to
// newPass, atomically (§3.8). It runs under the exclusive index.lock. A crash
// never leaves a mixed-passphrase keystore: keys.Open's recovery rolls forward
// (marker present) or back (only .new files). Returns the count of rotated secret
// files (the verifier counts as one).
//
// A wrong OLD passphrase is keystore.bad_passphrase (exit 4) and rotates nothing.
func (s *Store) ChangePassphrase(ctx context.Context, oldPass, newPass *secret.Bytes) (int, error) {
	var rotated int
	werr := s.withLock(ctx, func() error {
		// Recover any prior interrupted rotation FIRST so we start from a clean,
		// single-passphrase state (never stack a rotation on staged artifacts).
		if rerr := recoverRotation(s.dir); rerr != nil {
			return rerr
		}

		man, err := s.loadManifest()
		if err != nil {
			return err
		}
		if man == nil {
			return errKeys(CodeKeystoreBadPassphrase, "the keystore is not initialized; nothing to rotate")
		}
		// Verify the OLD passphrase against the current verifier (fail-closed,
		// exit 4) before touching any file.
		if verr := verifyAgainst(man, oldPass); verr != nil {
			return verr
		}

		m, err := s.loadMeta()
		if err != nil {
			return err
		}

		// Defense-in-depth (ROT-1): the rotation set is derived from meta.Wallets, so a
		// wallet blob on disk that meta.json does not list would be left under the OLD
		// passphrase — a silent orphan-blob skew. Fail CLOSED on that skew rather than
		// bake a half-rotated keystore: scan wallets/ and refuse if any blob is missing
		// from meta.
		if cerr := s.checkNoOrphanBlobs(m); cerr != nil {
			return cerr
		}

		// The set of secret files to rotate: keystore.json (verifier) + wallet blobs.
		// Paths are keystore-dir relative, slash-form, sorted for determinism.
		secretFiles := s.rotationFileSet(m)

		oldBytes := oldPass.Reveal()
		newBytes := newPass.Reveal()
		n := s.scryptN() // light stays light; a production manifest stays standard

		// ── STAGE ──: write each re-encryption as "<file>.new" with fresh
		// salts/nonces. Any decrypt failure aborts with nothing committed (the
		// orphaned .new files roll back on the next Open, and we clean them here too).
		staged := make([]string, 0, len(secretFiles))
		abort := func(cause error) error {
			for _, rel := range staged {
				_ = os.Remove(filepath.Join(s.dir, filepath.FromSlash(rel)+stagedSuffix))
			}
			return cause
		}

		// keystore.json: re-seal a FRESH verifier under newPass (the verifier
		// plaintext is arbitrary 32 random bytes, so we mint new ones rather than
		// carry the old). CreatedAt + Light are preserved.
		newMan, merr := s.restageManifest(man, newBytes, n)
		if merr != nil {
			return abort(merr)
		}
		if werr := s.stageManifest(newMan); werr != nil {
			return abort(werr)
		}
		staged = append(staged, "keystore.json")
		if ferr := fireFault("after_stage_manifest"); ferr != nil {
			return abort(ferr)
		}

		for _, rel := range secretFiles {
			if rel == "keystore.json" {
				continue
			}
			if rerr := s.restageWalletBlob(rel, oldBytes, newBytes, n); rerr != nil {
				return abort(rerr)
			}
			staged = append(staged, rel)
			if ferr := fireFault("after_stage_" + filepath.Base(rel)); ferr != nil {
				return abort(ferr)
			}
		}
		if ferr := fireFault("before_commit"); ferr != nil {
			return abort(ferr)
		}

		// ── COMMIT ──: atomic-write the marker listing every staged file. Before
		// this the rotation has not happened; after, it is irrevocable (roll forward).
		marker := rotateMarker{Files: append([]string(nil), staged...)}
		sort.Strings(marker.Files)
		mb, _ := json.MarshalIndent(marker, "", "  ")
		if werr := fsx.WriteAtomic(s.markerPath(), mb, 0o600); werr != nil {
			if fsx.IsReadOnly(werr) {
				return abort(errKeys(CodeKeystoreReadOnly, "the keystore is read-only; cannot commit the rotation"))
			}
			return abort(errWrap(CodeStateCorrupt, "writing the rotation commit marker", werr))
		}
		if ferr := fireFault("after_commit"); ferr != nil {
			// Crash right after commit: the marker is on disk, so the NEXT Open rolls
			// FORWARD. We must NOT clean up here — that is the whole point.
			return ferr
		}

		// ── SWAP ──: rename each "<file>.new" -> "<file>", then delete the marker.
		if serr := swapStaged(s.dir, marker.Files); serr != nil {
			return serr
		}
		if ferr := fireFault("after_swap_before_marker_delete"); ferr != nil {
			// Marker still present but all swaps done: the next Open finishes
			// (idempotent: an already-renamed file is a no-op) and deletes the marker.
			return ferr
		}
		_ = os.Remove(s.markerPath())

		rotated = len(secretFiles)
		return nil
	})
	if werr != nil {
		return 0, werr
	}
	return rotated, nil
}

// rotationFileSet returns the keystore-dir-relative (slash) paths of every secret
// file (verifier manifest + wallet blobs), sorted for determinism.
func (s *Store) rotationFileSet(m *metaFile) []string {
	out := []string{"keystore.json"}
	for id := range m.Wallets {
		out = append(out, filepath.ToSlash(filepath.Join("wallets", id+".json")))
	}
	sort.Strings(out)
	return out
}

// checkNoOrphanBlobs reads wallets/ and fails closed (state.corrupt) if any
// wallets/*.json is NOT listed in meta.Wallets — such a blob would be skipped by the
// meta-derived rotation set and silently stranded under the old passphrase (ROT-1).
// A missing wallets/ dir (a verifier-only keystore) is fine. Non-".json" files and
// rotation artifacts (".new") are ignored.
func (s *Store) checkNoOrphanBlobs(m *metaFile) error {
	entries, err := os.ReadDir(s.walletsDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return errWrap(CodeStateCorrupt, "scanning the wallets directory before rotation", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".json") || strings.HasSuffix(name, stagedSuffix) {
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		if _, ok := m.Wallets[id]; !ok {
			return errKeysf(CodeStateCorrupt,
				"wallet blob %q is not recorded in meta.json; refusing to rotate a keystore with orphan blobs (run keystore info / repair first)",
				filepath.Join("wallets", name))
		}
	}
	return nil
}

func (s *Store) markerPath() string { return filepath.Join(s.dir, rotateMarkerName) }

// restageManifest builds a new manifest with the verifier re-sealed under newBytes
// at cost n, preserving CreatedAt + Light. The verifier plaintext is arbitrary, so
// a fresh 32 random bytes are minted (the old verifier was already proven to
// decrypt by the caller). initManifest seals fresh random verifier bytes for us.
func (s *Store) restageManifest(base *manifest, newBytes []byte, n int) (*manifest, error) {
	tmpPass := secret.New(append([]byte(nil), newBytes...))
	defer tmpPass.Zero()

	tmp := &Store{dir: s.dir, clock: s.clock, light: base.Light}
	nm, err := tmp.initManifest(tmpPass)
	if err != nil {
		return nil, err
	}
	// Preserve the original creation time + light flag; only the verifier envelope
	// changes on rotation. initManifest already set KDFDefaults.N from the store's
	// scrypt cost (which equals n for the rotated keystore).
	nm.CreatedAt = base.CreatedAt
	nm.Light = base.Light
	nm.KDFDefaults.N = n
	return nm, nil
}

// stageManifest writes the new manifest to keystore.json.new (0600).
func (s *Store) stageManifest(nm *manifest) error {
	b, err := json.MarshalIndent(nm, "", "  ")
	if err != nil {
		return errWrap(CodeStateCorrupt, "encoding the rotated keystore.json", err)
	}
	return stageWrite(s.manifestPath()+stagedSuffix, b)
}

// restageWalletBlob decrypts the wallet blob at the keystore-relative slash path
// rel with oldBytes and writes its re-encryption (fresh salt/nonce, cost n) to
// "<file>.new" (0600). A decrypt failure under oldBytes is keystore.bad_passphrase
// (a blob the old passphrase cannot open is a corrupt/foreign keystore — fail
// closed rather than commit a half-rotation).
func (s *Store) restageWalletBlob(rel string, oldBytes, newBytes []byte, n int) error {
	id := strings.TrimSuffix(strings.TrimPrefix(rel, "wallets/"), ".json")
	wb, err := s.loadWalletBlob(id)
	if err != nil {
		return err
	}
	raw, derr := open(wb.Crypto, oldBytes)
	if derr != nil {
		return derr // keystore.bad_passphrase / state.corrupt
	}
	defer zeroBytes(raw)

	env, eerr := seal(raw, newBytes, n)
	if eerr != nil {
		return eerr
	}
	newBlob := walletBlob{
		DaxibWallet: wb.DaxibWallet,
		Type:        wb.Type,
		ID:          wb.ID,
		Crypto:      env,
	}
	b, merr := json.MarshalIndent(&newBlob, "", "  ")
	if merr != nil {
		return errWrap(CodeStateCorrupt, "encoding the rotated wallet blob", merr)
	}
	return stageWrite(filepath.Join(s.dir, filepath.FromSlash(rel))+stagedSuffix, b)
}

// stageWrite atomically writes a staged "<file>.new" (0600), mapping a read-only
// target to keystore.read_only.
func stageWrite(stagedFull string, b []byte) error {
	if werr := fsx.WriteAtomic(stagedFull, b, 0o600); werr != nil {
		if fsx.IsReadOnly(werr) {
			return errKeys(CodeKeystoreReadOnly, "the keystore is read-only; cannot stage the rotation")
		}
		return errWrap(CodeStateCorrupt, "staging a rotated secret file", werr)
	}
	return nil
}

// ── swap + crash recovery ───────────────────────────────────────────────────

// swapStaged renames each "<file>.new" -> "<file>" for the given relative paths.
// It is idempotent: a missing .new with an already-present target is a completed
// swap (the forward-recovery case), a no-op. Any other error is fatal.
func swapStaged(dir string, relFiles []string) error {
	for _, rel := range relFiles {
		target := filepath.Join(dir, filepath.FromSlash(rel))
		staged := target + stagedSuffix
		if _, err := os.Stat(staged); err != nil {
			if os.IsNotExist(err) {
				// Already swapped (forward recovery) — confirm the target exists.
				if _, terr := os.Stat(target); terr == nil {
					continue
				}
				return errKeysf(CodeStateCorrupt, "rotation swap incomplete: neither %s nor its staged copy exist", rel)
			}
			return errWrap(CodeStateCorrupt, "stat of a staged rotation file", err)
		}
		// os.Rename is atomic-replace on POSIX and maps to MoveFileEx(REPLACE_EXISTING)
		// on Windows. The staged file was durably written via fsx.WriteAtomic.
		if rerr := os.Rename(staged, target); rerr != nil {
			return errWrap(CodeStateCorrupt, "completing the rotation swap", rerr)
		}
	}
	return nil
}

// recoverRotation scans the keystore dir for rotation artifacts and brings it to a
// single-passphrase consistent state. With the marker present it rolls FORWARD
// (finish every rename, delete the marker); with only .new files it rolls BACK
// (delete them). It is idempotent and safe to call on every Open under the
// exclusive lock.
func recoverRotation(dir string) error {
	markerPath := filepath.Join(dir, rotateMarkerName)
	mb, err := os.ReadFile(markerPath) // #nosec G304 -- ROTATE-COMMIT under the store's own keystore dir
	if err == nil {
		var marker rotateMarker
		if jerr := json.Unmarshal(mb, &marker); jerr != nil {
			return errWrap(CodeStateCorrupt, "the rotation commit marker is corrupt", jerr)
		}
		if serr := swapStaged(dir, marker.Files); serr != nil {
			return serr
		}
		if rerr := os.Remove(markerPath); rerr != nil && !os.IsNotExist(rerr) {
			return errWrap(CodeStateCorrupt, "removing the rotation marker after forward recovery", rerr)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return errWrap(CodeStateCorrupt, "reading the rotation marker", err)
	}
	// No marker: roll BACK any orphaned ".new" files (an interrupted STAGE).
	return rollbackStaged(dir)
}

// rollbackStaged removes every "<file>.new" under the keystore dir + wallets/.
// fsx.WriteAtomic's own temp is "<base>.tmp-<rand>" (never ends in ".new"), so a
// clean suffix match is safe.
func rollbackStaged(dir string) error {
	for _, d := range []string{dir, filepath.Join(dir, "wallets")} {
		entries, err := os.ReadDir(d)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return errWrap(CodeStateCorrupt, "scanning for rotation artifacts", err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if strings.HasSuffix(e.Name(), stagedSuffix) {
				_ = os.Remove(filepath.Join(d, e.Name()))
			}
		}
	}
	return nil
}

// ── keystore info (read-only) ─────────────────────────────────────────────────

// Info is the read-only keystore summary (path, format, KDF template, counts). No
// unlock required.
type Info struct {
	Path        string
	Format      int
	Initialized bool
	Wallets     int
	KDF         string
	ScryptN     int
}

// KeystoreInfo reports keystore metadata without unlocking anything: the dir, the
// manifest format/KDF template, whether it is initialized, and the wallet count.
func (s *Store) KeystoreInfo(ctx context.Context) (Info, error) {
	out := Info{Path: s.dir}
	man, err := s.loadManifest()
	if err != nil {
		return Info{}, err
	}
	if man != nil {
		out.Initialized = true
		out.Format = man.Format
		out.KDF = man.KDFDefaults.KDF
		out.ScryptN = man.KDFDefaults.N
	}
	m, err := s.loadMeta()
	if err != nil {
		return Info{}, err
	}
	out.Wallets = len(m.Wallets)
	return out, nil
}
