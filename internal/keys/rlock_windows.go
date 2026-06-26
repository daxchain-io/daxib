//go:build windows

package keys

import (
	"context"
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"

	"github.com/daxchain-io/daxib/internal/fsx"
)

// readRetryAttempts / readRetryBackoff bound the ERROR_ACCESS_DENIED retry a
// Windows lock-free-ish reader does when it catches a name in pending-delete
// during a concurrent writer's atomic rename (§3.3/§7.9).
const (
	readRetryAttempts = 10
	readRetryBackoff  = 10 * time.Millisecond
)

// readKeystoreFile reads a keystore data file for the Windows reader path
// (§3.3, §7.9). Windows needs the reader to (1) take the SHARED fsx.RLock on the
// keystore's sibling .lock — the same lock object every writer takes
// exclusively — so a reader holding the data file open does not break a
// concurrent writer's MoveFileEx rename, and (2) retry transient
// ERROR_ACCESS_DENIED, which surfaces when a name is in pending-delete during
// that rename. The shared lock is taken against lockPath() (the sibling
// index.lock) so all keystore reads/writes contend on one lock object.
func (s *Store) readKeystoreFile(path string) ([]byte, error) {
	// If THIS Store already holds the exclusive index.lock (a mutation reading its
	// own meta.json/keystore.json), do NOT take the shared RLock: Windows
	// LockFileEx is mandatory and not re-entrant across handles, so an
	// exclusive-then-shared acquire on the same .lock from the same process
	// deadlocks until timeout (state.lock_timeout / exit 11).
	if s.holdingExclusive() {
		return readWithAccessDeniedRetry(path)
	}

	ctx, cancel := context.WithTimeout(context.Background(), lockTimeout)
	defer cancel()

	unlock, err := fsx.RLock(ctx, s.lockPath())
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return nil, errKeys(CodeStateLockTimeout, "timed out acquiring the keystore read lock; another daxib process may be holding it exclusively")
		}
		// Could not create/acquire the shared lock (e.g. read-only mount). Fall
		// through to the retry-read, which tolerates the rename race on its own.
		return readWithAccessDeniedRetry(path)
	}
	defer unlock()
	return readWithAccessDeniedRetry(path)
}

// readWithAccessDeniedRetry reads path, retrying a bounded number of times on
// ERROR_ACCESS_DENIED (a name in pending-delete during a concurrent atomic
// rename, §7.9). A non-ACCESS_DENIED error returns immediately.
func readWithAccessDeniedRetry(path string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < readRetryAttempts; attempt++ {
		b, err := os.ReadFile(path) // #nosec G304 -- path is a keystore file under the store's own dir
		if err == nil {
			return b, nil
		}
		lastErr = err
		if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return nil, err
		}
		time.Sleep(readRetryBackoff)
	}
	return nil, lastErr
}
