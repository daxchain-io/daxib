package cli

import (
	"context"
	"os"
)

// Execute is the single entrypoint cmd/daxib/main calls. It builds the Cobra
// tree, runs it with the cancellable context, funnels any returned error through
// the exit-code registry (mapError), and returns the process exit code. It never
// calls os.Exit itself — main owns that, so Execute stays testable.
//
// The service is opened LAZILY and per-command (each command that needs it opens
// it in its RunE and Closes it). Execute does not open the service up front so an
// empty environment still runs version/completion without provisioning. M1 ships
// only version, which opens nothing at all.
func Execute(ctx context.Context) int {
	rs := &rootState{}
	root := newRootCmd(ctx, rs)

	// Cobra reads os.Args; stdout/stderr default to the process streams. Tests
	// override via the command's SetOut/SetErr.
	root.SetOut(os.Stdout)
	root.SetErr(os.Stderr)

	err := root.ExecuteContext(ctx)
	return mapError(os.Stderr, rs.flags.Mode(), err)
}
