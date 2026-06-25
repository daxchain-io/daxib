package cli

import (
	"context"
	"errors"
	"io"

	"github.com/daxchain-io/daxib/internal/cli/render"
	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/spf13/cobra"
)

// render.go owns the SINGLE typed-error → exit-code funnel for the whole CLI
// surface. Every command's error passes through mapError, which projects it onto
// a *domain.Error and writes the error envelope to stderr via the render
// subpackage. The numeric registry itself lives in domain.ExitOf — this file is
// the frontend's one place that consults it. No command sets an exit code
// directly.
//
// Classification rule (no brittle string matching):
//   - a *domain.Error funnels straight through the registry (its Exit field);
//   - context.Canceled / DeadlineExceeded (Ctrl-C, SIGTERM, --timeout) is the
//     OK-ish cancellation path surfaced as a usage-class interruption;
//   - any OTHER plain error reaching the funnel originated in Cobra/pflag
//     command-line parsing (unknown command, unknown flag, bad arg count),
//     because every command RunE in this package returns a *domain.Error for its
//     own failures — so a non-domain error is by construction a USAGE error.

// mapError is the central error→exit projection. It returns the process exit
// code and writes the appropriate stderr rendering. A nil error returns ExitOK
// and writes nothing.
func mapError(stderr io.Writer, m render.Mode, err error) int {
	if err == nil {
		return int(domain.ExitOK)
	}

	// A typed domain error funnels straight through the registry.
	var de *domain.Error
	if errors.As(err, &de) {
		return int(render.ErrorEnvelope(stderr, m, de))
	}

	// Cancellation (signal/timeout). main installs a SIGTERM/SIGINT context; a
	// canceled run is a usage-class interruption, not a daxib bug. Surface it
	// honestly rather than as exit 1.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		ce := domain.New("usage.canceled", "operation canceled")
		return int(render.ErrorEnvelope(stderr, m, ce))
	}

	// Any remaining plain error came from Cobra/pflag parsing → USAGE (exit 2).
	// Command bodies in this package never return a bare error for their own
	// failures, so this branch is exactly the command-line-grammar case.
	ue := domain.New("usage.cli", err.Error())
	return int(render.ErrorEnvelope(stderr, m, ue))
}

// flagErrorFunc is installed on the root so flag-parse failures carry a clear
// message; classification still happens in mapError (flag errors are plain
// errors → USAGE there). Returning the error unchanged keeps Cobra from printing
// it (SilenceErrors) while letting the funnel render it.
func flagErrorFunc(_ *cobra.Command, err error) error { return err }
