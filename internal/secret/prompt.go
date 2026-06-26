package secret

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// promptFunc reads a secret from the terminal with echo disabled and prints a
// trailing newline (ReadPassword swallows the user's Enter). It is a package
// variable so tests can stub the actual TTY read without a real terminal. It is
// the DEFAULT used by Acquire when Request.Prompt is nil. Production callers (the
// cli frontend) inject their OWN host prompt through Options.Secret.Prompt →
// Request.Prompt — the frontend may not import this provider (the arch matrix
// forbids frontend→secret), so it builds an equivalent reader from os + x/term —
// keeping the interactive paths testable and the core free of a real TTY read.
//
// label is the prompt shown on stderr (so stdout stays clean for piping); the
// returned bytes are the raw secret with the trailing newline already consumed
// by ReadPassword.
var promptFunc = func(label string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	fmt.Fprint(os.Stderr, label)
	pw, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	return pw, nil
}

// IsTerminal reports whether the given reader is an interactive terminal. Only
// *os.File can be a terminal; anything else (a pipe, a bytes.Buffer in tests) is
// not.
//
// It is a daxie-parity surface (DLC-1): the cli frontend wires its own isTTY via
// term.IsTerminal(os.Stdin.Fd()) directly (cli/open.go), so this helper has no
// current caller in daxib. It is retained verbatim to mirror daxie's secret package
// (where it is likewise an unused convenience) rather than diverge the port.
func IsTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}
