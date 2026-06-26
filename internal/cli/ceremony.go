package cli

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/daxchain-io/daxib/internal/domain"
)

// mnemonicDisplay reports how a freshly created mnemonic was handled: when
// echoInResult is true the result keeps the mnemonic (the --yes / non-interactive
// path), otherwise the TTY ceremony already displayed + verified it and the
// frontend must redact it from the result.
type mnemonicDisplay struct {
	echoInResult bool
}

// preflightMnemonicDisplay refuses a `wallet create` whose fresh mnemonic could
// not be shown: with no TTY, no --yes, and no --json there is no safe channel to
// display the once-only secret, so we fail BEFORE creating the wallet (a distinct,
// non-hanging usage error) rather than silently discarding the backup.
//
// --json is an authoritative channel: under --json the mnemonic travels in the
// structured result (sensitive:true), so it is a valid non-interactive emission
// just like --yes — and the human stderr ceremony is suppressed (mnemonicCeremony
// is json-aware) so the seed is never split between an unstructured stderr line
// and a JSON result that omits it.
func preflightMnemonicDisplay(yes, jsonMode bool) error {
	if yes || jsonMode {
		return nil
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return nil
	}
	return domain.New("usage.confirmation_required",
		"`wallet create` would generate a mnemonic that can only be shown once, but stdin is not a TTY; "+
			"pass --yes to emit it once in the result (and capture it), or run interactively")
}

// mnemonicCeremony performs the once-only mnemonic display.
//
//   - --yes (non-interactive): the mnemonic stays in the result (echoInResult), so
//     the caller emits it exactly once with sensitive:true.
//   - --json: the once-only mnemonic must travel through the structured channel
//     (the JSON result, sensitive:true), not as free-form stderr prose, so the
//     --json output is the single authoritative emission. We treat it like --yes
//     and skip the human ceremony (which would otherwise dump the seed to stderr
//     while the JSON omitted it).
//   - TTY (no --yes, human): show the mnemonic on stderr, wait for the operator,
//     clear it, then require re-entry of two random word positions; on success the
//     mnemonic is redacted from the result (echoInResult=false).
//
// `out` is the human writer (stderr) for the interactive prompts; the function
// returns how the result should treat the mnemonic.
func mnemonicCeremony(out io.Writer, yes, jsonMode bool, mnemonic, bip39 string) (mnemonicDisplay, error) {
	if yes || jsonMode {
		return mnemonicDisplay{echoInResult: true}, nil
	}

	words := strings.Fields(mnemonic)
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintln(out, "RECORD THIS MNEMONIC — it is shown only once and is the only backup:")
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintln(out, "  "+mnemonic)
	if bip39 != "" {
		_, _ = fmt.Fprintln(out, "  bip39-passphrase: "+bip39)
	}
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprint(out, "Press Enter once you have written it down...")

	reader := bufio.NewReader(os.Stdin)
	_, _ = reader.ReadString('\n')

	// Clear the screen so the mnemonic is not left on a shared terminal.
	_, _ = fmt.Fprint(out, "\033[3J\033[2J\033[H")

	// Verify two distinct random word positions.
	a, b, err := twoDistinctPositions(len(words))
	if err != nil {
		return mnemonicDisplay{}, domain.Wrap("internal", "selecting verification positions", err)
	}
	for _, pos := range []int{a, b} {
		_, _ = fmt.Fprintf(out, "Enter word #%d to confirm: ", pos+1)
		line, _ := reader.ReadString('\n')
		got := strings.TrimSpace(strings.ToLower(line))
		if got != strings.ToLower(words[pos]) {
			return mnemonicDisplay{}, domain.Newf("usage.confirmation_required",
				"word #%d did not match; the wallet was created but verify your written copy with `wallet export`", pos+1)
		}
	}
	_, _ = fmt.Fprintln(out, "Mnemonic confirmed.")
	return mnemonicDisplay{echoInResult: false}, nil
}

// twoDistinctPositions returns two distinct random indices in [0, n) (n must be
// >= 2). Uses crypto/rand so the verification positions are unpredictable.
func twoDistinctPositions(n int) (int, int, error) {
	if n < 2 {
		return 0, 0, fmt.Errorf("need at least two words, have %d", n)
	}
	a, err := randInt(n)
	if err != nil {
		return 0, 0, err
	}
	for {
		b, err := randInt(n)
		if err != nil {
			return 0, 0, err
		}
		if b != a {
			return a, b, nil
		}
	}
}

func randInt(n int) (int, error) {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, err
	}
	return int(v.Int64()), nil
}
