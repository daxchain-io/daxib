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
// `out` is the human writer (stderr) for the interactive prompts; `in` is the
// injected input stream (cmd.InOrStdin() in production), read instead of os.Stdin
// directly so the ceremony is testable (KNOWN-3). The function returns how the
// result should treat the mnemonic. A nil `in` falls back to os.Stdin.
func mnemonicCeremony(out io.Writer, in io.Reader, yes, jsonMode bool, mnemonic, bip39 string) (mnemonicDisplay, error) {
	if yes || jsonMode {
		return mnemonicDisplay{echoInResult: true}, nil
	}
	if in == nil {
		in = os.Stdin
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

	reader := bufio.NewReader(in)
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

// txConfirm is the human-readable summary of a money-moving op shown at the y/N
// confirmation prompt (AF-3). Every field is a display string the CLI already holds
// from flags — no float, no secret. Empty fields are omitted from the prompt so a
// speedup/cancel (which has no fixed amount/recipient yet) reads cleanly.
type txConfirm struct {
	Action    string // "Send" | "Speed up" | "Cancel"
	Recipient string // --to (send); the original txid (speedup/cancel)
	Amount    string // --amount as typed (send only)
	Fee       string // --fee-rate "<n> sat/vByte" or "--speed <tier>" or "backend fast estimate"
	Network   string // resolved network label, or "(default)" when unresolved at flag/env time
}

// confirmTxSend is the AF-3 interactive guard for the money-moving ops (tx
// send/speedup/cancel). It is factored out of the commands so it is unit-testable:
// the caller passes whether stdin is a TTY, the --yes flag, the streams, and the
// summary. Behavior:
//
//   - --yes: skip the prompt, authorize (proceed=true). (--yes is the documented
//     "skip confirmations" escape — now honest, because there IS a prompt to skip.)
//   - interactive (TTY) without --yes: print the summary + a "Proceed? [y/N]" prompt;
//     proceed ONLY on an explicit yes/y (case-insensitive). Anything else aborts with
//     usage.confirmation_required (the operator declined).
//   - non-TTY without --yes: do NOT prompt (there is no TTY to read) — return
//     proceed=false with NO error, leaving the service's existing
//     usage.confirmation_required gate to fire (the historical contract is preserved:
//     a non-interactive money mover must pass --yes).
//
// proceed=true means "go ahead and call the service" (and pass Yes=true, since the
// operator has now confirmed). proceed=false with a nil error is the non-TTY pass-
// through; proceed=false with an error is an explicit decline.
func confirmTxSend(out io.Writer, in io.Reader, isTTY, yes bool, c txConfirm) (proceed bool, err error) {
	if yes {
		return true, nil
	}
	if !isTTY {
		// No TTY to prompt at: defer to the service's confirmation_required gate.
		return false, nil
	}
	if in == nil {
		in = os.Stdin
	}

	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintln(out, "Confirm this transaction:")
	if c.Action != "" {
		_, _ = fmt.Fprintf(out, "  action:    %s\n", c.Action)
	}
	if c.Recipient != "" {
		_, _ = fmt.Fprintf(out, "  recipient: %s\n", c.Recipient)
	}
	if c.Amount != "" {
		_, _ = fmt.Fprintf(out, "  amount:    %s\n", c.Amount)
	}
	if c.Fee != "" {
		_, _ = fmt.Fprintf(out, "  fee:       %s\n", c.Fee)
	}
	if c.Network != "" {
		_, _ = fmt.Fprintf(out, "  network:   %s\n", c.Network)
	}
	_, _ = fmt.Fprint(out, "Proceed? [y/N] ")

	reader := bufio.NewReader(in)
	line, _ := reader.ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	default:
		return false, domain.New("usage.confirmation_required",
			"aborted at the confirmation prompt (answer 'y' to proceed, or pass --yes to skip the prompt)")
	}
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
