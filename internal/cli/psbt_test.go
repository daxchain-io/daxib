package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/daxchain-io/daxib/internal/domain"
)

// execCLIStdin is execCLI with a PSBT (or any text) wired into cobra's input
// stream, so the --psbt-stdin air-gapped pipe is exercised end to end. (Unlike
// secrets, a PSBT is NOT routed around cobra's SetIn — resolvePSBT reads
// cmd.InOrStdin() directly, which SetIn feeds.)
func execCLIStdin(t *testing.T, stdin string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var outBuf, errBuf bytes.Buffer
	rs := &rootState{}
	ctx := context.Background()
	root := newRootCmd(ctx, rs)
	root.SetArgs(args)
	root.SetOut(&outBuf)
	root.SetErr(&errBuf)
	root.SetIn(strings.NewReader(stdin))
	err := root.ExecuteContext(ctx)
	code = mapError(&errBuf, effectiveMode(rs.flags.Mode(), args), err)
	return outBuf.String(), errBuf.String(), code
}

// readFile reads a file written by --out for the round-trip assertions.
func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// psbt_test.go is the CLI SURFACE harness for the `psbt` noun: the resolvePSBT
// exactly-one-of grammar (positional / --psbt-file / --psbt-stdin), the pure-verb
// round-trip (combine → finalize → extract on offline fixtures), the read-only
// decode JSON shape, --out file emission, and the money-authorizing-verb (sign /
// broadcast) --yes/TTY confirmation gate (a non-TTY run without --yes is
// usage.confirmation_required, exit 2, BEFORE any backend dial). The authoritative
// engine proof of the policy chokepoint (a denial yields NO PartialSig) lives at the
// service layer (internal/service/psbt_test.go); these tests pin the frontend
// grammar without a backend.
//
// The fixtures are valid base64 PSBTs spending a fixed P2WPKH prevout (a key the
// canonical `vec` wallet does NOT own — so they double as the not-owned case). They
// were generated offline via the psbt leaf (BuildFromUnsigned + a real
// txscript.WitnessSignature); fixSignedPSBT carries one valid PartialSig and so
// finalizes + extracts to a complete network tx.
const (
	// fixUnsignedPSBT: 1-in/1-out unsigned PSBT (no PartialSigs).
	fixUnsignedPSBT = "cHNidP8BAFICAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACrAAAAAAD9////AZBfAQAAAAAAFgAUZ4APkmAEFQ9HVhSi1Hf4Q1a0onQAAAAAAAEBH6CGAQAAAAAAFgAUJ6XuSi5Ec+P0zftQCvZo+Pl9YjUAAA=="
	// fixSignedPSBT: the same unsigned tx with one valid P2WPKH PartialSig attached.
	fixSignedPSBT = "cHNidP8BAFICAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACrAAAAAAD9////AZBfAQAAAAAAFgAUZ4APkmAEFQ9HVhSi1Hf4Q1a0onQAAAAAAAEBH6CGAQAAAAAAFgAUJ6XuSi5Ec+P0zftQCvZo+Pl9YjUiAgKbl/PhLax6oBFYLIMQSWQL/P8Arf4ANiXbTjTVIg4IXkcwRAIgUi30w2iZ+AfdQBvX3g//rBj9TFYr3dbG/QSA7Pnu5qICIDUayzmSdMpBOpSJYTdjXoth1Y4ryQ5W4z4I4AcRPPdKAQAA"
)

// ── resolvePSBT exactly-one-of grammar ────────────────────────────────────────

// TestPSBTDecodeRequiresInput proves a verb with no PSBT source is
// usage.psbt_required (exit 2).
func TestPSBTDecodeRequiresInput(t *testing.T) {
	isolateKeystore(t)
	importVec(t, "vec", "mainnet")
	_, stderr, code := execCLI(t, "psbt", "decode", "--network", "mainnet")
	if code != int(domain.ExitUsage) {
		t.Fatalf("psbt decode no-input exit=%d, want %d:\n%s", code, domain.ExitUsage, stderr)
	}
	if !strings.Contains(stderr, "psbt_required") {
		t.Errorf("expected usage.psbt_required, got:\n%s", stderr)
	}
}

// TestPSBTDecodeMutualExclusion proves passing both a positional PSBT AND
// --psbt-stdin is a usage error (exit 2) — exactly-one-of.
func TestPSBTDecodeMutualExclusion(t *testing.T) {
	isolateKeystore(t)
	importVec(t, "vec", "mainnet")
	_, stderr, code := execCLI(t, "psbt", "decode", fixUnsignedPSBT, "--psbt-stdin", "--network", "mainnet")
	if code != int(domain.ExitUsage) {
		t.Fatalf("psbt decode two-source exit=%d, want %d:\n%s", code, domain.ExitUsage, stderr)
	}
}

// TestPSBTResolveStdinChannel proves the air-gapped pipe: a PSBT on stdin via
// --psbt-stdin decodes identically to the positional form.
func TestPSBTResolveStdinChannel(t *testing.T) {
	isolateKeystore(t)
	importVec(t, "vec", "mainnet")
	out, _, code := execCLIStdin(t, fixUnsignedPSBT, "psbt", "decode", "--psbt-stdin", "--network", "mainnet", "--json")
	if code != 0 {
		t.Fatalf("psbt decode --psbt-stdin exit=%d, want 0:\n%s", code, out)
	}
	var res domain.PSBTResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("decode --json invalid: %v (%q)", err, out)
	}
	if len(res.Inputs) != 1 || len(res.Outputs) != 1 {
		t.Fatalf("decoded shape = %d in / %d out, want 1/1", len(res.Inputs), len(res.Outputs))
	}
}

// TestPSBTResolveFileChannel proves --psbt-file reads the artifact from disk.
func TestPSBTResolveFileChannel(t *testing.T) {
	isolateKeystore(t)
	importVec(t, "vec", "mainnet")
	pf := writeTempFile(t, "in.psbt", fixUnsignedPSBT+"\n")
	out, stderr, code := execCLI(t, "psbt", "decode", "--psbt-file", pf, "--network", "mainnet", "--json")
	if code != 0 {
		t.Fatalf("psbt decode --psbt-file exit=%d, want 0:\n%s", code, stderr)
	}
	var res domain.PSBTResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("decode --json invalid: %v", err)
	}
	if len(res.Inputs) != 1 {
		t.Fatalf("decoded inputs = %d, want 1", len(res.Inputs))
	}
}

// ── decode JSON shape (read-only) ─────────────────────────────────────────────

// TestPSBTDecodeJSONShape pins the decode envelope: the unsigned fixture is
// incomplete, has zero signatures, and reports one input + one output with sat
// values; the wallet owns none of it (the prevout key is foreign to `vec`).
func TestPSBTDecodeJSONShape(t *testing.T) {
	isolateKeystore(t)
	importVec(t, "vec", "mainnet")
	out, stderr, code := execCLI(t, "psbt", "decode", fixUnsignedPSBT, "--wallet", "vec", "--network", "mainnet", "--json")
	if code != 0 {
		t.Fatalf("psbt decode exit=%d, want 0:\n%s", code, stderr)
	}
	var res domain.PSBTResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("decode --json invalid: %v (%q)", err, out)
	}
	if res.Complete {
		t.Error("an unsigned PSBT must report complete=false")
	}
	if res.SignedByUs != 0 {
		t.Errorf("signed_by_us = %d, want 0 (unsigned)", res.SignedByUs)
	}
	if len(res.Inputs) != 1 || len(res.Outputs) != 1 {
		t.Fatalf("shape = %d in / %d out, want 1/1", len(res.Inputs), len(res.Outputs))
	}
	if res.Inputs[0].Mine {
		t.Error("the foreign prevout must not be flagged mine")
	}
	if res.Inputs[0].ValueSat != 100_000 || res.Outputs[0].ValueSat != 90_000 {
		t.Errorf("values = in %d / out %d, want 100000 / 90000", res.Inputs[0].ValueSat, res.Outputs[0].ValueSat)
	}
	// The signed fixture, by contrast, is finalizable and reports a signature.
	sout, _, scode := execCLI(t, "psbt", "decode", fixSignedPSBT, "--network", "mainnet", "--json")
	if scode != 0 {
		t.Fatalf("decode signed fixture exit=%d", scode)
	}
	var sres domain.PSBTResult
	if err := json.Unmarshal([]byte(sout), &sres); err != nil {
		t.Fatalf("decode signed --json invalid: %v", err)
	}
	if !sres.Inputs[0].Signed {
		t.Error("the signed fixture's input must report signed=true")
	}
}

// ── pure-verb round-trip: combine → finalize → extract ────────────────────────

// TestPSBTCombineFinalizeExtractRoundtrip walks the offline plumbing verbs:
// combine (two PSBTs sharing the unsigned tx — the unsigned + the signed),
// finalize (assemble the witness), then extract (raw network tx hex). All pure: no
// backend, no keystore unlock.
func TestPSBTCombineFinalizeExtractRoundtrip(t *testing.T) {
	isolateKeystore(t)
	importVec(t, "vec", "mainnet")

	// combine the unsigned + signed variants of the SAME unsigned tx → the PartialSig
	// is unioned in. --quiet so stdout is the bare base64 for the next pipe stage.
	combined, stderr, code := execCLI(t, "psbt", "combine", fixUnsignedPSBT, fixSignedPSBT, "--network", "mainnet", "--quiet")
	if code != 0 {
		t.Fatalf("psbt combine exit=%d, want 0:\n%s", code, stderr)
	}
	combined = strings.TrimSpace(combined)
	if combined == "" {
		t.Fatal("combine produced no PSBT")
	}

	// finalize the combined PSBT.
	finalized, fstderr, fcode := execCLI(t, "psbt", "finalize", combined, "--network", "mainnet", "--quiet")
	if fcode != 0 {
		t.Fatalf("psbt finalize exit=%d, want 0:\n%s", fcode, fstderr)
	}
	finalized = strings.TrimSpace(finalized)

	// extract the raw network tx hex from the finalized PSBT.
	raw, estderr, ecode := execCLI(t, "psbt", "extract", finalized, "--network", "mainnet", "--quiet")
	if ecode != 0 {
		t.Fatalf("psbt extract exit=%d, want 0:\n%s", ecode, estderr)
	}
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, " \t\n") {
		t.Fatalf("extract must emit one clean hex line, got %q", raw)
	}
	// The hex is a deserializable signed tx (lowercase hex, even length).
	if len(raw)%2 != 0 {
		t.Fatalf("extracted hex has odd length: %d", len(raw))
	}
}

// TestPSBTExtractIncompleteIsUsageError proves extracting an UNSIGNED PSBT is a
// clean psbt.incomplete usage error (exit 2), never a malformed tx.
func TestPSBTExtractIncompleteIsUsageError(t *testing.T) {
	isolateKeystore(t)
	importVec(t, "vec", "mainnet")
	_, stderr, code := execCLI(t, "psbt", "extract", fixUnsignedPSBT, "--network", "mainnet")
	if code != int(domain.ExitUsage) {
		t.Fatalf("extract incomplete exit=%d, want %d:\n%s", code, domain.ExitUsage, stderr)
	}
	if !strings.Contains(stderr, "psbt.incomplete") {
		t.Errorf("expected psbt.incomplete, got:\n%s", stderr)
	}
}

// TestPSBTDecodeBadPSBTIsUsageError proves an undecodable envelope is
// usage.bad_psbt (exit 2).
func TestPSBTDecodeBadPSBTIsUsageError(t *testing.T) {
	isolateKeystore(t)
	importVec(t, "vec", "mainnet")
	_, stderr, code := execCLI(t, "psbt", "decode", "not-a-psbt!!!", "--network", "mainnet")
	if code != int(domain.ExitUsage) {
		t.Fatalf("bad psbt exit=%d, want %d:\n%s", code, domain.ExitUsage, stderr)
	}
	if !strings.Contains(stderr, "bad_psbt") {
		t.Errorf("expected usage.bad_psbt, got:\n%s", stderr)
	}
}

// TestPSBTOutWritesArtifact proves --out writes the bare PSBT/hex to a file.
func TestPSBTOutWritesArtifact(t *testing.T) {
	isolateKeystore(t)
	importVec(t, "vec", "mainnet")
	dst := writeTempFile(t, "out.psbt", "") // reuse the helper's dir; we overwrite
	_, stderr, code := execCLI(t, "psbt", "finalize", fixSignedPSBT, "--out", dst, "--network", "mainnet")
	if code != 0 {
		t.Fatalf("psbt finalize --out exit=%d, want 0:\n%s", code, stderr)
	}
	got := readFile(t, dst)
	if strings.TrimSpace(got) == "" {
		t.Fatal("--out wrote an empty artifact")
	}
	// The on-disk artifact round-trips back through decode.
	_, dstderr, dcode := execCLI(t, "psbt", "decode", "--psbt-file", dst, "--network", "mainnet")
	if dcode != 0 {
		t.Fatalf("decode of the --out artifact exit=%d:\n%s", dcode, dstderr)
	}
}

// ── money-authorizing verbs: --yes / TTY confirmation gate ────────────────────

// TestPSBTSignNonTTYNoYesIsConfirmRequired proves the AF-3 gate: a non-interactive
// `psbt sign` without --yes is usage.confirmation_required (exit 2) — and it fires
// BEFORE any backend dial (signing authorizes a spend that can leave the box). The
// canonical execCLI stream is not a TTY, so the service's gate fires.
func TestPSBTSignNonTTYNoYesIsConfirmRequired(t *testing.T) {
	isolateKeystore(t)
	importVec(t, "vec", "mainnet")
	_, stderr, code := execCLI(t, "psbt", "sign", fixSignedPSBT, "--wallet", "vec", "--network", "mainnet")
	if code != int(domain.ExitUsage) {
		t.Fatalf("psbt sign non-TTY no-yes exit=%d, want %d:\n%s", code, domain.ExitUsage, stderr)
	}
	if !strings.Contains(stderr, "confirmation_required") {
		t.Errorf("expected usage.confirmation_required, got:\n%s", stderr)
	}
}

// TestPSBTBroadcastNonTTYNoYesIsConfirmRequired proves the same gate on broadcast.
func TestPSBTBroadcastNonTTYNoYesIsConfirmRequired(t *testing.T) {
	isolateKeystore(t)
	importVec(t, "vec", "mainnet")
	_, stderr, code := execCLI(t, "psbt", "broadcast", fixSignedPSBT, "--wallet", "vec", "--network", "mainnet")
	if code != int(domain.ExitUsage) {
		t.Fatalf("psbt broadcast non-TTY no-yes exit=%d, want %d:\n%s", code, domain.ExitUsage, stderr)
	}
	if !strings.Contains(stderr, "confirmation_required") {
		t.Errorf("expected usage.confirmation_required, got:\n%s", stderr)
	}
}

// ── help / flag surface ───────────────────────────────────────────────────────

// TestPSBTHelpListsSubcommands proves the noun wires every verb.
func TestPSBTHelpListsSubcommands(t *testing.T) {
	stdout, _, code := execCLI(t, "psbt", "--help")
	if code != 0 {
		t.Fatalf("psbt --help exit=%d, want 0", code)
	}
	for _, sub := range []string{"create", "sign", "combine", "finalize", "extract", "broadcast", "decode"} {
		if !strings.Contains(stdout, sub) {
			t.Errorf("psbt --help missing subcommand %q:\n%s", sub, stdout)
		}
	}
}

// TestPSBTSignHelpFlags proves the sign verb exposes the PSBT-input channels, --out,
// the passphrase channels, and leaks no EVM flag.
func TestPSBTSignHelpFlags(t *testing.T) {
	stdout, _, code := execCLI(t, "psbt", "sign", "--help")
	if code != 0 {
		t.Fatalf("psbt sign --help exit=%d, want 0", code)
	}
	for _, f := range []string{"--wallet", "--psbt-file", "--psbt-stdin", "--out", "--passphrase-stdin", "--passphrase-file"} {
		if !strings.Contains(stdout, f) {
			t.Errorf("psbt sign --help missing flag %q:\n%s", f, stdout)
		}
	}
	for _, leak := range []string{"--gas-", "--nonce", "--max-fee"} {
		if strings.Contains(stdout, leak) {
			t.Errorf("psbt sign --help leaks EVM flag %q", leak)
		}
	}
}

// TestPSBTCreateMissingToOrAmount proves create's required-flag grammar (exit 2).
func TestPSBTCreateMissingToOrAmount(t *testing.T) {
	isolateKeystore(t)
	importVec(t, "vec", "mainnet")
	if _, _, code := execCLI(t, "psbt", "create", "--amount", "0.001", "--network", "mainnet"); code != int(domain.ExitUsage) {
		t.Errorf("create missing --to exit=%d, want %d", code, domain.ExitUsage)
	}
	if _, _, code := execCLI(t, "psbt", "create", "--to", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "--network", "mainnet"); code != int(domain.ExitUsage) {
		t.Errorf("create missing --amount exit=%d, want %d", code, domain.ExitUsage)
	}
}
