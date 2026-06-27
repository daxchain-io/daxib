// Package archtest enforces the one-core/two-frontends import lattice
// (docs/PLAN.md §1 "one core, two frontends") as a REAL Go test, not a comment or
// a linter config. The depguard rules in .golangci.yml are a fast lint-time belt;
// this test is the load-bearing gate: it goes red the moment the dependency law
// is broken, even with every linter uninstalled.
//
// How it works: it shells out to `go list -json ./...` (the same data the Go
// toolchain uses), reads each module package's DIRECT imports (the Imports /
// TestImports fields — not the transitive closure, so the assertions catch the
// *authored* edge), classifies each package into an architectural layer by its
// import path, and asserts every edge against the allow-matrix below.
//
// The core rules this enforces (the lattice that survives every milestone):
//
//   - internal/domain (the contract) imports NOTHING internal.
//   - internal/version imports NOTHING internal.
//   - internal/cli and internal/mcpserver (the two frontends) must NOT import
//     each other, and may import ONLY service + domain + version (+ their own
//     subpackages, e.g. cli/render).
//   - internal/service (the core) never imports a frontend; it may import domain,
//     version, and the providers.
//   - providers (every other internal leaf) never import the core or a frontend.
//
// M1 ships only domain/version/service/cli/mcpserver, so the matrix is small —
// but it is REAL: a future edit that makes cli import mcpserver, or domain import
// service, or service import cli, turns this test red.
package archtest

import (
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const modulePrefix = "github.com/daxchain-io/daxib"
const internalPrefix = modulePrefix + "/internal/"

// goListPackage is the subset of `go list -json` output this test consumes.
type goListPackage struct {
	ImportPath  string   `json:"ImportPath"`
	Imports     []string `json:"Imports"`     // direct imports of the package's non-test files
	TestImports []string `json:"TestImports"` // direct imports of in-package _test.go files
}

// layer is an architectural class. A package belongs to exactly one layer; an
// import path that matches none is treated as external/stdlib and never
// constrains an edge.
type layer int

const (
	layerExternal layer = iota // stdlib or third-party; not classified
	layerHost                  // cmd/daxib
	layerFrontend              // internal/cli, internal/cli/render, internal/mcpserver(/...)
	layerCore                  // internal/service
	layerContract              // internal/domain
	layerProvider              // every internal leaf (keys, backend, policy, ... — none yet in M1)
	layerVersion               // internal/version
)

func (l layer) String() string {
	switch l {
	case layerHost:
		return "host"
	case layerFrontend:
		return "frontend"
	case layerCore:
		return "core"
	case layerContract:
		return "contract"
	case layerProvider:
		return "provider"
	case layerVersion:
		return "version"
	default:
		return "external"
	}
}

// providerNames is the set of provider package names. None are authored in M1;
// naming the v1 set now (docs/PLAN.md §2, §6, §8) means a future add cannot land
// on the wrong side of the matrix silently — registering it here is the only way
// past TestNoUnclassifiedInternalPackages.
var providerNames = map[string]bool{
	"keys": true, "descriptor": true, "backend": true, "coinselect": true,
	"psbt": true, "policy": true, "policyseal": true, "journal": true,
	"registry": true, "config": true, "secret": true, "fsx": true,
	"btcunit": true, "fee": true, "bip322": true, "contacts": true,
}

// frontendRoots are the package-path leaders (relative to internalPrefix) that
// mark a frontend. Anything under these prefixes is a frontend (so cli/render
// counts too).
var frontendRoots = []string{"cli", "mcpserver"}

// classify maps a full import path to its architectural layer.
func classify(importPath string) layer {
	if importPath == modulePrefix+"/cmd/daxib" {
		return layerHost
	}
	if !strings.HasPrefix(importPath, internalPrefix) {
		return layerExternal
	}
	rel := strings.TrimPrefix(importPath, internalPrefix) // e.g. "cli/render", "service", "domain"
	first := rel
	if i := strings.IndexByte(rel, '/'); i >= 0 {
		first = rel[:i]
	}
	switch first {
	case "version":
		return layerVersion
	case "service":
		return layerCore
	case "domain":
		return layerContract
	}
	for _, fr := range frontendRoots {
		if first == fr {
			return layerFrontend
		}
	}
	if providerNames[first] {
		return layerProvider
	}
	// An unknown internal package is a hard signal the matrix is out of date.
	return layerExternal
}

// frontendOf returns the frontend's short name (e.g. "cli", "mcpserver") for a
// frontend import path, used to enforce the "frontends must not import each
// other" rule.
func frontendOf(importPath string) string {
	rel := strings.TrimPrefix(importPath, internalPrefix)
	if i := strings.IndexByte(rel, '/'); i >= 0 {
		return rel[:i]
	}
	return rel
}

func TestImportMatrix(t *testing.T) {
	pkgs := goListAll(t)

	for _, p := range pkgs {
		from := classify(p.ImportPath)
		if from == layerExternal {
			continue // not one of our governed packages
		}
		for _, imp := range p.Imports {
			checkEdge(t, p.ImportPath, from, imp)
		}
	}
}

// checkEdge asserts a single from→imp edge is permitted by the matrix.
func checkEdge(t *testing.T, fromPath string, from layer, imp string) {
	t.Helper()

	to := classify(imp)
	if to == layerExternal {
		return // stdlib / third-party: not governed by the internal matrix
	}

	switch from {
	case layerHost:
		// cmd/daxib may import cli + version only (it calls cli.Execute).
		if to != layerFrontend && to != layerVersion {
			t.Errorf("HOST VIOLATION: %s imports %s (%s); cmd/daxib may import cli + version only", fromPath, imp, to)
		}
		if to == layerFrontend && frontendOf(imp) != "cli" {
			t.Errorf("HOST VIOLATION: %s imports %s; cmd/daxib may import internal/cli only (the host calls cli.Execute, never mcpserver directly)", fromPath, imp)
		}

	case layerFrontend:
		switch to {
		case layerCore, layerContract, layerVersion:
			// allowed
		case layerFrontend:
			// The two frontends are independent adapters over the same core, with ONE
			// sanctioned cross-frontend edge: cli → mcpserver (the host calls
			// cli.Execute; the cli `mcp serve|tools` command builds mcpserver.New(svc)
			// — Frontend 1 hosting Frontend 2). The REVERSE (mcpserver → cli) stays
			// forbidden: mcpserver never reaches back into the CLI. A frontend importing
			// its OWN subpackage (cli → cli/render, mcpserver → mcpserver/tools) is fine
			// (docs/PLAN.md §1, §6).
			if frontendOf(fromPath) != frontendOf(imp) && (frontendOf(fromPath) != "cli" || frontendOf(imp) != "mcpserver") {
				t.Errorf("FRONTEND VIOLATION: %s imports the other frontend %s; only the cli → mcpserver wiring edge is sanctioned (mcpserver must never import cli)", fromPath, imp)
			}
		case layerProvider:
			t.Errorf("FRONTEND VIOLATION: %s imports provider %s; frontends import service+domain(+version) only", fromPath, imp)
		default:
			t.Errorf("FRONTEND VIOLATION: %s imports %s (%s); frontends import service+domain(+version) only", fromPath, imp, to)
		}

	case layerCore:
		// service may import domain + version + every provider; never a frontend.
		if to == layerFrontend {
			t.Errorf("CORE VIOLATION: %s (service) imports frontend %s; the core never imports a frontend", fromPath, imp)
		}

	case layerContract:
		// domain imports nothing internal.
		if to != layerExternal {
			t.Errorf("CONTRACT VIOLATION: %s (domain) imports internal package %s; domain imports nothing internal", fromPath, imp)
		}

	case layerProvider:
		switch to {
		case layerCore:
			t.Errorf("PROVIDER VIOLATION: %s imports service; providers are leaves and never import the core", fromPath)
		case layerFrontend:
			t.Errorf("PROVIDER VIOLATION: %s imports frontend %s; providers never import a frontend", fromPath, imp)
		}

	case layerVersion:
		if to != layerExternal {
			t.Errorf("VERSION VIOLATION: %s imports internal package %s; version imports nothing internal", fromPath, imp)
		}
	}
}

// TestNoUnclassifiedInternalPackages closes the silent-un-governance gap:
// classify() returns layerExternal for an internal path it does not recognize,
// and TestImportMatrix skips every layerExternal source — so a brand-new internal
// package (not in providerNames/frontendRoots and not under version/service/
// domain) would land with ZERO import-matrix enforcement. This makes that a HARD
// failure: every package under internalPrefix MUST classify to a governed layer,
// forcing whoever adds internal/foo to register it (and the depguard lattice in
// .golangci.yml) or this test goes red.
func TestNoUnclassifiedInternalPackages(t *testing.T) {
	for _, p := range goListAll(t) {
		if !strings.HasPrefix(p.ImportPath, internalPrefix) {
			continue // cmd/daxib is the host and classifies explicitly
		}
		if classify(p.ImportPath) == layerExternal {
			t.Errorf("UNCLASSIFIED INTERNAL PACKAGE: %s classifies to layerExternal and is therefore ungoverned by the import matrix; register it in providerNames or frontendRoots (and the depguard lattice in .golangci.yml) so it lands on the correct side of the matrix", p.ImportPath)
		}
	}
}

// TestFrontendsDoNotImportEachOther is the explicit, file-scoped twin of the
// cross-frontend rule in TestImportMatrix: no file in internal/cli may import
// internal/mcpserver and vice versa. The package-level matrix already enforces
// this; this sweep makes the "one core, two INDEPENDENT frontends" guarantee a
// load-bearing per-package regression guard (docs/PLAN.md §1) that engages the
// moment either frontend grows real files.
func TestFrontendsDoNotImportEachOther(t *testing.T) {
	for _, p := range goListAll(t) {
		if classify(p.ImportPath) != layerFrontend {
			continue
		}
		self := frontendOf(p.ImportPath)
		for _, imp := range append(append([]string{}, p.Imports...), p.TestImports...) {
			if classify(imp) != layerFrontend || frontendOf(imp) == self {
				continue
			}
			// The ONE sanctioned cross-frontend edge: cli → mcpserver (the `mcp serve|
			// tools` command builds mcpserver.New(svc)). The reverse stays forbidden.
			if self == "cli" && frontendOf(imp) == "mcpserver" {
				continue
			}
			t.Errorf("CROSS-FRONTEND IMPORT: %s imports %s; only cli → mcpserver is sanctioned (mcpserver must never import cli)", p.ImportPath, imp)
		}
	}
}

// TestMcpserverImportsNoProvider is the explicit, per-package guard that the MCP
// server (Frontend 2) has the SAME import allowlist as the CLI: it may import ONLY
// service + domain + version (+ its own subpackage internal/mcpserver/tools) of the
// governed internal layers, plus stdlib/third-party (the MCP SDK + jsonschema-go,
// which classify external). It must NOT import ANY provider — that is what makes it
// physically unable to skip the policy.Reserve chokepoint or reach the keystore: a
// provider import is the ONLY way to do business logic, and the lattice denies it.
//
// The package-level TestImportMatrix already enforces this as a FRONTEND VIOLATION;
// this focused test makes the §6 "mcpserver imports service+domain(+version) only"
// guarantee a named, load-bearing regression guard — add (say) an internal/policy
// import to a mcpserver file and this goes red with a pointed message.
func TestMcpserverImportsNoProvider(t *testing.T) {
	for _, p := range goListAll(t) {
		// Both the core package and its tools subpackage are Frontend 2.
		if p.ImportPath != modulePrefix+"/internal/mcpserver" &&
			!strings.HasPrefix(p.ImportPath, modulePrefix+"/internal/mcpserver/") {
			continue
		}
		for _, imp := range append(append([]string{}, p.Imports...), p.TestImports...) {
			switch classify(imp) {
			case layerProvider:
				t.Errorf("MCPSERVER VIOLATION: %s imports provider %s; Frontend 2 imports service+domain(+version) only — a provider import is the only way to skip the policy.Reserve chokepoint, and the lattice forbids it", p.ImportPath, imp)
			case layerCore, layerContract, layerVersion, layerExternal:
				// allowed: service (core), domain (contract), version, and the MCP SDK /
				// jsonschema-go (external/third-party).
			case layerFrontend:
				// Only mcpserver's OWN packages (core ↔ tools subpackage); the
				// cross-frontend rule (cli) is covered by TestFrontendsDoNotImportEachOther.
				if frontendOf(imp) != "mcpserver" {
					t.Errorf("MCPSERVER VIOLATION: %s imports the other frontend %s; the two frontends are independent", p.ImportPath, imp)
				}
			case layerHost:
				t.Errorf("MCPSERVER VIOLATION: %s imports the host %s", p.ImportPath, imp)
			}
		}
	}
}

// goListAll runs `go list -json ./...` and returns every package in this module
// (no -deps: we assert on the module's own packages and their DIRECT imports;
// classify() gates so external import targets never constrain an edge).
func goListAll(t *testing.T) []goListPackage {
	t.Helper()
	cmd := exec.Command("go", "list", "-json", "./...")
	cmd.Dir = moduleRoot(t)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("go list failed: %v\nstderr:\n%s", err, ee.Stderr)
		}
		t.Fatalf("go list failed: %v", err)
	}
	var pkgs []goListPackage
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for dec.More() {
		var p goListPackage
		if err := dec.Decode(&p); err != nil {
			t.Fatalf("decoding go list output: %v", err)
		}
		pkgs = append(pkgs, p)
	}
	if len(pkgs) == 0 {
		t.Fatal("go list returned no packages")
	}
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].ImportPath < pkgs[j].ImportPath })
	return pkgs
}

// moduleRoot returns the module root by asking the toolchain, so the test runs
// correctly regardless of which package directory `go test` invokes it from.
func moduleRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", modulePrefix).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("locating module root: %v\nstderr:\n%s", err, ee.Stderr)
		}
		t.Fatalf("locating module root: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// TestDomainFilesImportNothingInternal is the file-scoped twin of the contract
// rule: every non-test .go file under internal/domain may import stdlib/external
// only — NEVER another internal package. The package-level matrix already
// enforces this; this per-file sweep makes "domain is the wire contract, it
// depends on nothing of ours" a load-bearing regression guard that engages the
// moment domain grows files, and it exercises the fileImports AST helper the
// later per-file guards (the M-NN "files on the correct side" tests) will reuse.
func TestDomainFilesImportNothingInternal(t *testing.T) {
	dir := filepath.Join(moduleRoot(t), "internal", "domain")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading internal/domain: %v", err)
	}
	for _, e := range entries {
		fn := e.Name()
		if e.IsDir() || !strings.HasSuffix(fn, ".go") || strings.HasSuffix(fn, "_test.go") {
			continue
		}
		for _, imp := range fileImports(t, filepath.Join(dir, fn)) {
			if strings.HasPrefix(imp, modulePrefix) {
				t.Errorf("CONTRACT VIOLATION: internal/domain/%s imports %s; domain imports nothing internal (it is the wire contract)", fn, imp)
			}
		}
	}
}

// fileImports parses one Go file and returns its direct import paths (unquoted).
func fileImports(t *testing.T, path string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	out := make([]string, 0, len(f.Imports))
	for _, spec := range f.Imports {
		out = append(out, strings.Trim(spec.Path.Value, `"`))
	}
	return out
}
