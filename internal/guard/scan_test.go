package guard

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestScannedTreeCoversTheModule is the guard on the guards.
//
// Every check in this package passes when the loader returns nothing, so a
// loader that walked the wrong directory, or skipped one too many, would turn
// all of them green while checking not one file. That failure is invisible in a
// test log - three passing tests that scanned an empty list look exactly like
// three passing tests that scanned the repository.
func TestScannedTreeCoversTheModule(t *testing.T) {
	tr := mustLoadModule(t)

	if tr.modulePath != "github.com/donislawdev/certdoctor" {
		t.Errorf("module path read from go.mod is %q, want github.com/donislawdev/certdoctor", tr.modulePath)
	}

	scanned := map[string]bool{}
	for _, f := range tr.files {
		scanned[f.rel] = true
	}

	// Known files, one per layer that exists today. When a layer gains its first
	// file this list gains a line, which is the point: it fails loudly rather
	// than quietly covering less than it claims.
	for _, want := range []string{
		"internal/core/status/status.go",
		"internal/core/exitcode/code.go",
		"internal/adapter/render/appearance.go",
		"internal/guard/scan.go",
		"cmd/certdoctor/main.go",
	} {
		if !scanned[want] {
			t.Errorf("%s was not scanned - the loader is missing part of the module", want)
		}
	}

	for _, f := range tr.files {
		if strings.HasPrefix(f.rel, "internal_tools/") {
			t.Errorf("%s was scanned - internal_tools is outside version control and must never be policed", f.rel)
		}
		if strings.Contains(f.rel, "/testdata/") {
			t.Errorf("%s was scanned - testdata holds the deliberately broken fixtures", f.rel)
		}
	}
}

// TestLoaderSkipsWhatIsNotOursToPolice exercises the walking rules against a
// fixture tree.
//
// It exists because the rule that matters most - a directory carrying its own
// go.mod belongs to a different module - is invisible in this repository. The
// only nested module here lives under internal_tools, which is skipped by name
// first, so the nested-module branch never runs and a break in it would show up
// nowhere.
func TestLoaderSkipsWhatIsNotOursToPolice(t *testing.T) {
	root := t.TempDir()
	write(t, root, "go.mod", "module fixture\n\ngo 1.26\n")
	write(t, root, "kept.go", "package fixture\n")
	write(t, root, "kept_test.go", "package fixture\n")
	write(t, root, "deeper/kept.go", "package deeper\n")
	write(t, root, "notgo.txt", "package fixture\n")
	write(t, root, ".git/hidden.go", "package hidden\n")
	write(t, root, "testdata/fixture.go", "package fixture\n")
	write(t, root, "internal_tools/tool.go", "package tool\n")
	write(t, root, "vendor/dep.go", "package dep\n")
	write(t, root, "nested/go.mod", "module nested\n\ngo 1.26\n")
	write(t, root, "nested/inner.go", "package inner\n")

	tr, err := loadTree(root, "fixture")
	if err != nil {
		t.Fatalf("loading the fixture tree: %v", err)
	}

	var got []string
	for _, f := range tr.files {
		got = append(got, f.rel)
	}
	want := []string{"deeper/kept.go", "kept.go", "kept_test.go"}
	if len(got) != len(want) {
		t.Fatalf("scanned %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("scanned %v, want %v - order must be stable so findings do not shuffle between runs", got, want)
		}
	}

	for _, f := range tr.files {
		wantTest := f.rel == "kept_test.go"
		if f.isTest != wantTest {
			t.Errorf("%s has isTest=%v, want %v - the guards decide what to skip from this flag", f.rel, f.isTest, wantTest)
		}
	}
}

// TestLoaderReportsAParseFailureRatherThanSkippingIt pins the ban on silence. A
// file the scanner could not read must stop the run, because reporting "clean"
// about a file nobody looked at is the failure mode this whole package exists to
// prevent.
func TestLoaderReportsAParseFailureRatherThanSkippingIt(t *testing.T) {
	root := t.TempDir()
	write(t, root, "go.mod", "module fixture\n\ngo 1.26\n")
	write(t, root, "broken.go", "package fixture\n\nfunc (\n")

	_, err := loadTree(root, "fixture")
	if err == nil {
		t.Fatal("a file that will not parse was skipped silently")
	}
	if !strings.Contains(err.Error(), "broken.go") {
		t.Errorf("the error does not name the file: %v", err)
	}
}

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("creating the directory for %s: %v", rel, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing %s: %v", rel, err)
	}
}

func mustLoadModule(t *testing.T) tree {
	t.Helper()
	tr, err := loadModule()
	if err != nil {
		t.Fatalf("loading the module tree: %v", err)
	}
	if len(tr.files) == 0 {
		t.Fatal("the module tree is empty - every guard in this package would pass without checking anything")
	}
	return tr
}

// loadFixture parses a file from testdata and presents it under the path it is
// pretending to live at, so a check that keys off location can be exercised
// without planting a real violation in the tree.
func loadFixture(t *testing.T, name, pretendRel string) sourceFile {
	t.Helper()
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, filepath.Join("testdata", name), nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing fixture %s: %v", name, err)
	}
	return sourceFile{
		rel:    pretendRel,
		isTest: strings.HasSuffix(pretendRel, "_test.go"),
		fset:   fset,
		file:   parsed,
	}
}

func requireNoFindings(t *testing.T, findings []Finding, rule string) {
	t.Helper()
	if len(findings) == 0 {
		return
	}
	t.Errorf("%s - %d violation(s):", rule, len(findings))
	for _, f := range findings {
		t.Errorf("  %s", f)
	}
}

// requireFinding asserts that the scanner reported a specific violation. The
// canaries use it rather than a bare count, because a scanner reporting the
// right number of the wrong things would pass a count.
func requireFinding(t *testing.T, findings []Finding, wantDetail string) {
	t.Helper()
	for _, f := range findings {
		if strings.Contains(f.Detail, wantDetail) {
			return
		}
	}
	t.Errorf("the scanner did not report %q. It reported: %v", wantDetail, findings)
}
