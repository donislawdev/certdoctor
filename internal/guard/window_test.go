package guard

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"strconv"
	"testing"
)

// THE WINDOW READS THE SCHEMA THE COMMAND LINE WRITES (ADR121 point 1). The
// window refuses a document whose schema_version is not the one it reads, and
// it may not import the renderer that declares the version (ADR124) - so the
// two constants are compared here, read out of the source of both, the way
// this package reads everything: without importing either.
//
// Without this, a MINOR raised in the renderer would leave the window refusing
// every report of its own release with a sentence about another version, and
// the first to notice would be a person with the window open.

// schemaSides are the two declarations, as file and constant.
var schemaSides = [2]struct{ file, name string }{
	{"internal/adapter/render/json.go", "SchemaVersion"},
	{"internal/gui/model/model.go", "SchemaVersion"},
}

// TestTheWindowReadsTheSchemaTheCommandLineWrites compares the two.
func TestTheWindowReadsTheSchemaTheCommandLineWrites(t *testing.T) {
	values := bothSides(t, schemaSides, "the schema the window reads")
	if values[0] != values[1] {
		t.Errorf("the command line writes schema %q (%s) and the window reads %q (%s) - the window would refuse every "+
			"report of its own release", values[0], schemaSides[0].file, values[1], schemaSides[1].file)
	}
}

// THE WINDOW LEADS TO THE REPOSITORY THE SBOM NAMES (ADR122). GitHub on the
// window's bar and the namespace of the software bill of materials both say
// where this project lives, and neither can import the other: the SBOM's is
// the constant of a command, and the window imports nothing of a command.
// So the two are read out of the source and compared, as the schema is - a
// project that moves would otherwise move in one of them.
var repositorySides = [2]struct{ file, name string }{
	{"cmd/sbom/spdx.go", "repository"},
	{"internal/gui/words/words.go", "RepositoryURL"},
}

// TestTheWindowLeadsToTheRepositoryTheSBOMNames compares the two.
func TestTheWindowLeadsToTheRepositoryTheSBOMNames(t *testing.T) {
	values := bothSides(t, repositorySides, "the repository GitHub leads to")
	if values[0] != values[1] {
		t.Errorf("the SBOM names the repository %q (%s) and the window's GitHub leads to %q (%s)",
			values[0], repositorySides[0].file, values[1], repositorySides[1].file)
	}
}

// bothSides reads the two string constants a guard compares, failing when a
// file or a constant is not there - a guard with nothing to read would be
// green about nothing. what names the guard in that failure.
func bothSides(t *testing.T, sides [2]struct{ file, name string }, what string) [2]string {
	t.Helper()
	tr := mustLoadModule(t)
	var values [2]string
	for i, side := range sides {
		sf, ok := fileOf(tr, side.file)
		if !ok {
			t.Fatalf("%s is not in the tree - the guard on %s has nothing to read", side.file, what)
		}
		value, found := stringConstant(sf.file, side.name)
		if !found {
			t.Fatalf("%s declares no string constant %s", side.file, side.name)
		}
		values[i] = value
	}
	return values
}

// TestTheSchemaConstantIsReadAndNothingElse is the canary of the reading
// above: the constant is found by its name, in a group or on its own, and a
// variable or a constant of another name is not it.
func TestTheSchemaConstantIsReadAndNothingElse(t *testing.T) {
	for _, c := range []struct {
		label, src, want string
		found            bool
	}{
		{"a constant on its own", "package p\n\nconst SchemaVersion = \"9.1\"\n", "9.1", true},
		{"a constant in a group", "package p\n\nconst (\n\tOther = \"x\"\n\tSchemaVersion = \"9.2\"\n)\n", "9.2", true},
		{"a variable of the name", "package p\n\nvar SchemaVersion = \"9.3\"\n", "", false},
		{"a constant of another name", "package p\n\nconst Schema = \"9.4\"\n", "", false},
		{"a constant that is not a string", "package p\n\nconst SchemaVersion = 9\n", "", false},
		// A rune unquotes as well as a string does, so only the kind of the
		// literal tells it from the version.
		{"a rune constant", "package p\n\nconst SchemaVersion = 'x'\n", "", false},
	} {
		got, found := stringConstant(sourceFrom(t, "p/p.go", c.src).file, "SchemaVersion")
		if got != c.want || found != c.found {
			t.Errorf("%s: read %q (found %v), want %q (found %v)", c.label, got, found, c.want, c.found)
		}
	}
}

// fileOf is the file of the tree at rel.
func fileOf(tr tree, rel string) (sourceFile, bool) {
	for _, sf := range tr.files {
		if sf.rel == filepath.ToSlash(rel) {
			return sf, true
		}
	}
	return sourceFile{}, false
}

// stringConstant is the value of the string constant name declared at the top
// of f.
func stringConstant(f *ast.File, name string) (string, bool) {
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs := spec.(*ast.ValueSpec)
			for i, id := range vs.Names {
				if id.Name != name || i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return "", false
				}
				value, err := strconv.Unquote(lit.Value)
				return value, err == nil
			}
		}
	}
	return "", false
}
