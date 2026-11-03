package guard

import (
	"fmt"
	"go/ast"
	"go/token"
	"testing"
)

// The window names the report's closed lists in words of its own - a kind of
// finding is the title of a card, a reason for UNKNOWN is the line under a
// layer's name - and the lists themselves live in the core.
//
// WHY A GUARD AND NOT AN IMPORT. The window knows the report's contract and
// not the core's types (ADR121), so the catalogue spells each value as the
// document does rather than reaching for the constant. That is a second
// spelling of a list, and a list held in two places is the one that drifts:
// a kind added to the core would reach the window as its raw name, and nobody
// would see it until a person read "stack_divergence" as a title. This reads
// both lists from the source and holds them equal in both directions.
const (
	windowWords      = "internal/gui/words/words.go"
	findingKindsFile = "internal/core/report/finding.go"
	reasonsFile      = "internal/core/status/reason.go"
)

// TestTheWindowNamesEveryKindOfFinding is the guard for the kinds.
func TestTheWindowNamesEveryKindOfFinding(t *testing.T) {
	tr := mustLoadModule(t)
	requireNoViolations(t, checkWindowNames(tr, "kinds", findingKindsFile, "FindingKind"),
		"a kind of finding the window has no name for")
}

// TestTheWindowNamesEveryReasonForUnknown is the guard for the reasons.
func TestTheWindowNamesEveryReasonForUnknown(t *testing.T) {
	tr := mustLoadModule(t)
	requireNoViolations(t, checkWindowNames(tr, "reasons", reasonsFile, "Reason"),
		"a reason for UNKNOWN the window has no name for")
}

// TestTheWindowNamesGuardCanFail plants a catalogue that names one kind the
// core does not have and leaves out every kind it does, and expects both
// directions to be reported.
func TestTheWindowNamesGuardCanFail(t *testing.T) {
	real := mustLoadModule(t)
	planted := tree{modulePath: real.modulePath}
	for _, sf := range real.files {
		if sf.rel != windowWords {
			planted.files = append(planted.files, sf)
		}
	}
	planted.files = append(planted.files, loadFixture(t, "window_words.go", windowWords))

	violations := checkWindowNames(planted, "kinds", findingKindsFile, "FindingKind")
	requireViolation(t, violations, `"tls_handshake" has no name in the window`)
	requireViolation(t, violations, `"no_such_kind" is named by the window`)
}

// checkWindowNames holds the keys of one map in the window's catalogue equal
// to the string constants of one type in the file of the core that declares
// them.
func checkWindowNames(tr tree, mapName, declaredIn, typeName string) []Violation {
	declared, named := map[string]bool{}, map[string]bool{}
	var wordsFile sourceFile
	for _, sf := range tr.files {
		switch sf.rel {
		case declaredIn:
			for _, v := range constantsOfType(sf, typeName) {
				declared[v] = true
			}
		case windowWords:
			wordsFile = sf
			for _, v := range mapKeys(sf, mapName) {
				named[v] = true
			}
		}
	}
	// Either side read as empty is a moved file or a renamed declaration, and
	// an empty list on both sides would compare equal and check nothing.
	if len(declared) == 0 || len(named) == 0 {
		return []Violation{{windowWords, 1, fmt.Sprintf(
			"read %d values of %s from %s and %d keys of %s from %s - one of the two declarations has moved",
			len(declared), typeName, declaredIn, len(named), mapName, windowWords)}}
	}
	var violations []Violation
	line := 1
	if wordsFile.file != nil {
		line = wordsFile.fset.Position(wordsFile.file.Package).Line
	}
	for v := range declared {
		if !named[v] {
			violations = append(violations, Violation{windowWords, line, fmt.Sprintf(
				"%q has no name in the window - %s declares it, and the map %s does not name it", v, declaredIn, mapName)})
		}
	}
	for v := range named {
		if !declared[v] {
			violations = append(violations, Violation{windowWords, line, fmt.Sprintf(
				"%q is named by the window and %s declares no such value", v, declaredIn)})
		}
	}
	return sortViolations(violations)
}

// constantsOfType is every string constant in the file declared with this
// type named on its own line.
func constantsOfType(sf sourceFile, typeName string) []string {
	var out []string
	for _, decl := range sf.file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			if ident, isIdent := vs.Type.(*ast.Ident); !isIdent || ident.Name != typeName {
				continue
			}
			for _, value := range vs.Values {
				if lit, isLit := value.(*ast.BasicLit); isLit && lit.Kind == token.STRING {
					out = append(out, literalValue(lit))
				}
			}
		}
	}
	return out
}

// mapKeys is the string keys of the map literal a package level variable of
// this name is set to.
func mapKeys(sf sourceFile, name string) []string {
	var out []string
	for _, decl := range sf.file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) != 1 || vs.Names[0].Name != name || len(vs.Values) != 1 {
				continue
			}
			composite, isComposite := vs.Values[0].(*ast.CompositeLit)
			if !isComposite {
				continue
			}
			for _, element := range composite.Elts {
				kv, isKV := element.(*ast.KeyValueExpr)
				if !isKV {
					continue
				}
				if lit, isLit := kv.Key.(*ast.BasicLit); isLit && lit.Kind == token.STRING {
					out = append(out, literalValue(lit))
				}
			}
		}
	}
	return out
}
