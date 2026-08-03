package guard

import (
	"fmt"
	"go/ast"
	"go/token"
	"testing"
)

// appearanceDictionary is the one file allowed to write an escape sequence or a
// glyph. Everything else asks the dictionary.
//
// The dictionary has to exist somewhere, so the rule cannot be "nowhere". Making
// it exactly one named file is what stops a second one appearing, because adding
// a name here is a visible act while writing a colour inline is not.
const appearanceDictionary = "internal/adapter/render/appearance.go"

// statusVocabulary declares the status labels, so it is also the one file
// allowed to write them out.
const statusVocabulary = "internal/core/status/status.go"

// TestNoLiteralAppearanceOutsideDictionary is the guard from docs 13 section
// 2.2: a FAIL rendered so that it reads like a PASS breaks the product's main
// promise and looks like a success while doing it.
func TestNoLiteralAppearanceOutsideDictionary(t *testing.T) {
	tr := mustLoadModule(t)
	requireNoViolations(t, checkAppearanceLiterals(tr), "literal appearance outside the dictionary")
}

// TestAppearanceGuardDetectsPlantedViolations is the canary. The real tree has
// one renderer and no colours yet, so this guard would pass while blind.
func TestAppearanceGuardDetectsPlantedViolations(t *testing.T) {
	real := mustLoadModule(t)
	planted := tree{
		modulePath: real.modulePath,
		// The real files come along so the status labels are read from the real
		// vocabulary rather than from a second copy written into this test.
		files: append(append([]sourceFile{}, real.files...),
			loadFixture(t, "appearance_violation.go", "internal/adapter/render/planted.go")),
	}
	violations := checkAppearanceLiterals(planted)

	requireViolation(t, violations, "literal escape sequence")
	requireViolation(t, violations, "non-ASCII character")
	requireViolation(t, violations, "literal status label")
}

// checkAppearanceLiterals reports escape sequences, non-ASCII characters and
// status labels written straight into the source.
//
// What it does not see:
//
//   - test files, which are skipped. A test has to be able to write the expected
//     glyph and label out in full to have something to compare against.
//   - a sequence assembled at run time. Two halves concatenated, or a byte built
//     from its numeric value, both pass.
//   - a colour chosen correctly but applied to the wrong status. This guard is
//     about where appearance is written, not about whether it is right.
func checkAppearanceLiterals(tr tree) []Violation {
	labels := statusLabels(tr)
	var violations []Violation

	for _, sf := range tr.files {
		if sf.isTest {
			continue
		}
		appearanceAllowed := sf.rel == appearanceDictionary
		labelsAllowed := sf.rel == statusVocabulary

		ast.Inspect(sf.file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || (lit.Kind != token.STRING && lit.Kind != token.CHAR) {
				return true
			}
			value := literalValue(lit)
			line := sf.fset.Position(lit.Pos()).Line

			if !appearanceAllowed {
				for _, r := range value {
					if r == 0x1b {
						violations = append(violations, Violation{sf.rel, line, fmt.Sprintf(
							"literal escape sequence - colour belongs in %s, never at the call site", appearanceDictionary)})
						break
					}
				}
				for _, r := range value {
					if r > 0x7f {
						violations = append(violations, Violation{sf.rel, line, fmt.Sprintf(
							"non-ASCII character %q - status glyphs belong in %s, and a stray one here would also put a non-English string in front of a user", r, appearanceDictionary)})
						break
					}
				}
			}
			if !labelsAllowed && labels[value] {
				violations = append(violations, Violation{sf.rel, line, fmt.Sprintf(
					"literal status label %q - the renderer takes the label from the status, never from the call site", value)})
			}
			return true
		})
	}
	return sortViolations(violations)
}

// statusLabels reads the four labels out of the status vocabulary itself rather
// than repeating them here. A guard carrying its own copy of the list it polices
// stops catching a value the day somebody renames one.
func statusLabels(tr tree) map[string]bool {
	labels := map[string]bool{}
	for _, sf := range tr.files {
		if sf.rel != statusVocabulary {
			continue
		}
		for _, decl := range sf.file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			ast.Inspect(gen, func(n ast.Node) bool {
				if lit, isLit := n.(*ast.BasicLit); isLit && lit.Kind == token.STRING {
					labels[literalValue(lit)] = true
				}
				return true
			})
		}
	}
	return labels
}

// TestStatusLabelsWereActuallyFound closes the hole in the guard above: if the
// vocabulary file moved, statusLabels would return an empty map and the label
// half of the guard would pass without checking anything.
func TestStatusLabelsWereActuallyFound(t *testing.T) {
	labels := statusLabels(mustLoadModule(t))
	if len(labels) != 4 {
		t.Fatalf("read %d status labels from %s, want 4: %v", len(labels), statusVocabulary, labels)
	}
}
