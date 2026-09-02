package guard

import (
	"fmt"
	"go/ast"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// authorityAllowlist names the files allowed to decide who signed a chain and
// how widely this machine holds that signer.
//
// WHY THIS LIST EXISTS, AND WHY THE NUMBER WORTH DEFENDING IS ONE. This is the
// judgement inviolable rule 21 calls harm when it is wrong: telling somebody
// their traffic is being intercepted when it is not. It is safe to make only
// when several facts are weighed TOGETHER - which stores were actually
// assessed, which of them hold an anchor that closes this chain, and which
// refused it for the one reason that says anything about the signer. A second
// place weighing them is a second place where three of the four could be
// weighed, and the sentence it produced would read identically.
//
// IT IS THE MEASURED SHAPE OF OBS50 RATHER THAN A PRECAUTION. Four times in
// this tree a rule got a second home while somebody was tidying up, and every
// time the mutation register reported it as a SKIP: entries that still passed
// and had stopped proving anything. This list makes the second home a red test.
//
// THE ENTRY WAS WRITTEN BEFORE THE FILE EXISTED - the same order execAllowlist
// and remediationAllowlist were built in, and for the same reason: a guard
// added after the code it covers arrives to find the rule already broken, and
// the only moment it can be seen to bite is while the path is still empty.
//
// IT SKIPS TEST FILES, unlike the certificate-verification scanner and for the
// reason OBS5 records: a test of a renderer legitimately needs one of these to
// render, and a fixture is not a second rule.
var authorityAllowlist = map[string]bool{
	// The one place. The counting rule, the three holdings it can answer and
	// the careful sentence attached to each live together, so that reading one
	// is reading the others.
	"internal/core/trust/authority.go": true,
}

// TestNothingOutsideTheAllowlistJudgesASigningAuthority is the rule turned into
// something a machine can check.
func TestNothingOutsideTheAllowlistJudgesASigningAuthority(t *testing.T) {
	tr := mustLoadModule(t)
	requireNoViolations(t, checkAuthority(tr), "a signing authority judged outside the allowlist")
}

// TestTheAuthorityGuardCanFail is the canary.
//
// Without it this check would look identical whether it read every file in the
// tree or none of them, and it passes today partly BECAUSE the allowlist says
// so - the shape that hides a scanner having quietly stopped scanning.
//
// It names BOTH shapes rather than counting them. A count passes just as well
// when the wrong half survives, and a scanner that recognised only a qualified
// report.SigningAuthority would walk past a package that had declared its own.
func TestTheAuthorityGuardCanFail(t *testing.T) {
	tr := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		files:      []sourceFile{loadFixture(t, "judges_an_authority.go", "internal/core/trust/planted.go")},
	}
	violations := checkAuthority(tr)
	requireViolation(t, violations, "may not judge who signed a chain")

	if len(violations) != 3 {
		t.Errorf("reported %d violations and the fixture plants three - a qualified SigningAuthority, a bare "+
			"one, and an Inspection attaching a product name: %v", len(violations), violations)
	}
}

// TestTheAuthorityAllowlistNamesFilesThatExist is the shape this tree already
// carries for six other lists, applied to a seventh - OBS63.
//
// An entry pointing at a file that does not exist is an exemption lying in
// ambush: it costs nothing while the path is empty and starts excusing whatever
// appears there later, under a name chosen for entirely different reasons, by
// somebody who never read the decision that granted it.
func TestTheAuthorityAllowlistNamesFilesThatExist(t *testing.T) {
	tr := mustLoadModule(t)
	present := map[string]bool{}
	for _, sf := range tr.files {
		present[sf.rel] = true
	}
	for named := range authorityAllowlist {
		if !present[named] {
			t.Errorf("the authority allowlist names %q, and no such file is in this module - "+
				"an exemption for a file that does not exist excuses whatever takes that name next", named)
		}
	}
}

// accusationAllowlist names the files allowed to contain one of the words a
// reader takes as a finding of fact about their own network.
//
// IT CLOSES THE GAP GUARD 30 NAMED ABOUT ITSELF. That guard defends ONE
// decision - that the judgement is made in one place - and said in its own
// comment that it does not see "a sentence about interception assembled into a
// plain string and printed". The contract in report now refuses a finding that
// accuses while naming no product, which covers everything a LAYER produces. It
// does not cover a renderer wording its own sentence, because a renderer's
// output never passes through report.Finding.Breach. This does.
//
// TWO ENTRIES, AND EACH IS THERE FOR A DIFFERENT REASON. authority.go is the one
// place allowed to make the claim, so it is the one place allowed to word it.
// finding.go holds the list of words itself, which cannot be written without
// writing them.
//
// IT SKIPS TEST FILES for the reason OBS5 records, and the bench script is not
// Go so it is not reached here at all - that one is defended by its own check.
var accusationAllowlist = map[string]bool{
	// The one place allowed to make the claim, so the one place allowed to word
	// it.
	"internal/core/trust/authority.go": true,
	// It holds the list of words itself, which cannot be written without
	// writing them.
	"internal/core/report/finding.go": true,
	// It is the list of PRODUCT NAMES, and one of them is "mitmproxy" - which
	// begins with a word on the list. A product name is not a sentence, this
	// file words nothing, and guard 30 above already refuses it the right to
	// judge. Measured while writing this scanner: without the line, it reported
	// this file six times for naming the product it exists to name.
	"internal/core/trust/inspection.go": true,
}

// accusingWordsIn EXTRACTS the list from the source of the package that declares
// it, rather than carrying a copy.
//
// A COPY IS NOT AVAILABLE HERE AND THAT TURNED OUT TO BE THE BETTER ANSWER. This
// package may not import internal/core/report - the layer guard says so, and
// weakening it to give this one a convenience would be trading a structural rule
// for a shortcut. So the list is read out of the file that declares it, which is
// the shape this project already uses where a word list has two readers: the
// commit-message checks pull theirs out of the language guard rather than
// restating it.
//
// AN EXTRACTION THAT FINDS NOTHING IS A RED TEST, NEVER A QUIET PASS. A scanner
// looking for an empty list of words reports no violations and looks exactly
// like a clean tree - which is the failure mode every canary in this package
// exists to prevent, arriving here through the back door.
func accusingWordsIn(t *testing.T, tr tree) []string {
	t.Helper()
	const declaredIn = "internal/core/report/finding.go"
	var words []string
	for _, sf := range tr.files {
		if sf.rel != declaredIn {
			continue
		}
		ast.Inspect(sf.file, func(n ast.Node) bool {
			spec, ok := n.(*ast.ValueSpec)
			if !ok || len(spec.Names) != 1 || spec.Names[0].Name != "AccusingWords" || len(spec.Values) != 1 {
				return true
			}
			lit, ok := spec.Values[0].(*ast.CompositeLit)
			if !ok {
				return true
			}
			for _, element := range lit.Elts {
				value, ok := element.(*ast.BasicLit)
				if !ok || value.Kind != token.STRING {
					continue
				}
				unquoted, err := strconv.Unquote(value.Value)
				if err != nil {
					continue
				}
				words = append(words, unquoted)
			}
			return true
		})
	}
	if len(words) == 0 {
		t.Fatalf("no accusing words could be read out of %s - the scanner below would then look for "+
			"nothing and report a clean tree, which is indistinguishable from it having worked", declaredIn)
	}
	return words
}

// TestTheAccusingWordsCanBeReadFromTheContract is the canary on the extraction
// itself, and it is separate from the canary on the scanner because they fail
// for different reasons: this one goes red when somebody renames or moves the
// declaration, that one when the scanner stops scanning.
func TestTheAccusingWordsCanBeReadFromTheContract(t *testing.T) {
	words := accusingWordsIn(t, mustLoadModule(t))
	for _, word := range words {
		if strings.TrimSpace(word) == "" {
			t.Errorf("read an empty accusing word, which matches every string there is")
		}
	}
}

// TestNothingOutsideTheAllowlistAccusesAnybodyOfInterception is inviolable rule
// 21 turned into something a machine can check.
//
// Telling somebody their traffic is being read when it is not is the mistake
// this project calls harm rather than a defect. Measured 2026-08-19: every field
// this program can fill in has the same value for an intercepting middlebox and
// for an organisation's own certificate authority, so the sentence is safe only
// where a name from the inspection list is attached - and that is one file.
func TestNothingOutsideTheAllowlistAccusesAnybodyOfInterception(t *testing.T) {
	tr := mustLoadModule(t)
	requireNoViolations(t, checkAccusation(tr, accusingWordsIn(t, tr)), "an accusation worded outside the allowlist")
}

// TestTheAccusationGuardCanFail is the canary.
//
// It names BOTH shapes rather than counting them. A whole literal equal to a
// sentence and a word buried inside a format string are different-looking nodes
// to a reader, and a scanner that matched only the first would pass this tree
// today and every day after.
func TestTheAccusationGuardCanFail(t *testing.T) {
	tr := tree{
		modulePath: "github.com/donislawdev/certdoctor",
		files:      []sourceFile{loadFixture(t, "accuses_of_interception.go", "internal/adapter/render/planted.go")},
	}
	violations := checkAccusation(tr, accusingWordsIn(t, mustLoadModule(t)))
	requireViolation(t, violations, "may not tell somebody their traffic is being read")

	if len(violations) != 2 {
		t.Errorf("reported %d violations and the fixture plants two - a whole sentence and a word inside a "+
			"format string: %v", len(violations), violations)
	}
}

// TestTheAccusationAllowlistNamesFilesThatExist is OBS63 applied to an eighth
// list, for the reason it was applied to the seven before it: an entry pointing
// at a file that does not exist costs nothing while the path is empty and starts
// excusing whatever appears there later.
func TestTheAccusationAllowlistNamesFilesThatExist(t *testing.T) {
	tr := mustLoadModule(t)
	present := map[string]bool{}
	for _, sf := range tr.files {
		present[sf.rel] = true
	}
	for named := range accusationAllowlist {
		if !present[named] {
			t.Errorf("the accusation allowlist names %q, and no such file is in this module - "+
				"an exemption for a file that does not exist excuses whatever takes that name next", named)
		}
	}
}

// checkAccusation reports every string literal in a product file outside the
// allowlist that contains one of the accusing words.
//
// IT READS LITERALS RATHER THAN SENTENCES, which is what makes it total. It
// cannot tell an accusation from a comment about one - so a file that needs to
// DISCUSS the subject writes it in a comment, which this does not read, or earns
// a line on the allowlist with a reason beside it.
//
// WHAT IT DOES NOT SEE, said here rather than discovered later: a sentence built
// by concatenating fragments none of which contain a whole word, and a sentence
// arriving from outside this program. The first is defeat by deliberate effort
// rather than by accident, which is the class of mistake this guard is not for.
// The second is what the contract in report refuses.
func checkAccusation(tr tree, accusingWords []string) []Violation {
	var violations []Violation
	for _, sf := range tr.files {
		if sf.isTest || accusationAllowlist[sf.rel] {
			continue
		}
		ast.Inspect(sf.file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			for _, word := range accusingWords {
				if !containsWordStem(lit.Value, word) {
					continue
				}
				violations = append(violations, Violation{sf.rel, sf.fset.Position(lit.Pos()).Line, fmt.Sprintf(
					"%s may not tell somebody their traffic is being read - it says %q, and every field this "+
						"program can fill in has the same value for a middlebox and for an organisation's own "+
						"authority, so the sentence is safe only where a name from the inspection list is "+
						"attached", sf.rel, word)})
				return true
			}
			return true
		})
	}
	return sortViolations(violations)
}

// checkAuthority reports every product file outside the allowlist that builds a
// value whose type is named SigningAuthority.
//
// IT READS THE NAME RATHER THAN RESOLVING THE TYPE, which is what makes it
// cheap and total. A package that declared its own SigningAuthority in order to
// write a second counting rule is exactly the case worth catching, and it would
// type check perfectly.
//
// WHAT IT DOES NOT SEE, said here rather than discovered later: a sentence
// about interception assembled into a plain string and printed. This guard
// defends the ONE decision that the judgement is made in one place, not the
// general property that nothing else can word an accusation - and the general
// property has no scanner. What does defend it is the contract in report, which
// refuses a finding whose holding and whose store lists disagree.
func checkAuthority(tr tree) []Violation {
	var violations []Violation
	for _, sf := range tr.files {
		if sf.isTest || authorityAllowlist[sf.rel] {
			continue
		}
		ast.Inspect(sf.file, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || !namesSigningAuthority(lit.Type) {
				return true
			}
			violations = append(violations, Violation{sf.rel, sf.fset.Position(lit.Pos()).Line, fmt.Sprintf(
				"%s may not judge who signed a chain - saying that an authority is local to this machine is the "+
					"claim inviolable rule 21 calls harm when it is wrong, and the facts that make it safe to "+
					"make live in one file so that they cannot be weighed three out of four anywhere else", sf.rel)})
			return true
		})
	}
	return sortViolations(violations)
}

// judgedTypes are the type names whose construction IS the judgement.
//
// SigningAuthority weighs which stores were assessed, which closed the chain and
// which refused it for the one reason that says anything about a signer.
// Inspection attaches a PRODUCT NAME to that signer, which is the only thing in
// this program that turns a count into a sentence about somebody's network -
// P6b-K2. Building either one somewhere else is the same mistake arriving by two
// doors, so one scanner answers for both.
var judgedTypes = map[string]bool{"SigningAuthority": true, "Inspection": true}

// namesAJudgement reports whether a composite literal's type is one of those,
// qualified by a package or not.
func namesSigningAuthority(expr ast.Expr) bool {
	switch typed := expr.(type) {
	case *ast.Ident:
		return judgedTypes[typed.Name]
	case *ast.SelectorExpr:
		return typed.Sel != nil && judgedTypes[typed.Sel.Name]
	case *ast.StarExpr:
		return namesSigningAuthority(typed.X)
	}
	return false
}

// containsWordStem is the same question report.ContainsWordStem answers, asked
// here because this package may not import that one.
//
// THE DUPLICATION IS DELIBERATE AND ITS COST IS BOUNDED, which is why it is
// written down rather than avoided. The list of words is extracted rather than
// copied, so the thing most likely to drift cannot. This is a boundary rule in
// test-only code, so no mutation entry aims at it and none is disarmed by it -
// which is the harm OBS50 actually measures.
//
// THE TWO HAVE ALREADY DIVERGED ONCE AND IT CANNOT BITE HERE, which is said out
// loud rather than left to be discovered. report.ContainsWordStem asks the RUNE
// whether it is a letter, because a distinguished name is somebody else's UTF-8
// and counting bytes there named a product inside an accented name - measured
// 2026-09-02. This one still counts bytes, and it never sees a non-ASCII one:
// every .go file in this tree is pure ASCII, which is guard row 8 with a canary
// of its own. If that guard ever goes, this comment is wrong and this function
// is the second thing to fix.
//
// IT MATCHES A STEM RATHER THAN A WHOLE WORD, and the canary is what settled
// that: "intercept" has to catch "intercepted" and "intercepting", or this
// scanner refuses nothing anybody would actually write while looking strict. The
// price is that it also catches "mitmproxy", which is why the list of products
// has a line on the allowlist above.
func containsWordStem(value, want string) bool {
	lowerValue, lowerWant := strings.ToLower(value), strings.ToLower(want)
	if lowerWant == "" {
		return false
	}
	for from := 0; from <= len(lowerValue)-len(lowerWant); {
		at := strings.Index(lowerValue[from:], lowerWant)
		if at < 0 {
			return false
		}
		start := from + at
		if wordBoundaryAt(lowerValue, start-1) {
			return true
		}
		from = start + 1
	}
	return false
}

// wordBoundaryAt reports whether the byte at this index is a word boundary, an
// index outside the string counting as one.
func wordBoundaryAt(value string, index int) bool {
	if index < 0 || index >= len(value) {
		return true
	}
	c := value[index]
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return false
	}
	return true
}
