package guard

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// fixtureAccountNames are the invented account names allowed to appear in a
// path inside this module.
//
// Every one of them is made up. That is the whole rule: a fixture proving that
// an account name gets masked works with any name at all, so a real one proves
// nothing extra and publishes something instead.
var fixtureAccountNames = map[string]bool{
	"jdoe":  true,
	"bob":   true,
	"bobby": true,
	"build": true,
	"sys":   true,
}

// profilePath matches a path that names somebody's account.
//
// Both spellings of the Windows separator are accepted, because the same path
// appears in Go source escaped and in a raw string unescaped, and a guard that
// only knew one of them would be half a guard.
var profilePath = regexp.MustCompile(`(?:[A-Za-z]:\\{1,2}Users\\{1,2}|/home/|/Users/)([A-Za-z0-9._-]+)`)

// TestNoRealAccountNameReachesTheRepository keeps the author's machine out of
// the published tree.
//
// THIS GUARD EXISTS BECAUSE THE FAILURE HAPPENED, not because it was imagined.
// A real account name reached the tracked tree, in fixtures for the very
// function whose job is removing account names from reports. Nothing was red and
// nothing would have been: the property under test holds for any name, so the
// real one did no work while being published to everybody who clones this.
//
// It was found by a person asking whether public comments were a problem, not by
// any check here. That is the part worth remembering.
func TestNoRealAccountNameReachesTheRepository(t *testing.T) {
	tr, err := loadModule()
	if err != nil {
		t.Fatalf("the module could not be read: %v", err)
	}
	requireNoViolations(t, checkPersonalData(tr.root, scannedFiles(t, tr)), "an account name in a path")
}

// scannedFiles is the module's Go sources plus the fuzzing corpus.
//
// THE CORPUS IS HERE BECAUSE IT IS THE LIKELIEST PLACE FOR THIS TO GO WRONG NEXT.
// The failure this guard exists for happened in fixtures for the masking
// function; its seed corpus sits one directory away, is tracked, is published,
// and until this was added no scan in the repository read it. A seed grows from
// a crash or gets pasted in from a real report, which is exactly how a real host
// name or home directory would arrive - by the ordinary route rather than by
// carelessness.
func scannedFiles(t *testing.T, tr tree) []sourceFile {
	t.Helper()
	files := append([]sourceFile{}, tr.files...)

	corpus, err := corpusFiles(tr.root)
	if err != nil {
		t.Fatalf("the fuzzing corpus could not be listed: %v", err)
	}
	for _, rel := range corpus {
		files = append(files, sourceFile{rel: rel})
	}
	return files
}

// TestTheCorpusIsActuallyRead is the coverage half, and it is what the pass above
// cannot give on its own.
//
// The corpus is clean, so a scan that skipped it entirely would report exactly
// what a scan that read it reports. Without this, dropping the corpus back out
// would leave every test in this file green.
func TestTheCorpusIsActuallyRead(t *testing.T) {
	tr, err := loadModule()
	if err != nil {
		t.Fatalf("the module could not be read: %v", err)
	}

	corpus, err := corpusFiles(tr.root)
	if err != nil {
		t.Fatalf("the fuzzing corpus could not be listed: %v", err)
	}
	if len(corpus) == 0 {
		t.Fatal("no seed corpus is in the tree, so this test proves nothing - if the corpus was removed on purpose, this check goes with it")
	}

	scanned := map[string]bool{}
	for _, sf := range scannedFiles(t, tr) {
		scanned[sf.rel] = true
	}
	for _, rel := range corpus {
		if !scanned[rel] {
			t.Errorf("%s is a tracked seed and the personal data scan does not read it", rel)
		}
	}
}

// TestThePersonalDataGuardCanFail is the canary, and on a clean tree it carries
// more weight than the pass above: after the fix there is nothing left to find,
// so a scanner that read nothing at all would look identical.
func TestThePersonalDataGuardCanFail(t *testing.T) {
	planted := []sourceFile{{rel: "personal_violation.go"}}
	violations := checkPersonalData("testdata", planted)
	requireViolation(t, violations, "names an account")

	// BOTH SPELLINGS, AND THIS HALF WAS PAID FOR. The same path appears in Go
	// source unescaped inside a raw string and doubled inside an ordinary one.
	// A shell version of this scan, written while building the guard, knew only
	// one of them and reported the repository clean while the account name it
	// was looking for sat in the other form two directories away.
	if len(violations) != 2 {
		t.Fatalf("the fixture plants one path in each spelling and the scan found %d: %v",
			len(violations), violations)
	}
	found := violations[0].Detail + " " + violations[1].Detail
	for _, name := range []string{"realperson", "otherperson"} {
		if !strings.Contains(found, name) {
			t.Errorf("the scan did not report %q, so one spelling of a Windows path goes unread", name)
		}
	}
}

// checkPersonalData reports every path naming an account that is not on the list
// of invented names.
//
// It reads bytes rather than the syntax tree, for the same reason the ASCII scan
// does: a comment is where this goes wrong, and the syntax tree has thrown the
// comments away by the time anything could look at them.
//
// WHAT IT DOES NOT CATCH, said here rather than discovered later. It knows about
// one shape - a home directory with a name in it. An internal host name, a
// customer's domain, an employer, a licence key pasted into a fixture or a real
// address in a seed corpus all go straight past it. There is no pattern for
// "somebody's private business" and pretending otherwise would be worse than the
// narrow rule, because a guard believed to cover everything gets read as
// permission to stop looking.
func checkPersonalData(root string, files []sourceFile) []Violation {
	var violations []Violation
	for _, sf := range files {
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(sf.rel)))
		if err != nil {
			violations = append(violations, Violation{sf.rel, 0,
				fmt.Sprintf("could not be read, so nothing is known about it: %v", err)})
			continue
		}
		violations = append(violations, accountNamesIn(sf.rel, string(content))...)
	}
	return sortViolations(violations)
}

// accountNamesIn reports one violation per line carrying a name that is not on
// the list.
func accountNamesIn(rel, content string) []Violation {
	var violations []Violation
	for number, line := range strings.Split(content, "\n") {
		for _, found := range profilePath.FindAllStringSubmatch(line, -1) {
			name := found[1]
			if fixtureAccountNames[strings.ToLower(name)] {
				continue
			}
			violations = append(violations, Violation{rel, number + 1, fmt.Sprintf(
				"names an account %q in a path - this repository is published, so fixtures use an invented name from the list in personal_test.go", name)})
		}
	}
	return violations
}
