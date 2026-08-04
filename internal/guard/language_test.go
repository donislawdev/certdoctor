package guard

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// polishWords are words that cannot be anything but Polish.
//
// WHY A WORD LIST AND NOT A LANGUAGE DETECTOR. The rule is that everything in
// this repository is English, and the guard that was supposed to notice a slip
// is the ASCII scan - which cannot, by construction. A Polish word written
// without its diacritics is plain ASCII, so "haslo" sits in a fixture looking
// exactly like an identifier nobody recognises. That is how one reached the
// tracked tree.
//
// The list is deliberately short and made of words that are not English and are
// not substrings of English ones. Every entry is matched as a WHOLE WORD, case
// insensitively, so "plik" cannot fire inside a longer identifier.
var polishWords = []string{
	"haslo", "hasla", "uzytkownik", "uzytkownika",
	"sciezka", "sciezki", "blad", "bledy", "bledow",
	"wartosc", "wartosci", "zmienna", "zmiennej",
	"plik", "pliku", "pliki", "plikow",
	"nazwa", "nazwy", "klucz", "klucza", "katalog", "katalogu",
	"sprawdz", "sprawdza", "przyklad", "komenda", "wiersz",
	"warstwa", "warstwy", "sonda", "sondy", "straznik", "straznika",
	"kolejnosc", "zrodlo", "zrodla", "maskowanie", "poswiadczenie",
	"czyli", "oraz", "ktory", "ktora", "ktore", "jesli", "wiec",
	"zeby", "tylko", "jest", "bardzo", "moze", "musi", "powinien",
}

// proseFiles are the tracked files this guard reads besides the Go sources.
//
// WHY A LIST AND NOT A WALK. Walking the tree for text files would have to know
// what git ignores, and the ignored files - the planning documents, the tooling,
// the technical changelog - are in Polish ON PURPOSE. A walker would report
// hundreds of violations on the author's machine and none in a fresh clone,
// which is the exact shape this package refuses elsewhere: a guard that is red
// locally and green in CI teaches that red means nothing.
//
// The Go file below belongs to a nested module, so the module walk skips it -
// and it is tracked, published, and would otherwise be the one Go file nobody
// checks.
var proseFiles = []string{
	"README.md",
	"CHANGELOG.md",
	"SECURITY.md",
	".gitignore",
	".gitattributes",
	"go.mod",
	".github/workflows/ci.yml",
	"tools/coverage-gate.sh",
	"tools/coverage-floor.txt",
	"tools/expected-modules.txt",
	"tools/probe-macos-truststore/go.mod",
	"tools/probe-macos-truststore/main.go",
}

var polishWord = regexp.MustCompile(`(?i)\b(` + strings.Join(polishWords, "|") + `)\b`)

// languageAllowlist is the one file allowed to carry the words, and it is this
// one - the file that declares them cannot avoid containing them.
//
// It has exactly one entry and a test below pins that number. The appearance
// guard has the same shape for the same reason: an allowlist that can grow
// quietly is a rule that ends up naming every file that broke it.
var languageAllowlist = map[string]bool{
	"internal/guard/language_test.go": true,
}

// TestTheRepositoryIsInEnglish is the language rule with something behind it.
//
// It said "everything in the repository is English, without exceptions" and was
// enforced by nobody. The ASCII guard looks like the check that would catch a
// slip and is blind to exactly this one, because a Polish word stripped of its
// diacritics is indistinguishable from ASCII noise.
func TestTheRepositoryIsInEnglish(t *testing.T) {
	tr, err := loadModule()
	if err != nil {
		t.Fatalf("the module could not be read: %v", err)
	}

	requireNoViolations(t, checkLanguage(tr.root, scannedPaths(t, tr)), "a Polish word")
}

// scannedPaths is everything this guard reads: the module's Go sources, the
// tracked files the module walk does not reach, and the fuzzing corpus.
func scannedPaths(t *testing.T, tr tree) []string {
	t.Helper()
	paths := make([]string, 0, len(tr.files)+len(proseFiles))
	for _, sf := range tr.files {
		paths = append(paths, sf.rel)
	}
	paths = append(paths, proseFiles...)

	corpus, err := corpusFiles(tr.root)
	if err != nil {
		t.Fatalf("the fuzzing corpus could not be listed: %v", err)
	}
	return append(paths, corpus...)
}

// TestTheScanCoversTheProseFilesAndTheGoSources proves both halves are actually
// read.
//
// Without it, dropping the prose files from the set would leave every test here
// green: the tree is English, so a scan of half of it reports exactly what a scan
// of all of it reports. That is the shape where a guard quietly covers less than
// its name says.
func TestTheScanCoversTheProseFilesAndTheGoSources(t *testing.T) {
	tr, err := loadModule()
	if err != nil {
		t.Fatalf("the module could not be read: %v", err)
	}

	covered := map[string]bool{}
	for _, rel := range scannedPaths(t, tr) {
		covered[rel] = true
	}
	for _, rel := range proseFiles {
		if !covered[rel] {
			t.Errorf("%s is tracked and published and no scan reads it", rel)
		}
	}
	if !covered["internal/core/redact/redact.go"] {
		t.Error("the Go sources are not in the scan, so the half where this last went wrong is unread")
	}

	// THE THIRD HALF, ADDED AFTER IT WAS FOUND MISSING. The corpus is tracked
	// and published and was read by neither of the two above: the module walk
	// skips testdata by name, and the prose list does not mention it.
	corpus, err := corpusFiles(tr.root)
	if err != nil {
		t.Fatalf("the fuzzing corpus could not be listed: %v", err)
	}
	if len(corpus) == 0 {
		t.Fatal("no seed corpus is in the tree, so this test proves nothing about whether one would be scanned - if the corpus was removed on purpose, this check goes with it")
	}
	for _, rel := range corpus {
		if !covered[rel] {
			t.Errorf("%s is a tracked seed and no scan reads it", rel)
		}
	}
}

// TestTheProseFileListNamesFilesThatExist keeps the list from rotting quietly. A
// renamed file would drop out of the scan and nothing else would say so.
func TestTheProseFileListNamesFilesThatExist(t *testing.T) {
	tr, err := loadModule()
	if err != nil {
		t.Fatalf("the module could not be read: %v", err)
	}
	for _, rel := range proseFiles {
		if _, err := os.Stat(filepath.Join(tr.root, filepath.FromSlash(rel))); err != nil {
			t.Errorf("the list names %s, which is not in the tree: %v", rel, err)
		}
	}
}

// TestTheLanguageAllowlistIsStillOneFileLong pins the number, because the
// cheapest way to silence this guard is to name the file that tripped it.
func TestTheLanguageAllowlistIsStillOneFileLong(t *testing.T) {
	if len(languageAllowlist) != 1 {
		t.Errorf("the allowlist has %d entries, and the only file that cannot avoid these words is the one declaring them", len(languageAllowlist))
	}
}

// TestTheLanguageGuardCanFail is the canary. The tree is English now, so the
// check above would look identical if the scanner read nothing at all.
func TestTheLanguageGuardCanFail(t *testing.T) {
	violations := checkLanguage("testdata", []string{"language_violation.go"})
	requireViolation(t, violations, "is Polish")

	// The fixture plants a word in a comment and a word in a string literal,
	// because the two are where this goes wrong and only one of them is visible
	// to a scanner that reads syntax instead of bytes.
	if len(violations) != 2 {
		t.Fatalf("the fixture plants one word in a comment and one in a literal, and the scan found %d: %v",
			len(violations), violations)
	}
}

// checkLanguage reports every whole-word occurrence of a listed Polish word.
//
// WHAT IT DOES NOT CATCH, said here rather than discovered later. It knows a few
// dozen words and nothing about Polish grammar, so an inflected form outside the
// list goes straight past it, and so does a whole sentence built from words
// nobody listed. It is a net for the likely slip, not a language detector, and
// the honest way to read a green run is "none of these words", never "this is
// English".
func checkLanguage(root string, paths []string) []Violation {
	var violations []Violation
	for _, rel := range paths {
		if languageAllowlist[rel] {
			continue
		}
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			violations = append(violations, Violation{rel, 0,
				fmt.Sprintf("could not be read, so nothing is known about it: %v", err)})
			continue
		}
		violations = append(violations, polishWordsIn(rel, string(content))...)
	}
	return sortViolations(violations)
}

func polishWordsIn(rel, content string) []Violation {
	var violations []Violation
	for number, line := range strings.Split(content, "\n") {
		if found := polishWord.FindString(line); found != "" {
			violations = append(violations, Violation{rel, number + 1, fmt.Sprintf(
				"%q is Polish, and everything in this repository is English - the word list is in language_test.go", found)})
		}
	}
	return violations
}
