package render

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// readBack is Decode without the steps a test fixture cannot pass.
//
// The fixtures of this package are pages, not runs: most carry one layer, or a
// verdict typed by hand, so report.Validate refuses them and so does Decode.
// What they are good for is the one question this helper answers - whether
// every value a renderer reads survives being written to the document and read
// from it - and that is the conversion alone.
func readBack(t *testing.T, document []byte) report.Report {
	t.Helper()
	var saved jsonReport
	if err := json.Unmarshal(document, &saved); err != nil {
		t.Fatalf("the document this package wrote could not be read back: %v", err)
	}
	read, err := reportFrom(saved)
	if err != nil {
		t.Fatalf("the document this package wrote could not be converted back: %v", err)
	}
	return read
}

// pageFixtures is every report this package draws pages from in its tests,
// named, with one report per finding kind.
func pageFixtures() map[string]report.Report {
	fixtures := map[string]report.Report{
		"every status":                 everyStatusReport(),
		"a handshake":                  handshakeReport(),
		"a resolution":                 resolutionReport(),
		"hostile text":                 hostileReport(),
		"a poisoned report":            poisonedReport(),
		"hostile text everywhere":      reportWithHostileTextEverywhere(),
		"a run of a fraction of an ms": withDuration(everyStatusReport(), 1600*time.Microsecond),
	}
	for kind, finding := range bodyFixtures {
		fixtures["one "+kind.String()] = parityReport(finding)
	}
	return fixtures
}

func withDuration(r report.Report, d time.Duration) report.Report {
	r.Run.Duration = d
	return r
}

// TestASavedReportIsWrittenAgainAsTheRunWroteIt is the guard ADR121 (c) asks
// for: a page written from a saved document is the page the run wrote.
//
// For every fixture, each of the four surfaces is drawn twice - from the
// report, and from the report read back out of its own document - and the two
// have to be the same bytes. A field a renderer reads and the document does
// not carry fails here, as does one carried in a way that comes back
// different. The duration of a run was the first such field: the document cut
// its milliseconds where every page rounded them.
func TestASavedReportIsWrittenAgainAsTheRunWroteIt(t *testing.T) {
	fixtures := pageFixtures()
	if len(fixtures) < len(report.AllFindingKinds)+6 {
		t.Fatalf("only %d fixtures, so a finding kind has no report of its own here", len(fixtures))
	}
	for name, original := range fixtures {
		document, err := Encode(original)
		if err != nil {
			t.Fatalf("%s: could not be written: %v", name, err)
		}
		read := readBack(t, document)
		for _, one := range surfaces() {
			want, err := one.render(original)
			if err != nil {
				t.Fatalf("%s: the %s surface refused the original: %v", name, one.name, err)
			}
			got, err := one.render(read)
			if err != nil {
				t.Fatalf("%s: the %s surface refused the report read back: %v", name, one.name, err)
			}
			if got != want {
				t.Errorf("%s: the %s page written from the saved document differs from the run's page "+
					"at byte %d", name, one.name, firstByteApart(got, want))
			}
		}
	}
}

func firstByteApart(a, b string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return min(len(a), len(b))
}

// savedDocuments are what --from will be handed: documents certdoctor wrote
// with --json against three real sites, with every layer and a verdict worked
// out from the rows. They are the window's fixtures - internal/gui/model/testdata
// says how they were made - and they are read from there rather than copied,
// because a copy would be a second fixture that drifts from the first.
func savedDocuments(t *testing.T) map[string][]byte {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("..", "..", "gui", "model", "testdata", "*.json"))
	if err != nil || len(paths) < 3 {
		t.Fatalf("expected the three saved reports beside the window's model, found %d (%v)", len(paths), err)
	}
	documents := map[string][]byte{}
	for _, path := range paths {
		document, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		documents[filepath.Base(path)] = document
	}
	return documents
}

// TestADocumentCertdoctorWroteIsRead is the other half: every saved document
// is accepted, and reads back as a report that writes the same document.
func TestADocumentCertdoctorWroteIsRead(t *testing.T) {
	for name, document := range savedDocuments(t) {
		read, err := Decode(document)
		if err != nil {
			t.Fatalf("%s: refused: %v", name, err)
		}
		again, err := Encode(read)
		if err != nil {
			t.Fatalf("%s: could not be written again: %v", name, err)
		}
		was, _ := valueOf(document)
		is, _ := valueOf(again)
		if where := firstDifference("", was, is); where != "" {
			t.Errorf("%s: written again, it differs at %s", name, where)
		}
	}
}

// TestHowADocumentIsSpelledDoesNotMatter holds that the comparison in Decode
// is of values: a document passed through a tool that reformats JSON, given a
// byte order mark by an editor, or checked out with Windows line endings is the
// same report.
func TestHowADocumentIsSpelledDoesNotMatter(t *testing.T) {
	document := savedDocuments(t)["untrusted-root.json"]
	var compact bytes.Buffer
	if err := json.Compact(&compact, document); err != nil {
		t.Fatal(err)
	}
	for name, spelled := range map[string][]byte{
		"compact":            compact.Bytes(),
		"a byte order mark":  append([]byte{0xEF, 0xBB, 0xBF}, document...),
		"windows line ends":  bytes.ReplaceAll(document, []byte("\n"), []byte("\r\n")),
		"a line end at last": append(append([]byte{}, document...), '\n'),
	} {
		if _, err := Decode(spelled); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
}

// TestADocumentCertdoctorDidNotWriteIsRefusedWithTheReason is every way a file
// handed to --from can fail to be a report, each refused with a sentence that
// says which.
func TestADocumentCertdoctorDidNotWriteIsRefusedWithTheReason(t *testing.T) {
	document := string(savedDocuments(t)["untrusted-root.json"])
	edit := func(old, replacement string) []byte {
		if !strings.Contains(document, old) {
			t.Fatalf("the fixture no longer contains %q, so this case tests nothing", old)
		}
		return []byte(strings.Replace(document, old, replacement, 1))
	}

	for _, c := range []struct {
		name     string
		document []byte
		says     string
	}{
		{"UTF-16 little-endian", append([]byte{0xFF, 0xFE}, []byte("{")...), "UTF-16"},
		{"UTF-16 big-endian", append([]byte{0xFE, 0xFF}, []byte("{")...), "--out"},
		{"empty", []byte(" \n\t"), "empty"},
		{"a byte order mark and nothing", []byte{0xEF, 0xBB, 0xBF}, "empty"},
		{"not UTF-8", edit(`"certdoctor"`, "\"cert\xffdoctor\""), "not UTF-8"},
		{"not JSON", []byte("certdoctor: report written to x"), "not JSON"},
		{"an array", []byte(`[` + document + `]`), "not an object"},
		{"no schema version", edit(`"schema_version": "2.4",`, ``), "no schema_version"},
		{"a schema version that is not text", edit(`"schema_version": "2.4"`, `"schema_version": 2.4`), "no schema_version"},
		{"another schema version", edit(`"schema_version": "2.4"`, `"schema_version": "2.3"`), `"2.3"`},
		{"a field missing", edit(`"redacted": false,`, ``), "shape"},
		{"a field nobody declared", edit(`"redacted": false,`, `"redacted": false, "extra": 1,`), "shape"},
		{"a port that is not whole", edit(`"port": 443`, `"port": 443.0`), "wrong kind"},
		{"a time that is not one", edit(`"started_at": "`, `"started_at": "yesterday`), "started_at is not a time"},
		{"a run longer than a duration holds", edit(`"duration_ms": 3505,`, `"duration_ms": 9999999999999999,`), "length of time"},
		{"a run of negative length", edit(`"duration_ms": 3505,`, `"duration_ms": -1,`), "length of time"},
		{"a forged verdict", edit(`"status": "FAIL",`, `"status": "PASS",`), "rules every report keeps"},
		{"a status outside the list", edit(`"status": "FAIL",`, `"status": "BROKEN",`), "rules every report keeps"},
		{"a layer named something else", edit(`"name": "Context"`, `"name": "Something else"`), "layers[0].name"},
		{"an empty string where a null is written", edit(`"container": null`, `"container": ""`), "shape"},
	} {
		_, err := Decode(c.document)
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: refused without saying %q: %v", c.name, c.says, err)
		}
	}
}

// FuzzDecodeEndsInAReportOrAReason is inviolable rule 35 for the one parser in
// this program whose whole input is somebody else's file: whatever the bytes,
// Decode answers a report or a refusal and never panics, and a report it
// accepts is one it accepts again once written.
func FuzzDecodeEndsInAReportOrAReason(f *testing.F) {
	paths, _ := filepath.Glob(filepath.Join("..", "..", "gui", "model", "testdata", "*.json"))
	for _, path := range paths {
		if document, err := os.ReadFile(path); err == nil {
			f.Add(document)
		}
	}
	f.Add([]byte(`{"schema_version": "2.4"}`))
	f.Add([]byte{0xFF, 0xFE, '{', 0})
	f.Add([]byte("\xEF\xBB\xBF{}"))
	f.Fuzz(func(t *testing.T, document []byte) {
		read, err := Decode(document)
		if err != nil {
			if err.Error() == "" {
				t.Fatal("a refusal with no sentence")
			}
			return
		}
		again, err := Encode(read)
		if err != nil {
			t.Fatalf("an accepted report could not be written: %v", err)
		}
		if _, err := Decode(again); err != nil {
			t.Fatalf("an accepted report, written again, was refused: %v", err)
		}
	})
}

// TestAFileBreakingEveryRuleIsNotListedRuleByRule holds fewOf: a refusal names
// a few problems and counts the rest, rather than burying its first sentence.
func TestAFileBreakingEveryRuleIsNotListedRuleByRule(t *testing.T) {
	_, err := Decode([]byte(`{"schema_version": "2.4", "tool": {}, "run": {}, "verdict": {}, "layers": [{}], "notes": [{}]}`))
	if err == nil {
		t.Fatal("an object of empty parts was accepted")
	}
	said := err.Error()
	if !strings.Contains(said, "more") || strings.Count(said, "\n") > 8 {
		t.Errorf("the refusal lists every rule rather than a few and a count:\n%s", said)
	}
}

// TestAnEmptyStringIsNotANull is the comparison in Decode at work on a field
// the shape allows either way: a layer's reason may be a string or a null, and
// this program writes a null for a layer that has none, so a document saying ""
// is not one it wrote - though every other check reads the two the same.
func TestAnEmptyStringIsNotANull(t *testing.T) {
	document := string(savedDocuments(t)["untrusted-root.json"])
	const passing = `"name": "Name resolution",
      "status": "PASS",
      "reason": null,`
	if !strings.Contains(document, passing) {
		t.Fatalf("the fixture has no passing L1 without a reason, so this case tests nothing")
	}
	_, err := Decode([]byte(strings.Replace(document, passing, `"name": "Name resolution",
      "status": "PASS",
      "reason": "",`, 1)))
	if err == nil || !strings.Contains(err.Error(), "would write differently") {
		t.Errorf("an empty detail where certdoctor writes a null was not refused for it: %v", err)
	}
}
