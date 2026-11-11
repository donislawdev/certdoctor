package guard

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The canaries of the shape ratchet in size_test.go. A gate that finds nothing
// looks exactly like a gate that measures nothing, so each of these runs the
// checks against a tree written by hand and requires them to speak.

// handTree is a measured tree written out by hand, with the dials that tree
// measures - worked out here by reading the samples, not by asking the code
// under test, which would only prove the same arithmetic was done twice.
//
// One production function and one test function stand at the top of every axis,
// and every number on the test side is bigger than its production twin, so an
// axis reading the wrong side cannot come out at the right number.
func handTree() ([]sizedFunction, []sizedFile, dials) {
	functions := []sizedFunction{
		{name: "big", file: "a.go", line: 3, code: 60, depth: 4, branches: 20, arguments: 8},
		{name: "small", file: "a.go", line: 90, code: 10, depth: 1, branches: 2, arguments: 1},
		{name: "TestBig", file: "a_test.go", line: 5, code: 100, depth: 6, branches: 40, arguments: 12, isTest: true},
	}
	files := []sizedFile{
		{rel: "a.go", code: 700},
		{rel: "b.go", code: 10},
		{rel: "a_test.go", code: 900, isTest: true},
	}
	exact := dials{
		"function": 60, "functions-near-ceiling": 1,
		"test-function": 100, "test-functions-near-ceiling": 1,
		"file": 700, "files-near-ceiling": 1,
		"test-file": 900, "test-files-near-ceiling": 1,
		"depth": 4, "depth-near-ceiling": 1,
		"test-depth": 6,
		"branches":   20, "branches-near-ceiling": 1,
		"arguments": 8, "arguments-near-ceiling": 1,
	}
	return functions, files, exact
}

// generous is a set of dials nothing in a hand tree comes near.
func generous() dials {
	limits := dials{}
	for _, name := range dialNames() {
		limits[name] = 10000
	}
	return limits
}

// TestTheSizeMeasureCountsCodeAndNotComment is the probe for the length measure,
// and it is what keeps this measure and the reporting tool's from drifting apart.
//
// IT IS THE SAME NAMED CLAIM THE OTHER ONE MAKES ABOUT ITSELF, deliberately
// word for word: ninety lines of comment do not move the measure, and ninety
// lines of code move it by ninety. Two implementations pinned to one stated
// promise can still differ, but not about the thing the promise is about - and
// the promise is the part docs/22 argues for.
func TestTheSizeMeasureCountsCodeAndNotComment(t *testing.T) {
	const added = 90
	base := "package p\n\nfunc f() {\n\ta := 1\n\tb := 2\n\t_ = a + b\n}\n"
	plain := measureOne(t, base)

	comments := strings.Repeat("\t// explanation\n", added)
	withComment := measureOne(t, strings.Replace(base, "\ta := 1\n", comments+"\ta := 1\n", 1))
	if withComment.code != plain.code {
		t.Errorf("%d lines of comment moved the measure from %d to %d - it is a ceiling on explanation",
			added, plain.code, withComment.code)
	}

	statements := strings.Repeat("\t_ = 1\n", added)
	withCode := measureOne(t, strings.Replace(base, "\ta := 1\n", statements+"\ta := 1\n", 1))
	if withCode.code != plain.code+added {
		t.Errorf("%d lines of code moved the measure from %d to %d, want %d",
			added, plain.code, withCode.code, plain.code+added)
	}

	// A BLOCK COMMENT IS THE CASE A PREFIX TEST GETS WRONG, and it is here
	// because the classifier is the only part of this measure with state.
	block := "\t/* one\n\ttwo\n\tthree */\n"
	withBlock := measureOne(t, strings.Replace(base, "\ta := 1\n", block+"\ta := 1\n", 1))
	if withBlock.code != plain.code {
		t.Errorf("a three line block comment moved the measure from %d to %d", plain.code, withBlock.code)
	}
}

// TestTheSizeRatchetCanFail requires every dial in the file to be able to fire,
// each under its own name. An axis left out of the checks would otherwise be a
// number in a file that nothing reads.
func TestTheSizeRatchetCanFail(t *testing.T) {
	functions, files, _ := handTree()
	tiny := dials{}
	for _, a := range axes {
		tiny[a.ceiling] = 1
		if a.crowd != "" {
			tiny[a.crowd] = 0
		}
	}
	violations := checkShape(tiny, functions, files)

	for _, a := range axes {
		requireViolation(t, violations, fmt.Sprintf("the ceiling for %s is 1 (dial %q)", a.what, a.ceiling))
		if a.crowd != "" {
			requireViolation(t, violations, fmt.Sprintf("were frozen (dial %q)", a.crowd))
		}
	}
}

// TestTheSecondDialCatchesWhatTheFirstCannot is the argument for having two
// numbers per axis, run rather than written down.
//
// THE SHAPE IT DESCRIBES IS THE ONE docs/22 NAMES: twenty functions growing by
// two lines each move no maximum at all. Here nothing is over any ceiling and
// the gate still fires, which is the only way to show that the second number is
// not decoration on the first.
func TestTheSecondDialCatchesWhatTheFirstCannot(t *testing.T) {
	limits := generous()
	limits["functions-near-ceiling"] = 1

	var crept []sizedFunction
	for i := 0; i < 5; i++ {
		crept = append(crept, sizedFunction{name: fmt.Sprintf("f%d", i), file: "a.go", line: i + 1, code: 70})
	}
	violations := checkShape(limits, crept, []sizedFile{{rel: "a.go", code: 10}})

	for _, v := range violations {
		if strings.Contains(v.Detail, "the ceiling for") {
			t.Fatalf("something was over a ceiling, so this test is not showing what it claims: %s", v)
		}
	}
	requireViolation(t, violations, "the tree crept toward one")
}

// TestANumberApartFromItsMeasurementIsRefused is the canary of the exactness
// gate, in both directions and for both kinds of number.
func TestANumberApartFromItsMeasurementIsRefused(t *testing.T) {
	functions, files, exact := handTree()
	requireNoViolations(t, checkExact(exact, functions, files), "the hand tree against its own measurement")

	for _, c := range []struct {
		dial  string
		moved int
		want  string
	}{
		{"function", 62, `"function" is 62 and the biggest thing it measures is 60 (a.go:3 big), so the number stands above`},
		{"file", 699, `"file" is 699 and the biggest thing it measures is 700 (a.go), so the number stands below`},
		{"depth-near-ceiling", 2, `"depth-near-ceiling" is 2 and 1 of depth's samples reach 4`},
		{"test-depth", 7, `"test-depth" is 7`},
	} {
		limits := dials{}
		for name, value := range exact {
			limits[name] = value
		}
		limits[c.dial] = c.moved
		requireViolation(t, checkExact(limits, functions, files), c.want)
	}
}

// TestEachAxisReadsOnlyItsOwnSide holds the split between production and tests.
//
// Every test sample in the hand tree is bigger than its production twin, so a
// production axis that also read the tests would measure the test number, and
// the hand-worked dials would stop matching.
func TestEachAxisReadsOnlyItsOwnSide(t *testing.T) {
	functions, files, exact := handTree()
	requireNoViolations(t, checkExact(exact, functions, files), "each axis reading the side it names")
}

// TestLoweringACeilingDoesNotMoveItsBand is the owner's decision of 2026-11-11
// (ADR132), run: the band is a number of its own, not a share of the ceiling.
//
// One function stands one line under the band and one stands at its start, and
// the count is frozen at zero so the gate says what it counted. Lowering the
// ceiling from 84 to 60 has to leave that answer alone: one function, from the
// same line. Under the share this replaced, sixty percent of 60 is 36, both
// would be in the band, and lowering one number would have forced raising
// another.
func TestLoweringACeilingDoesNotMoveItsBand(t *testing.T) {
	functions := []sizedFunction{
		{name: "under", file: "a.go", line: 1, code: functionBand - 1},
		{name: "at", file: "a.go", line: 9, code: functionBand},
	}
	files := []sizedFile{{rel: "a.go", code: 10}}
	for _, ceiling := range []int{84, 60} {
		limits := generous()
		limits["function"] = ceiling
		limits["functions-near-ceiling"] = 0
		requireViolation(t, checkShape(limits, functions, files),
			fmt.Sprintf("1 of function's samples now reach %d lines of code", functionBand))
	}
}

// TestTheCeilingFileRefusesToHalfAnswer covers the reading rather than the
// measuring, because a file that parsed into zeros would turn this whole guard
// into a formality that passes.
func TestTheCeilingFileRefusesToHalfAnswer(t *testing.T) {
	write := func(body string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "ceiling.txt")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("writing the fixture: %v", err)
		}
		return path
	}

	var complete strings.Builder
	for i, name := range dialNames() {
		fmt.Fprintf(&complete, "%s %d\n", name, (i+1)*10)
	}
	whole := complete.String()

	if _, err := readCeilings(write(whole)); err != nil {
		t.Fatalf("a complete file was refused: %v", err)
	}
	// A COUNT OF ZERO IS AN ANSWER. Nothing in the band is a state the tree can
	// be in, unlike nothing under a ceiling.
	zeroCount := strings.Replace(whole, "functions-near-ceiling 20\n", "functions-near-ceiling 0\n", 1)
	if zeroCount == whole {
		t.Fatal("the fixture no longer sets functions-near-ceiling to 20, so this case proves nothing")
	}
	if _, err := readCeilings(write(zeroCount)); err != nil {
		t.Errorf("a count of zero was refused: %v", err)
	}

	for _, c := range []struct {
		name string
		body string
		want string
	}{
		{"a dial left out", strings.Replace(whole, "file 50\n", "", 1), "silent zero"},
		{"a ceiling of zero", strings.Replace(whole, "file 50\n", "file 0\n", 1), "ceiling of zero"},
		{"a dial nobody declared", whole + "colour 3\n", "not a dial"},
		{"a dial set twice", whole + "file 40\n", "set twice"},
		{"something that is not a count", strings.Replace(whole, "file 50\n", "file plenty\n", 1), "not a count"},
		{"a line with three fields", whole + "file 40 please\n", "expected"},
	} {
		if c.body == whole {
			t.Errorf("%s: the fixture did not change, so the case proves nothing", c.name)
			continue
		}
		_, err := readCeilings(write(c.body))
		if err == nil {
			t.Errorf("%s was accepted", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s was refused with %q, which does not mention %q", c.name, err, c.want)
		}
	}
}
