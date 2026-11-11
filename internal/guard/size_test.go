package guard

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// THE SHAPE RATCHET. docs/22 section 6 point 2: on the day M1 closed, the
// measured values became a ceiling, and from then on they may only fall.
//
// WHY A GUARD HERE RATHER THAN A STEP IN THE WORKFLOW. The measuring tool lives
// outside version control, and a gate CI cannot see is a gate that is red on one
// machine and absent on the others - the exact arrangement the tool's own go.mod
// warns about. A guard runs inside "go test ./...", which is already wired on all
// three platforms, so this needs no new step to be trusted on any of them.
//
// THE COST OF THAT CHOICE IS WRITTEN DOWN RATHER THAN HIDDEN: the length measure
// exists twice, here and in the reporting tool. Two spellings of one rule drift,
// and this tree has measured what that costs. What holds them together is not
// discipline but a PROBE - the same named claim the reporting tool makes about
// itself, asked again here: ninety lines of comment do not move the measure and
// ninety lines of code move it by ninety. A drift that mattered would have to
// survive both.
//
// FOUR AXES SINCE 2026-11-11 (ADR132), where there had been one. Length and
// branching do not move together: a hundred lines of straight setup read from
// top to bottom, and forty lines with branches inside branches have to be held
// in the head all at once, which is where a case gets missed. A nine argument
// signature can be a four line function and passes every length ceiling. The
// measures themselves are in shape_test.go, each with a probe asking it in both
// directions.
//
// TWO NUMBERS PER AXIS, NOT ONE - docs/22 section 6. A ceiling on the single
// worst case catches one function growing to a record and MISSES twenty growing
// by two lines each, which moves no maximum at all. So the count of things
// already standing in the band below the ceiling is frozen too.
//
// AND EVERY NUMBER IS THE MEASUREMENT, NOT A LIMIT ABOVE IT - also since
// 2026-11-11. "Down is routine, up is a decision" only holds if down actually
// happens, and the file said 84 the day the longest function was 82.
//
// What this cannot see: whether a design is right, whether a function does one
// thing, whether a name says what it holds. A short function can be wrong. This
// only stops the tree from drifting into something nobody can follow.

// The bands: where each axis counts as close to its ceiling.
//
// ABSOLUTE NUMBERS, NOT A SHARE OF THE CEILING - the owner's decision of
// 2026-11-11 (ADR132). Until then the band was sixty percent of the ceiling, and
// with every ceiling held to its measurement that is a ratchet nobody can turn:
// lowering the function ceiling from 84 to the 82 it measured would have moved
// the band from 51 to 50 and the count in it from 9 to 12, so lowering one
// number would have forced raising another. A band that reshapes itself under
// what it watches says nothing.
//
// The four length bands started where the old rule put them - sixty percent of
// that day's ceiling, rounded up - and are frozen there, so the counts did not
// move on the day the rule changed. Depth and arguments are small whole numbers,
// where a share means little: depth's band is one level under its ceiling, and
// the arguments band is seven because at six it already held thirty one
// signatures, ordinary probe constructors among them, which is a band ordinary
// new code would move.
const (
	functionBand     = 51
	testFunctionBand = 86
	fileBand         = 598
	testFileBand     = 785
	depthBand        = 4
	branchesBand     = 18
	argumentsBand    = 7
)

// ceilingFile is where the numbers live, beside the coverage floors.
//
// IN THE REPOSITORY, because CI has to read them, and in ONE file because a
// number kept in two places starts disagreeing with itself the first time one of
// them is edited - the sentence coverage-floor.txt opens with.
const ceilingFile = "tools/size-ceiling.txt"

// dials are the numbers in ceilingFile, by name.
type dials map[string]int

// sizedFunction is one function body, measured on every axis.
type sizedFunction struct {
	name      string
	file      string
	line      int
	code      int
	depth     int
	branches  int
	arguments int
	isTest    bool
}

// sizedFile is one file, measured.
type sizedFile struct {
	rel    string
	code   int
	isTest bool
}

// axis is one ceiling, the band under it, and what it reads.
//
// AN AXIS READS ONE SIDE OF THE TREE. Tests and production get their own
// numbers because they are different measurements, not because tests are
// allowed more: a table of twenty cases is the clearest thing a guard can be and
// the longest thing in it, and one ceiling over both would either tear the
// production code apart or watch nothing in the tests. Branching and arguments
// are watched on production only, for the same reason - a guard spelling out
// every case is doing its job.
type axis struct {
	ceiling string // the dial holding the worst case
	crowd   string // the dial holding how many stand in the band, "" for none
	band    int
	what    string // what one sample is, as a violation says it
	verb    string // how a violation says a sample holds its number
	unit    string // what the number counts
	tests   bool
	files   bool
	of      func(sizedFunction) int // the number a function carries, nil for a file axis
}

// axes are every axis the ratchet holds. The dial names in ceilingFile are read
// from here, so a dial the guard does not check cannot be set, and a dial it
// checks cannot be left out.
var axes = []axis{
	{ceiling: "function", crowd: "functions-near-ceiling", band: functionBand,
		what: "a function", verb: "is", unit: "lines of code",
		of: func(f sizedFunction) int { return f.code }},
	{ceiling: "test-function", crowd: "test-functions-near-ceiling", band: testFunctionBand,
		what: "a test function", verb: "is", unit: "lines of code", tests: true,
		of: func(f sizedFunction) int { return f.code }},
	{ceiling: "file", crowd: "files-near-ceiling", band: fileBand,
		what: "a file", verb: "is", unit: "lines of code", files: true},
	{ceiling: "test-file", crowd: "test-files-near-ceiling", band: testFileBand,
		what: "a test file", verb: "is", unit: "lines of code", tests: true, files: true},
	{ceiling: "depth", crowd: "depth-near-ceiling", band: depthBand,
		what: "a function", verb: "nests", unit: "levels deep",
		of: func(f sizedFunction) int { return f.depth }},
	{ceiling: "test-depth",
		what: "a test function", verb: "nests", unit: "levels deep", tests: true,
		of: func(f sizedFunction) int { return f.depth }},
	{ceiling: "branches", crowd: "branches-near-ceiling", band: branchesBand,
		what: "a function", verb: "has", unit: "decision points",
		of: func(f sizedFunction) int { return f.branches }},
	{ceiling: "arguments", crowd: "arguments-near-ceiling", band: argumentsBand,
		what: "a function", verb: "takes", unit: "arguments",
		of: func(f sizedFunction) int { return f.arguments }},
}

// sample is one thing an axis measured: a function or a file, where it stands,
// and its number.
type sample struct {
	file  string
	line  int
	name  string
	value int
}

// fileSample is the name a whole file goes by in a violation.
const fileSample = "this file"

// at says where a sample stands, the way a person would go and look for it.
func (s sample) at() string {
	if s.name == fileSample {
		return s.file
	}
	return fmt.Sprintf("%s:%d %s", s.file, s.line, s.name)
}

// samples returns what the axis reads from the measured tree.
func (a axis) samples(functions []sizedFunction, files []sizedFile) []sample {
	var out []sample
	if a.files {
		for _, file := range files {
			if file.isTest == a.tests {
				out = append(out, sample{file: file.rel, line: 1, name: fileSample, value: file.code})
			}
		}
		return out
	}
	for _, f := range functions {
		if f.isTest == a.tests {
			out = append(out, sample{file: f.file, line: f.line, name: f.name, value: a.of(f)})
		}
	}
	return out
}

// reading is what one axis found: its worst sample and how many reach the band.
type reading struct {
	worst   sample
	crowded int
}

// read sums the samples up. On a tie the first sample in tree order is the
// worst, so the name a violation gives does not change between runs.
func (a axis) read(samples []sample) reading {
	var r reading
	for _, s := range samples {
		if s.value > r.worst.value {
			r.worst = s
		}
		if a.crowd != "" && s.value >= a.band {
			r.crowded++
		}
	}
	return r
}

// TestNothingGrewPastTheSizeRatchet is the gate.
func TestNothingGrewPastTheSizeRatchet(t *testing.T) {
	limits, functions, files := measuredTree(t)
	requireNoViolations(t, checkShape(limits, functions, files), "something past the shape ratchet")

	for _, a := range axes {
		r := a.read(a.samples(functions, files))
		t.Logf("%-28s worst %4d %s", a.ceiling, r.worst.value, r.worst.at())
		if a.crowd != "" {
			t.Logf("%-28s %4d at %d or more", a.crowd, r.crowded, a.band)
		}
	}
}

// TestTheShapeCeilingsAreTodaysMeasurement is the other half of every number in
// the file: it has to BE the measurement, not merely stand above it.
//
// A ceiling parked above the truth grants headroom nobody decided to grant, and
// the next arrival slips in under it in silence - which is the failure the
// ceiling exists to prevent, wearing its own badge. Nothing watched that gap
// until 2026-11-11, and that day it held 2 lines on the function ceiling and 32
// on the file ceiling. So shortening something comes with a chore, and it is
// meant to be routine: bring its number down in the same change.
//
// The counts are held to the same rule for the same reason. Frozen one above the
// truth, a count would let the next arrival into the band without a word.
func TestTheShapeCeilingsAreTodaysMeasurement(t *testing.T) {
	limits, functions, files := measuredTree(t)
	requireNoViolations(t, checkExact(limits, functions, files), "a number standing apart from what it measures")
}

// measuredTree reads the numbers and measures the module, once for each gate.
func measuredTree(t *testing.T) (dials, []sizedFunction, []sizedFile) {
	t.Helper()
	tr, err := loadModule()
	if err != nil {
		t.Fatalf("the module could not be read: %v", err)
	}
	limits, err := readCeilings(filepath.Join(tr.root, filepath.FromSlash(ceilingFile)))
	if err != nil {
		t.Fatalf("the ceilings could not be read: %v", err)
	}
	functions, files, err := measureTree(tr)
	if err != nil {
		t.Fatalf("the tree could not be measured: %v", err)
	}
	// EVERY AXIS HAS TO HAVE READ SOMETHING. An axis reading the wrong side, or
	// nothing, would pass against any ceiling ever set.
	for _, a := range axes {
		if len(a.samples(functions, files)) == 0 {
			t.Fatalf("the axis %q measured nothing, so a green result here would mean nothing", a.ceiling)
		}
	}
	return limits, functions, files
}

// checkShape turns a measurement into violations of the ceilings and the counts.
//
// EVERY BREACH IS REPORTED, not just the first. A run that stopped at the worst
// one would send somebody back for a second run to discover the next, and the
// list is short enough that seeing all of it is the point.
func checkShape(limits dials, functions []sizedFunction, files []sizedFile) []Violation {
	var found []Violation
	for _, a := range axes {
		samples := a.samples(functions, files)
		ceiling := limits[a.ceiling]
		for _, s := range samples {
			if s.value > ceiling {
				found = append(found, Violation{
					File: s.file, Line: s.line,
					Detail: fmt.Sprintf("%s %s %d %s and the ceiling for %s is %d (dial %q): %s",
						s.name, a.verb, s.value, a.unit, a.what, ceiling, a.ceiling, ceilingAdvice),
				})
			}
		}
		if a.crowd == "" {
			continue
		}
		// THE SECOND NUMBER. Its violation names the count rather than a place,
		// because there is no single place: what it caught is the tree as a whole
		// drifting upward, and pointing at whichever function happens to have
		// crossed the band last would be pointing at the wrong one.
		if crowded := a.read(samples).crowded; crowded > limits[a.crowd] {
			found = append(found, Violation{
				File: ceilingFile, Line: 1,
				Detail: fmt.Sprintf("%d of %s's samples now reach %d %s and %d were frozen (dial %q) - "+
					"nothing broke a ceiling, the tree crept toward one. %s",
					crowded, a.ceiling, a.band, a.unit, limits[a.crowd], a.crowd, ceilingAdvice),
			})
		}
	}
	return sortViolations(found)
}

// checkExact holds every number to exactly what it measures, in both directions.
func checkExact(limits dials, functions []sizedFunction, files []sizedFile) []Violation {
	var found []Violation
	for _, a := range axes {
		r := a.read(a.samples(functions, files))
		if r.worst.value != limits[a.ceiling] {
			found = append(found, Violation{
				File: ceilingFile, Line: 1,
				Detail: fmt.Sprintf("%q is %d and the biggest thing it measures is %d (%s), "+
					"so the number stands %s the truth - move it to %d. %s",
					a.ceiling, limits[a.ceiling], r.worst.value, r.worst.at(),
					side(r.worst.value, limits[a.ceiling]), r.worst.value, slackAdvice),
			})
		}
		if a.crowd != "" && r.crowded != limits[a.crowd] {
			found = append(found, Violation{
				File: ceilingFile, Line: 1,
				Detail: fmt.Sprintf("%q is %d and %d of %s's samples reach %d %s, "+
					"so the number stands %s the truth - move it to %d. %s",
					a.crowd, limits[a.crowd], r.crowded, a.ceiling, a.band, a.unit,
					side(r.crowded, limits[a.crowd]), r.crowded, slackAdvice),
			})
		}
	}
	return sortViolations(found)
}

// side says which way a number misses its measurement.
func side(measured, frozen int) string {
	if measured > frozen {
		return "below"
	}
	return "above"
}

// ceilingAdvice is the sentence every breach ends with.
//
// IT SAYS WHAT TO DO, because an error message is read by somebody who is
// already stuck, and because the wrong reaction here is cheap and looks like
// tidying: raising the number until the run goes green. docs/22 point 3 puts
// that decision with the owner, in the same words the coverage floor uses.
const ceilingAdvice = "shorten it, or ask the owner to raise the ceiling - raising it to " +
	"get unblocked is the same act as editing an expected value to make a test pass"

// slackAdvice is the sentence a number standing above its measurement ends with.
const slackAdvice = "Headroom nobody decided to grant is how the next arrival gets in without being noticed."

// measureTree measures every function and file the guards police.
//
// IT TAKES ITS FILE LIST FROM loadModule RATHER THAN WALKING AGAIN, so the
// question "what counts as ours" is answered in exactly one place. That is the
// half of this measure that is NOT duplicated: the reporting tool has its own
// walk, and if the two disagreed about scope they would disagree about the
// biggest file rather than about a rule. loadModule parses every file whatever
// its build tags, so the window's cgo files and the Windows-only files are
// measured on every platform, and the numbers are the same on all three.
func measureTree(tr tree) ([]sizedFunction, []sizedFile, error) {
	var functions []sizedFunction
	var files []sizedFile

	for _, sf := range tr.files {
		source, err := os.ReadFile(filepath.Join(tr.root, filepath.FromSlash(sf.rel)))
		if err != nil {
			return nil, nil, fmt.Errorf("reading %s: %w", sf.rel, err)
		}
		inFunctions, inFile, err := measureSource(sf.rel, source, sf.isTest)
		if err != nil {
			return nil, nil, err
		}
		functions = append(functions, inFunctions...)
		files = append(files, inFile)
	}
	return functions, files, nil
}

// measureSource is the measure itself, and the unit it counts is named in
// docs/22 section 5.
//
//	A FUNCTION is the LINES OF CODE in its body: lines that are neither empty
//	nor entirely comment, counted from the line carrying the word "func" to the
//	closing brace. The doc comment above a function is NOT counted.
//	A FILE is the same count over the whole file.
//
// CODE RATHER THAN ALL LINES, and this is the one decision in the measure that
// had to be reversed once already. This project requires comments saying WHY,
// and stands a paragraph beside every guard about what it does not catch. A
// measure that counted those would be a CEILING ON EXPLANATION, pushing directly
// against the rule the project is trying to keep.
func measureSource(rel string, source []byte, isTest bool) ([]sizedFunction, sizedFile, error) {
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, rel, source, parser.SkipObjectResolution)
	if err != nil {
		return nil, sizedFile{}, fmt.Errorf("parsing %s: %w", rel, err)
	}
	carriesCode := classifyLines(string(source))

	var functions []sizedFunction
	for _, declaration := range parsed.Decls {
		fd, ok := declaration.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		// The start comes from fd.Type.Pos(), the word "func". fd.Pos() on a
		// documented function points at its comment, which would put the whole
		// explanation inside the measure.
		from := fset.Position(fd.Type.Pos()).Line
		to := fset.Position(fd.Body.Rbrace).Line
		functions = append(functions, sizedFunction{
			name:      functionName(fd),
			file:      rel,
			line:      from,
			code:      countCode(carriesCode, from, to),
			depth:     depthOf(fd.Body),
			branches:  branchesOf(fd.Body),
			arguments: argumentsOf(fd.Type),
			isTest:    isTest,
		})
	}

	whole := 0
	for _, carries := range carriesCode {
		if carries {
			whole++
		}
	}
	return functions, sizedFile{rel: rel, code: whole, isTest: isTest}, nil
}

// countCode counts the lines carrying code between two line numbers, inclusive.
func countCode(carriesCode []bool, from, to int) int {
	count := 0
	for i := from; i <= to && i <= len(carriesCode); i++ {
		if carriesCode[i-1] {
			count++
		}
	}
	return count
}

// classifyLines says, for every line, whether it carries anything but comment.
//
// IT TRACKS BLOCK COMMENTS ACROSS LINES, which is the whole reason this cannot
// be a prefix test. A line ending a block comment and then starting a statement
// carries code, and a line in the middle of one does not however it is spelled.
func classifyLines(source string) []bool {
	lines := strings.Split(source, "\n")
	// Splitting on a trailing newline leaves an empty tail that is not a line.
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	carriesCode := make([]bool, len(lines))
	inBlock := false
	for i, line := range lines {
		rest := strings.TrimSpace(line)
		for rest != "" {
			if inBlock {
				end := strings.Index(rest, "*/")
				if end < 0 {
					break
				}
				inBlock = false
				rest = strings.TrimSpace(rest[end+2:])
				continue
			}
			if strings.HasPrefix(rest, "//") {
				break
			}
			if strings.HasPrefix(rest, "/*") {
				inBlock = true
				rest = rest[2:]
				continue
			}
			carriesCode[i] = true
			break
		}
	}
	return carriesCode
}

// functionName is what a violation calls the thing it found, receiver included
// so that two methods of the same name can be told apart.
func functionName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	var receiver strings.Builder
	if err := printType(&receiver, fd.Recv.List[0].Type); err != nil {
		return fd.Name.Name
	}
	return "(" + receiver.String() + ")." + fd.Name.Name
}

// printType writes the spelling of a receiver type, which is only ever a name,
// a pointer to one, or a generic instantiation of one.
func printType(b *strings.Builder, expr ast.Expr) error {
	switch typed := expr.(type) {
	case *ast.Ident:
		b.WriteString(typed.Name)
	case *ast.StarExpr:
		b.WriteString("*")
		return printType(b, typed.X)
	case *ast.IndexExpr:
		return printType(b, typed.X)
	case *ast.IndexListExpr:
		return printType(b, typed.X)
	default:
		return fmt.Errorf("unexpected receiver type %T", expr)
	}
	return nil
}

// dialNames are every name the file has to set, in the order of the axes.
func dialNames() []string {
	var names []string
	for _, a := range axes {
		names = append(names, a.ceiling)
		if a.crowd != "" {
			names = append(names, a.crowd)
		}
	}
	return names
}

// readCeilings reads the frozen numbers.
//
// A MISSING DIAL IS AN ERROR AND NOT A ZERO. A ceiling read as zero would fail
// every run, which is loud. A COUNT read as zero would fail every run too, and a
// future dial defaulting the other way would pass every run silently. Requiring
// every dial by name means the file cannot half-answer.
func readCeilings(path string) (dials, error) {
	handle, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	known := map[string]bool{}
	for _, name := range dialNames() {
		known[name] = true
	}

	limits := dials{}
	scanner := bufio.NewScanner(handle)
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) != 2 {
			return nil, fmt.Errorf("%s:%d: expected '<name> <number>', got %q", ceilingFile, line, text)
		}
		value, convErr := strconv.Atoi(fields[1])
		if convErr != nil || value < 0 {
			return nil, fmt.Errorf("%s:%d: %q is not a count", ceilingFile, line, fields[1])
		}
		if !known[fields[0]] {
			return nil, fmt.Errorf("%s:%d: %q is not a dial this guard knows", ceilingFile, line, fields[0])
		}
		if _, set := limits[fields[0]]; set {
			return nil, fmt.Errorf("%s:%d: %q is set twice", ceilingFile, line, fields[0])
		}
		limits[fields[0]] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	for _, name := range dialNames() {
		if _, set := limits[name]; !set {
			return nil, fmt.Errorf("%s does not set %q, so that dial would be a silent zero", ceilingFile, name)
		}
	}
	for _, a := range axes {
		if limits[a.ceiling] == 0 {
			return nil, fmt.Errorf("%s sets %q to a ceiling of zero, which no tree can be under", ceilingFile, a.ceiling)
		}
	}
	return limits, nil
}
