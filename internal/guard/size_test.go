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

// THE SIZE RATCHET. docs/22 section 6 point 2: on the day M1 closes, the
// measured values become a ceiling and from then on they may only fall.
//
// WHY A GUARD HERE RATHER THAN A STEP IN THE WORKFLOW. The measuring tool lives
// outside version control, and a gate CI cannot see is a gate that is red on one
// machine and absent on the others - the exact arrangement the tool's own go.mod
// warns about. A guard runs inside "go test ./...", which is already wired on all
// three platforms, so this needs no new step to be trusted on any of them.
//
// THE COST OF THAT CHOICE IS WRITTEN DOWN RATHER THAN HIDDEN: the measure now
// exists twice, here and in the reporting tool. Two spellings of one rule drift,
// and this tree has measured what that costs. What holds them together is not
// discipline but the PROBE below - the same named claim the reporting tool
// makes about itself, asked again here: ninety lines of comment do not move the
// measure and ninety lines of code move it by ninety. A drift that mattered
// would have to survive both.
//
// TWO DIALS, NOT ONE - docs/22 section 6, taken from the reference rule set. A
// ceiling on the single worst case catches one function growing to a record and
// MISSES twenty functions growing by two lines each, which moves no maximum at
// all. So the count of things already close to the ceiling is frozen too.

// nearCeilingShare is the percentage of a ceiling at which something counts as
// close to it.
//
// SIXTY IS A CHOICE AND THE ONLY DEFENCE OF IT IS PROPORTION. Lower, and the
// count includes so much of the tree that ordinary new code moves it, which
// makes this the guard that shouts at correct work - and docs/22 records what
// happens to those: they are switched off within a week. Higher, and the dial
// only reacts once something is nearly a record, which is what the other dial
// already covers. At sixty, a function is on the list when it is six times the
// median of this tree, which is a length worth a second look on its own.
const nearCeilingShare = 60

// ceilingFile is where the numbers live, beside the coverage floors.
//
// IN THE REPOSITORY, because CI has to read them, and in ONE file because a
// number kept in two places starts disagreeing with itself the first time one of
// them is edited - the sentence coverage-floor.txt opens with.
const ceilingFile = "tools/size-ceiling.txt"

// ceilings are the frozen numbers, one per dial.
type ceilings struct {
	function          int
	testFunction      int
	file              int
	nearFunctions     int
	nearTestFunctions int
	nearFiles         int
	declared          map[string]bool
}

// sizedFunction is one function body, measured.
type sizedFunction struct {
	name   string
	file   string
	line   int
	code   int
	isTest bool
}

// sizedFile is one file, measured.
type sizedFile struct {
	rel  string
	code int
}

// TestNothingGrewPastTheSizeRatchet is the gate.
func TestNothingGrewPastTheSizeRatchet(t *testing.T) {
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
	if len(files) == 0 || len(functions) == 0 {
		t.Fatal("nothing was measured, so a green result here would mean nothing")
	}

	requireNoViolations(t, checkSizes(limits, functions, files), "something past the size ratchet")
}

// checkSizes turns a measurement into violations.
//
// EVERY BREACH IS REPORTED, not just the first. A run that stopped at the worst
// one would send somebody back for a second run to discover the next, and the
// list is short enough that seeing all of it is the point.
func checkSizes(limits ceilings, functions []sizedFunction, files []sizedFile) []Violation {
	var found []Violation

	nearFunctions, nearTestFunctions, nearFiles := 0, 0, 0
	for _, f := range functions {
		ceiling, near := limits.function, &nearFunctions
		what := "a function"
		if f.isTest {
			ceiling, near = limits.testFunction, &nearTestFunctions
			what = "a test function"
		}
		if f.code > ceiling {
			found = append(found, Violation{
				File: f.file, Line: f.line,
				Detail: fmt.Sprintf("%s is %d lines of code and the ceiling for %s is %d: %s",
					f.name, f.code, what, ceiling, ceilingAdvice),
			})
		}
		if atLeastShare(f.code, ceiling) {
			*near++
		}
	}
	for _, f := range files {
		if f.code > limits.file {
			found = append(found, Violation{
				File: f.rel, Line: 1,
				Detail: fmt.Sprintf("this file is %d lines of code and the ceiling for a file is %d: %s",
					f.code, limits.file, ceilingAdvice),
			})
		}
		if atLeastShare(f.code, limits.file) {
			nearFiles++
		}
	}

	// THE SECOND DIAL. Its violation names the count rather than a place,
	// because there is no single place: what it caught is the tree as a whole
	// drifting upward, and pointing at whichever function happens to have
	// crossed the line last would be pointing at the wrong one.
	for _, dial := range []struct {
		what    string
		counted int
		frozen  int
	}{
		{"functions", nearFunctions, limits.nearFunctions},
		{"test functions", nearTestFunctions, limits.nearTestFunctions},
		{"files", nearFiles, limits.nearFiles},
	} {
		if dial.counted > dial.frozen {
			found = append(found, Violation{
				File: ceilingFile, Line: 1,
				Detail: fmt.Sprintf(
					"%d %s are now within %d%% of their ceiling and %d were frozen - "+
						"nothing broke a ceiling, the tree crept toward one. %s",
					dial.counted, dial.what, nearCeilingShare, dial.frozen, ceilingAdvice),
			})
		}
	}

	return sortViolations(found)
}

// ceilingAdvice is the sentence every breach ends with.
//
// IT SAYS WHAT TO DO, because an error message is read by somebody who is
// already stuck, and because the wrong reaction here is cheap and looks like
// tidying: raising the number until the run goes green. docs/22 point 3 puts
// that decision with the owner, in the same words the coverage floor uses.
const ceilingAdvice = "shorten it, or ask the owner to raise the ceiling - raising it to " +
	"get unblocked is the same act as editing an expected value to make a test pass"

// atLeastShare says whether value has reached nearCeilingShare percent of
// ceiling, without floating point.
func atLeastShare(value, ceiling int) bool { return value*100 >= ceiling*nearCeilingShare }

// measureTree measures every function and file the guards police.
//
// IT TAKES ITS FILE LIST FROM loadModule RATHER THAN WALKING AGAIN, so the
// question "what counts as ours" is answered in exactly one place. That is the
// half of this measure that is NOT duplicated: the reporting tool has its own
// walk, and if the two disagreed about scope they would disagree about the
// biggest file rather than about a rule.
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
			name:   functionName(fd),
			file:   rel,
			line:   from,
			code:   countCode(carriesCode, from, to),
			isTest: isTest,
		})
	}

	whole := 0
	for _, carries := range carriesCode {
		if carries {
			whole++
		}
	}
	return functions, sizedFile{rel: rel, code: whole}, nil
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

// readCeilings reads the frozen numbers.
//
// A MISSING DIAL IS AN ERROR AND NOT A ZERO. A ceiling read as zero would fail
// every run, which is loud; a COUNT read as zero would fail every run too, and a
// future dial defaulting the other way would pass every run silently. Requiring
// all six by name means the file cannot half-answer.
func readCeilings(path string) (ceilings, error) {
	handle, err := os.Open(path)
	if err != nil {
		return ceilings{}, err
	}
	defer handle.Close()

	limits := ceilings{declared: map[string]bool{}}
	scanner := bufio.NewScanner(handle)
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) != 2 {
			return ceilings{}, fmt.Errorf("%s:%d: expected '<name> <number>', got %q", ceilingFile, line, text)
		}
		value, convErr := strconv.Atoi(fields[1])
		if convErr != nil || value < 0 {
			return ceilings{}, fmt.Errorf("%s:%d: %q is not a count", ceilingFile, line, fields[1])
		}
		target, known := map[string]*int{
			"function":                    &limits.function,
			"test-function":               &limits.testFunction,
			"file":                        &limits.file,
			"functions-near-ceiling":      &limits.nearFunctions,
			"test-functions-near-ceiling": &limits.nearTestFunctions,
			"files-near-ceiling":          &limits.nearFiles,
		}[fields[0]]
		if !known {
			return ceilings{}, fmt.Errorf("%s:%d: %q is not a dial this guard knows", ceilingFile, line, fields[0])
		}
		if limits.declared[fields[0]] {
			return ceilings{}, fmt.Errorf("%s:%d: %q is set twice", ceilingFile, line, fields[0])
		}
		limits.declared[fields[0]] = true
		*target = value
	}
	if err := scanner.Err(); err != nil {
		return ceilings{}, err
	}

	for _, dial := range []string{
		"function", "test-function", "file",
		"functions-near-ceiling", "test-functions-near-ceiling", "files-near-ceiling",
	} {
		if !limits.declared[dial] {
			return ceilings{}, fmt.Errorf("%s does not set %q, so that dial would be a silent zero", ceilingFile, dial)
		}
	}
	if limits.function == 0 || limits.testFunction == 0 || limits.file == 0 {
		return ceilings{}, fmt.Errorf("%s sets a ceiling of zero, which no tree can be under", ceilingFile)
	}
	return limits, nil
}

// TestTheSizeMeasureCountsCodeAndNotComment is the probe, and it is what keeps
// this measure and the reporting tool's from drifting apart.
//
// IT IS THE SAME NAMED CLAIM THE OTHER ONE MAKES ABOUT ITSELF, deliberately
// word for word: ninety lines of comment do not move the measure, and ninety
// lines of code move it by ninety. Two implementations pinned to one stated
// promise can still differ, but not about the thing the promise is about - and
// the promise is the part docs/22 argues for.
//
// IT GOES THROUGH measureSource RATHER THAN COUNTING ITS OWN WAY. A probe with
// its own arithmetic would prove only that the same thing was written twice.
func TestTheSizeMeasureCountsCodeAndNotComment(t *testing.T) {
	const added = 90
	base := "package p\n\nfunc f() {\n\ta := 1\n\tb := 2\n\t_ = a + b\n}\n"

	measureOne := func(source string) sizedFunction {
		t.Helper()
		functions, _, err := measureSource("probe.go", []byte(source), false)
		if err != nil {
			t.Fatalf("the probe source did not measure: %v", err)
		}
		if len(functions) != 1 {
			t.Fatalf("the probe source holds %d functions, want 1", len(functions))
		}
		return functions[0]
	}

	plain := measureOne(base)

	comments := strings.Repeat("\t// explanation\n", added)
	withComment := measureOne(strings.Replace(base, "\ta := 1\n", comments+"\ta := 1\n", 1))
	if withComment.code != plain.code {
		t.Errorf("%d lines of comment moved the measure from %d to %d - it is a ceiling on explanation",
			added, plain.code, withComment.code)
	}

	statements := strings.Repeat("\t_ = 1\n", added)
	withCode := measureOne(strings.Replace(base, "\ta := 1\n", statements+"\ta := 1\n", 1))
	if withCode.code != plain.code+added {
		t.Errorf("%d lines of code moved the measure from %d to %d, want %d",
			added, plain.code, withCode.code, plain.code+added)
	}

	// A BLOCK COMMENT IS THE CASE A PREFIX TEST GETS WRONG, and it is here
	// because the classifier is the only part of this measure with state.
	block := "\t/* one\n\ttwo\n\tthree */\n"
	withBlock := measureOne(strings.Replace(base, "\ta := 1\n", block+"\ta := 1\n", 1))
	if withBlock.code != plain.code {
		t.Errorf("a three line block comment moved the measure from %d to %d", plain.code, withBlock.code)
	}
}

// TestTheSizeRatchetCanFail is the canary. A gate that finds nothing looks
// exactly like a gate that measures nothing.
func TestTheSizeRatchetCanFail(t *testing.T) {
	tiny := ceilings{function: 1, testFunction: 1, file: 1}
	functions := []sizedFunction{{name: "f", file: "a.go", line: 3, code: 40}}
	files := []sizedFile{{rel: "a.go", code: 400}}

	requireViolation(t, checkSizes(tiny, functions, files), "the ceiling for a function is 1")
	requireViolation(t, checkSizes(tiny, functions, files), "the ceiling for a file is 1")
}

// TestTheSecondDialCatchesWhatTheFirstCannot is the argument for having two, run
// rather than written down.
//
// THE SHAPE IT DESCRIBES IS THE ONE docs/22 NAMES: twenty functions growing by
// two lines each move no maximum at all. Here nothing is over any ceiling and
// the gate still fires, which is the only way to show that the second dial is
// not decoration on the first.
func TestTheSecondDialCatchesWhatTheFirstCannot(t *testing.T) {
	limits := ceilings{function: 100, testFunction: 100, file: 1000, nearFunctions: 1}

	var crept []sizedFunction
	for i := 0; i < 5; i++ {
		crept = append(crept, sizedFunction{name: fmt.Sprintf("f%d", i), file: "a.go", line: i + 1, code: 70})
	}
	violations := checkSizes(limits, crept, []sizedFile{{rel: "a.go", code: 10}})

	for _, v := range violations {
		if strings.Contains(v.Detail, "the ceiling for a function") {
			t.Fatalf("something was over a ceiling, so this test is not showing what it claims: %s", v)
		}
	}
	requireViolation(t, violations, "the tree crept toward one")
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

	complete := "function 10\ntest-function 20\nfile 30\n" +
		"functions-near-ceiling 1\ntest-functions-near-ceiling 2\nfiles-near-ceiling 3\n"

	if _, err := readCeilings(write(complete)); err != nil {
		t.Fatalf("a complete file was refused: %v", err)
	}

	for _, c := range []struct {
		name string
		body string
		want string
	}{
		{"a dial left out", strings.Replace(complete, "file 30\n", "", 1), "silent zero"},
		{"a ceiling of zero", strings.Replace(complete, "file 30", "file 0", 1), "ceiling of zero"},
		{"a dial nobody declared", complete + "colour 3\n", "not a dial"},
		{"a dial set twice", complete + "file 40\n", "set twice"},
		{"something that is not a count", strings.Replace(complete, "file 30", "file plenty", 1), "not a count"},
		{"a line with three fields", complete + "file 40 please\n", "expected"},
	} {
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
