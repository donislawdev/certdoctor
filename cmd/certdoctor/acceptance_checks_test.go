//go:build acceptance

package main

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/adapter/render"
	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	"github.com/donislawdev/certdoctor/internal/core/layer"
)

// aTarget is the URL every check uses unless it is about the URL itself.
//
// A documentation domain, because these runs are real and a name belonging to
// somebody would make this suite send traffic at them.
const aTarget = "https://example.com"

// anUnresolvableTarget is a name that CANNOT exist, and that is a guarantee
// rather than a hope.
//
// .invalid is reserved by RFC 2606 precisely so that it can never be delegated
// to anybody, so every resolver on earth answers NXDOMAIN for this and no packet
// leaves the user's own network to find that out.
//
// IT EXISTS BECAUSE L1 MADE THIS SUITE DEPEND ON THE OUTSIDE WORLD - OBS46, and
// the decision recorded there is that these checks verify STRUCTURE, not
// content. example.com sits behind a load balancer that rotates the order of the
// addresses it hands back, so two runs against it legitimately differ - which is
// true information about DNS and useless for asking whether our own output is
// stable.
const anUnresolvableTarget = "https://certdoctor-acceptance.invalid"

// ---------------------------------------------------------------- group A

// TestTheShippedBinaryWritesNoFileNobodyAskedFor is inviolable rule 14 observed
// rather than inferred.
//
// "It diagnoses, it never repairs" is the first line of the README, and until
// now the only thing holding it up was a guard reading DECLARED IMPORTS - which
// by its own admission cannot see a write through a handle passed as a
// parameter or through a subprocess. This counts the files on the disk before
// and after instead, which is the form of the promise a user would check.
func TestTheShippedBinaryWritesNoFileNobodyAskedFor(t *testing.T) {
	dir := t.TempDir()

	before := census(t, dir)
	r := startProgram(t, invocation{dir: dir}, aTarget)
	if r.code != exitcode.Inconclusive.Int() {
		t.Fatalf("an ordinary run ended with %d, not the code for nothing assessed: %s", r.code, r.stderr)
	}
	if new := appeared(before, census(t, dir)); len(new) != 0 {
		t.Errorf("a run that was asked for nothing on disk created %v", new)
	}

	// And with --out, EXACTLY the file that was asked for and no other. The
	// atomic write puts its temporary file beside the destination, so a run that
	// forgot to clean up would show two.
	before = census(t, dir)
	r = startProgram(t, invocation{dir: dir}, aTarget, "--json", "--out", "report.json")
	if r.code != exitcode.Inconclusive.Int() {
		t.Fatalf("writing a report ended with %d: %s", r.code, r.stderr)
	}
	new := appeared(before, census(t, dir))
	if len(new) != 1 || new[0] != "report.json" {
		t.Errorf("asked for one file called report.json, the directory gained %v", new)
	}
}

// TestTheShippedBinaryLeavesNoLitterWhenAWriteFails covers the branches OBS26
// says no test executes, because they cannot be reached portably from inside.
//
// From outside they can: a destination that is an existing DIRECTORY is refused
// by every platform at the rename, which is exactly the half-finished write
// whose cleanup nobody had ever run.
func TestTheShippedBinaryLeavesNoLitterWhenAWriteFails(t *testing.T) {
	dir := t.TempDir()
	inTheWay := filepath.Join(dir, "report.json")
	if err := os.Mkdir(inTheWay, 0o755); err != nil {
		t.Fatalf("preparing the obstruction: %v", err)
	}

	before := census(t, dir)
	r := startProgram(t, invocation{dir: dir}, aTarget, "--json", "--out", "report.json")

	if r.code == exitcode.OK.Int() {
		t.Error("writing a report over a directory reported success")
	}
	if r.stdout != "" {
		t.Errorf("a failed run put %d bytes on standard output", len(r.stdout))
	}
	if left := appeared(before, census(t, dir)); len(left) != 0 {
		t.Errorf("a failed write left %v behind in somebody's directory", left)
	}
}

// TestTheShippedBinaryRefusesADeviceAsAReportDestination pins OBS34, which was
// found only because the binary travelled to another system.
//
// The old answer named a temporary file the user had never mentioned. It was
// true and it was not an answer.
func TestTheShippedBinaryRefusesADeviceAsAReportDestination(t *testing.T) {
	device := "/dev/null"
	if runtime.GOOS == "windows" {
		device = "NUL"
	}

	r := runProgram(t, aTarget, "--json", "--out", device)
	if r.code == exitcode.OK.Int() {
		t.Fatal("a device was accepted as a report destination")
	}
	if !strings.Contains(strings.ToLower(r.stderr), "device") {
		t.Errorf("the refusal does not say the destination is a device: %q", r.stderr)
	}
	if strings.Contains(r.stderr, ".certdoctor-report-") {
		t.Errorf("the refusal names a temporary file nobody asked for: %q", r.stderr)
	}
}

// ---------------------------------------------------------------- group B

// TestTheShippedBinaryPutsNothingButJSONOnStandardOutput is the pipeline
// contract at the only place it is real.
//
// It validates against the SAME schema the program uses, rather than against a
// second description of the document written here - a copy would agree with
// itself however wrong both were.
func TestTheShippedBinaryPutsNothingButJSONOnStandardOutput(t *testing.T) {
	r := runProgram(t, aTarget, "--json")
	if r.code != exitcode.Inconclusive.Int() {
		t.Fatalf("the run ended with %d: %s", r.code, r.stderr)
	}
	if err := render.ValidateDocument([]byte(r.stdout)); err != nil {
		t.Fatalf("what came out of the pipe is not the document this program declares:\n%v\n%s", err, r.stdout)
	}

	// Every declared layer, exactly once. A missing row would be a silence, and
	// a consumer filtering on it would read that as "no problem found".
	var document struct {
		Layers []struct {
			ID string `json:"id"`
		} `json:"layers"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &document); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if len(document.Layers) != len(layer.All) {
		t.Fatalf("%d layers are declared and the document carries %d", len(layer.All), len(document.Layers))
	}
	for i, id := range layer.All {
		if document.Layers[i].ID != id.String() {
			t.Errorf("row %d is %q where the registry declares %q", i, document.Layers[i].ID, id)
		}
	}
}

// TestTheShippedBinaryWritesNothingToStandardOutputWhenItFails keeps a pipeline
// from parsing an error as a result.
func TestTheShippedBinaryWritesNothingToStandardOutputWhenItFails(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"--json", "not a url at all"},
		{aTarget, "--timeout", "abc"},
		{aTarget, "--format", "invented"},
	} {
		r := runProgram(t, args...)
		if r.code == exitcode.OK.Int() {
			continue
		}
		if r.stdout != "" {
			t.Errorf("%v ended with %d and still put %q on standard output", args, r.code, r.stdout)
		}
		if r.stderr == "" {
			t.Errorf("%v ended with %d and said nothing about why", args, r.code)
		}
	}
}

// TestTheShippedBinarySendsNoColourIntoAPipe covers what OBS28 says a test
// inside the program cannot: the branch that asks whether the destination is a
// terminal.
//
// Everything this suite runs is captured through a pipe, so the answer has to be
// no. Colour arriving here would reach a log file or a ticket as <-[34m, which
// reads as a corrupted report.
func TestTheShippedBinarySendsNoColourIntoAPipe(t *testing.T) {
	for _, args := range [][]string{{aTarget}, {aTarget, "--json"}, {"--help"}} {
		r := runProgram(t, args...)
		for where, text := range map[string]string{"standard output": r.stdout, "standard error": r.stderr} {
			if strings.Contains(text, "\x1b") {
				t.Errorf("%v put an escape sequence on %s", args, where)
			}
		}
	}
}

// ---------------------------------------------------------------- group C

// TestTheShippedBinaryTellsAnUnreadableValueFromAnImpossibleOne pins OBS27.
//
// The fuzz guard asks whether a code is IN THE TABLE and is green whichever of
// them comes back, so nothing until now held these two apart. For a script
// writing `if code == 2` the difference decides whether one typo in one flag is
// caught and the other waved through.
func TestTheShippedBinaryTellsAnUnreadableValueFromAnImpossibleOne(t *testing.T) {
	unreadable := runProgram(t, aTarget, "--timeout", "abc")
	if unreadable.code != exitcode.Usage.Int() {
		t.Errorf("a value that does not parse ended with %d, not the usage code: %s", unreadable.code, unreadable.stderr)
	}

	impossible := runProgram(t, aTarget, "--timeout", "-5")
	if impossible.code != exitcode.Config.Int() {
		t.Errorf("a value that parses and cannot be met ended with %d, not the config code: %s",
			impossible.code, impossible.stderr)
	}

	if unreadable.code == impossible.code {
		t.Error("both bad values for the same flag give the same code, so a script cannot tell them apart")
	}
}

// TestTheShippedBinaryNamesTheSwitchItDidNotRecogniseRatherThanTheURL keeps a
// mistyped flag from being reported as a bad address.
func TestTheShippedBinaryNamesTheSwitchItDidNotRecogniseRatherThanTheURL(t *testing.T) {
	r := runProgram(t, aTarget, "--jsno")
	if r.code != exitcode.Usage.Int() {
		t.Fatalf("a misspelt switch ended with %d: %s", r.code, r.stderr)
	}
	if !strings.Contains(r.stderr, "jsno") {
		t.Errorf("the message does not name the switch that was not recognised: %q", r.stderr)
	}
	if strings.Contains(r.stderr, aTarget) {
		t.Errorf("the message blames the URL for a mistake in a switch: %q", r.stderr)
	}
}

// TestTheShippedBinaryHonoursASwitchAfterTheURL is docs/22 row 20 seen from
// outside.
//
// The standard flag package stops parsing at the first non-flag argument and
// does not report it, so this exact command line once printed a terminal report
// and said nothing about --json.
func TestTheShippedBinaryHonoursASwitchAfterTheURL(t *testing.T) {
	r := runProgram(t, aTarget, "--json")
	if err := render.ValidateDocument([]byte(r.stdout)); err != nil {
		t.Fatalf("a switch written after the URL was ignored - what came out is not the document:\n%v", err)
	}
}

// TestTheShippedBinaryAnswersEveryMetaSwitchFromItself covers the switches that
// describe the tool rather than a machine.
//
// --license matters most: a person holding a downloaded executable has no
// repository to look in, so the text has to be IN THE BINARY. Nothing but
// running it can show that.
func TestTheShippedBinaryAnswersEveryMetaSwitchFromItself(t *testing.T) {
	help := runProgram(t, "--help")
	if help.code != exitcode.OK.Int() {
		t.Fatalf("--help ended with %d: %s", help.code, help.stderr)
	}
	page := help.stdout + help.stderr

	// The list of switches comes from the declaration the program parses with,
	// not from a list written here that could quietly fall behind it.
	fs, _ := newFlagSet()
	fs.VisitAll(func(f *flag.Flag) {
		if !strings.Contains(page, "-"+f.Name) {
			t.Errorf("the help page does not mention -%s", f.Name)
		}
	})

	version := runProgram(t, "--version")
	if version.code != exitcode.OK.Int() || strings.TrimSpace(version.stdout) == "" {
		t.Errorf("--version ended with %d and said %q", version.code, version.stdout)
	}

	license := runProgram(t, "--license")
	if license.code != exitcode.OK.Int() {
		t.Fatalf("--license ended with %d: %s", license.code, license.stderr)
	}
	if !strings.Contains(license.stdout, "GNU GENERAL PUBLIC LICENSE") {
		t.Error("--license does not print the licence this project is released under")
	}
	// The full text, not an identifier. A short answer here would mean the embed
	// silently stopped reaching the binary.
	if len(license.stdout) < 30_000 {
		t.Errorf("--license printed %d bytes, which is too short to be the whole text", len(license.stdout))
	}
}

// ---------------------------------------------------------------- group D

// TestTheShippedBinaryProducesTheSameDocumentTwice is repeatability measured
// through a REAL CLOCK.
//
// There is already a test for this inside the program, and it runs against a
// clock that is a stand-in - which hides exactly the kind of non-determinism
// this catches, because a fake clock makes two runs identical in the one field
// that legitimately differs. Here the two runs differ in that field and in
// nothing else, and the list of fields allowed to differ is pinned rather than
// assumed.
//
// IT ASKS ABOUT A NAME THAT CANNOT EXIST, AND IT DID NOT HAVE TO UNTIL L1.
// While this program reached nothing, any target produced the same document
// twice. Now it measures somebody else's DNS, and the resolver behind
// example.com rotates the ORDER of the addresses it returns - so two runs
// differ, correctly, and this check would report a load balancer doing its job
// as a defect in our output.
//
// The property being defended never included the network: it is that OUR OWN
// ordering is stable, because iterating a Go map is randomised and a renderer
// that walked one would shuffle rows between runs. A name that resolves nowhere
// keeps that property askable.
func TestTheShippedBinaryProducesTheSameDocumentTwice(t *testing.T) {
	first := runProgram(t, anUnresolvableTarget, "--json")
	second := runProgram(t, anUnresolvableTarget, "--json")

	if first.code != second.code {
		t.Fatalf("the same command ended with %d and then %d", first.code, second.code)
	}
	if first.stdout == "" {
		t.Fatal("the run produced no document, so comparing two of them would compare nothing")
	}

	a := decodeDocument(t, first.stdout)
	b := decodeDocument(t, second.stdout)

	// Blanked by NAME, everywhere they occur, so a duration added inside a
	// finding later is covered without this test being edited.
	varying := map[string]bool{"started_at": true, "duration_ms": true}
	if !differsOnly(t, a, b, varying) {
		t.Errorf("two runs of the same command differ outside %v:\n--- first\n%s\n--- second\n%s",
			varyingNames(varying), first.stdout, second.stdout)
	}

	// And the fields allowed to vary have to BE there, otherwise this check
	// would pass just as well against a document that lost them.
	if !hasEvery(a, varying) {
		t.Errorf("the document is missing one of %v, so this comparison proves less than it appears to",
			varyingNames(varying))
	}
}

func decodeDocument(t *testing.T, text string) map[string]any {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal([]byte(text), &decoded); err != nil {
		t.Fatalf("the document does not parse: %v", err)
	}
	return decoded
}

// blankVarying replaces the value of every key named in varying, at any depth.
func blankVarying(value any, varying map[string]bool) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, inner := range typed {
			if varying[key] {
				out[key] = nil
				continue
			}
			out[key] = blankVarying(inner, varying)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, inner := range typed {
			out[i] = blankVarying(inner, varying)
		}
		return out
	}
	return value
}

func differsOnly(t *testing.T, a, b map[string]any, varying map[string]bool) bool {
	t.Helper()
	return reflect.DeepEqual(blankVarying(a, varying), blankVarying(b, varying))
}

// hasEvery reports whether each named key occurs at least once in the document.
func hasEvery(value any, wanted map[string]bool) bool {
	found := map[string]bool{}
	var walk func(any)
	walk = func(v any) {
		switch typed := v.(type) {
		case map[string]any:
			for key, inner := range typed {
				if wanted[key] {
					found[key] = true
				}
				walk(inner)
			}
		case []any:
			for _, inner := range typed {
				walk(inner)
			}
		}
	}
	walk(value)
	return len(found) == len(wanted)
}

func varyingNames(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	return out
}

// ---------------------------------------------------------------- group E

// TestTheShippedBinaryKeepsAProxyPasswordOffEverySurface is inviolable rule 17
// checked the way it will actually be broken: on a real command line, with a
// real environment, against the real program.
//
// The password here is invented and looks like nothing anybody uses, because
// this file is public and stays public.
func TestTheShippedBinaryKeepsAProxyPasswordOffEverySurface(t *testing.T) {
	const secret = "zzsecretzz"
	env := []string{"HTTPS_PROXY=http://someone:" + secret + "@proxy.example.com:8080"}

	for _, args := range [][]string{{aTarget}, {aTarget, "--json"}, {aTarget, "--redact"}} {
		r := startProgram(t, invocation{env: env}, args...)
		if strings.Contains(r.stdout, secret) {
			t.Errorf("%v put the proxy password on standard output", args)
		}
		if strings.Contains(r.stderr, secret) {
			t.Errorf("%v put the proxy password on standard error", args)
		}
		// The other side. A run that printed nothing would satisfy the check
		// above, and the variable has to be REPORTED - that is the product.
		if !strings.Contains(r.stdout, "HTTPS_PROXY") {
			t.Errorf("%v does not report that HTTPS_PROXY is set at all", args)
		}
	}
}

// TestTheShippedBinaryKeepsTheDisabledCertificateCheckVisible is the same rule
// from the other side, and the side that is easy to break while fixing the
// first one.
//
// NODE_TLS_REJECT_UNAUTHORIZED=0 means a runtime has stopped verifying
// certificates. The value IS the finding, and masking once deleted it because
// the name contains a word that looks like a credential.
func TestTheShippedBinaryKeepsTheDisabledCertificateCheckVisible(t *testing.T) {
	env := []string{"NODE_TLS_REJECT_UNAUTHORIZED=0"}

	r := startProgram(t, invocation{env: env}, aTarget, "--json")
	if !strings.Contains(r.stdout, "NODE_TLS_REJECT_UNAUTHORIZED") {
		t.Fatalf("the variable is not reported at all:\n%s", r.stdout)
	}

	var document struct {
		Layers []struct {
			Findings []struct {
				EnvironmentVariable *struct {
					Name  string  `json:"name"`
					Value *string `json:"value"`
				} `json:"environment_variable"`
			} `json:"findings"`
		} `json:"layers"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &document); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	for _, row := range document.Layers {
		for _, finding := range row.Findings {
			v := finding.EnvironmentVariable
			if v == nil || v.Name != "NODE_TLS_REJECT_UNAUTHORIZED" {
				continue
			}
			if v.Value == nil || *v.Value != "0" {
				t.Errorf("the disabled certificate check was reported as %v, and that value is the whole finding", v.Value)
			}
			return
		}
	}
	t.Error("no finding carries NODE_TLS_REJECT_UNAUTHORIZED, so nothing was checked here")
}

// TestTheShippedBinaryWritesAReportOnlyItsOwnerCanRead covers the mode bits,
// where they mean something.
//
// The report carries somebody's proxy configuration and internal host names. On
// a shared machine a world readable one is a leak that no amount of masking
// inside the document prevents.
func TestTheShippedBinaryWritesAReportOnlyItsOwnerCanRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("NOT CHECKED: mode bits do not carry this meaning on this system, so the report's " +
			"permissions were not established. This is a skip, not a pass.")
	}

	dir := t.TempDir()
	r := startProgram(t, invocation{dir: dir}, aTarget, "--json", "--out", "report.json")
	if r.code != exitcode.Inconclusive.Int() {
		t.Fatalf("writing the report ended with %d: %s", r.code, r.stderr)
	}

	info, err := os.Stat(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatalf("the report was not written: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("the report is readable beyond its owner: mode %o", mode)
	}
}

// ---------------------------------------------------------- needs a network

// TestTheShippedBinaryProducesAValidDocumentForARealName runs the whole path
// against a name that actually resolves.
//
// Today this establishes less than it will: no layer reaches the network yet, so
// it proves the program survives a real target and still produces a document its
// own schema accepts. It is here now so that the day L1 resolves for real, the
// check already exists and the change shows up in it.
func TestTheShippedBinaryProducesAValidDocumentForARealName(t *testing.T) {
	needsTheInternet(t)

	r := runProgram(t, aTarget, "--json")
	if err := render.ValidateDocument([]byte(r.stdout)); err != nil {
		t.Fatalf("a run against a real name produced a document its own schema refuses:\n%v", err)
	}
	if r.code != exitcode.Inconclusive.Int() && r.code != exitcode.Diagnosis.Int() {
		t.Errorf("a run against a real name ended with %d, which is neither a diagnosis nor an inability to make one: %s",
			r.code, r.stderr)
	}
}

// ------------------------------------------------------------- the canary

// TestTheFileCensusCanSeeAFileAppear is the canary under group A, and it is here
// because that group has the failure shape this project has already been bitten
// by once.
//
// A census that read NOTHING would make every "no file appeared" check pass
// while establishing nothing at all - two empty listings compare equal, exactly
// as two empty outputs did in TestTheSameRunProducesTheSameBytes, where a guard
// quietly became a coin toss. So the machinery is shown a file appearing and a
// file staying put, and it has to tell them apart.
func TestTheFileCensusCanSeeAFileAppear(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "deeper")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatalf("preparing: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "already-here"), []byte("x"), 0o600); err != nil {
		t.Fatalf("preparing: %v", err)
	}

	before := census(t, dir)
	if len(before) != 1 {
		t.Fatalf("the census saw %d files where one was planted, so it is not reading the directory", len(before))
	}

	// A file appearing, including one buried a level down - a walk that only
	// looked at the top would miss a temporary file written beside a nested
	// destination.
	if err := os.WriteFile(filepath.Join(nested, "appeared"), []byte("y"), 0o600); err != nil {
		t.Fatalf("planting: %v", err)
	}
	got := appeared(before, census(t, dir))
	if len(got) != 1 || got[0] != "deeper/appeared" {
		t.Errorf("the census did not report a file appearing one level down, it reported %v", got)
	}

	// And the other side: nothing new means nothing reported. A census that
	// called every file new would satisfy the check above and fail every real
	// run, which is a different uselessness.
	if quiet := appeared(census(t, dir), census(t, dir)); len(quiet) != 0 {
		t.Errorf("an unchanged directory was reported as having gained %v", quiet)
	}
}
