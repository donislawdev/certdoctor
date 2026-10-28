//go:build acceptance

package main

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor"
	"github.com/donislawdev/certdoctor/internal/adapter/render"
	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	"github.com/donislawdev/certdoctor/internal/core/layer"
	"github.com/donislawdev/certdoctor/internal/core/redact"
	"github.com/donislawdev/certdoctor/internal/core/report"
)

// aRealName is the URL for the checks whose question IS a real server - the
// chain somebody else's server presents, a public authority every store
// trusts.
//
// A documentation domain, because these runs are real and a name belonging to
// somebody would make this suite send traffic at them.
//
// EVERY CHECK THAT REACHES FOR IT ASKS needsTheInternet FIRST, and a guard
// outside this build tag holds that (OBS150). Until 2026-10-13 this was the
// target of every check, and seventeen of them turned red whenever the network
// blinked while asking questions about files, pipes and pages. Everything else
// runs against aLoopbackTarget.
const aRealName = "https://example.com"

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
	target := aLoopbackTarget(t)

	// A DIAGNOSIS, because the loopback target is built to fail L4 on every
	// machine - and a run that got that far also ran every trust store probe,
	// which is where another program gets started and could leave a file.
	before := census(t, dir)
	r := startProgram(t, invocation{dir: dir}, target)
	if r.code != exitcode.Diagnosis.Int() {
		t.Fatalf("an ordinary run ended with %d, not the code for a diagnosis: %s", r.code, r.stderr)
	}
	if new := appeared(before, census(t, dir)); len(new) != 0 {
		t.Errorf("a run that was asked for nothing on disk created %v", new)
	}

	// And with --out, EXACTLY the file that was asked for and no other. The
	// atomic write puts its temporary file beside the destination, so a run that
	// forgot to clean up would show two.
	before = census(t, dir)
	r = startProgram(t, invocation{dir: dir}, target, "--json", "--out", "report.json")
	if r.code != exitcode.Diagnosis.Int() {
		t.Fatalf("writing a report ended with %d: %s", r.code, r.stderr)
	}
	new := appeared(before, census(t, dir))
	if len(new) != 1 || new[0] != "report.json" {
		t.Errorf("asked for one file called report.json, the directory gained %v", new)
	}
}

// TestTheShippedBinaryRefusesADirectoryAndLeavesNoLitter is P3-7 through the
// binary, and it replaced a check that measured something else.
//
// IT USED TO REACH THE HALF-FINISHED WRITE, which was the only portable way in:
// a destination that is an existing DIRECTORY is refused by every platform at
// the rename. P3-7 put a refusal in FRONT of that, so the binary never gets
// there any more - and the old check would have gone on passing while proving
// nothing, which is the shape OBS81 names. The cleanup it used to cover is
// reached in process now, through writeAndRename.
//
// WHAT IT COVERS INSTEAD IS THE ANSWER A PERSON GETS. Measured before the fix:
// "moving the finished report to .: rename .\.certdoctor-report-1719771881 .:
// Access is denied." - true, and about a temporary file nobody mentioned.
func TestTheShippedBinaryRefusesADirectoryAndLeavesNoLitter(t *testing.T) {
	dir := t.TempDir()
	inTheWay := filepath.Join(dir, "report.json")
	if err := os.Mkdir(inTheWay, 0o755); err != nil {
		t.Fatalf("preparing the obstruction: %v", err)
	}

	before := census(t, dir)
	r := startProgram(t, invocation{dir: dir}, aLoopbackTarget(t), "--json", "--out", "report.json")

	if r.code == exitcode.OK.Int() {
		t.Error("writing a report over a directory reported success")
	}
	if r.stdout != "" {
		t.Errorf("a failed run put %d bytes on standard output", len(r.stdout))
	}
	if left := appeared(before, census(t, dir)); len(left) != 0 {
		t.Errorf("a refused write left %v behind in somebody's directory", left)
	}
	// AND THE SENTENCE IS OURS RATHER THAN THE OPERATING SYSTEM'S. Without this
	// assertion the check passes on the old behaviour too - the run failed and
	// cleaned up after itself either way, and what changed is the only part a
	// person reads.
	if !strings.Contains(r.stderr, "is a directory rather than a file") {
		t.Errorf("the binary does not say what is wrong with the destination: %q", r.stderr)
	}
	if strings.Contains(r.stderr, "certdoctor-report-") {
		t.Errorf("the binary names a temporary file nobody asked for: %q", r.stderr)
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

	r := runProgram(t, aLoopbackTarget(t), "--json", "--out", device)
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
	r := runProgram(t, aLoopbackTarget(t), "--json")
	if r.code != exitcode.Diagnosis.Int() {
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
	target := aLoopbackTarget(t)
	for _, args := range [][]string{
		{},
		{"--json", "not a url at all"},
		{target, "--timeout", "abc"},
		{target, "--format", "invented"},
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
	target := aLoopbackTarget(t)
	for _, args := range [][]string{{target}, {target, "--json"}, {"--help"}} {
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
	target := aLoopbackTarget(t)
	unreadable := runProgram(t, target, "--timeout", "abc")
	if unreadable.code != exitcode.Usage.Int() {
		t.Errorf("a value that does not parse ended with %d, not the usage code: %s", unreadable.code, unreadable.stderr)
	}

	impossible := runProgram(t, target, "--timeout", "-5")
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
	target := aLoopbackTarget(t)
	r := runProgram(t, target, "--jsno")
	if r.code != exitcode.Usage.Int() {
		t.Fatalf("a misspelt switch ended with %d: %s", r.code, r.stderr)
	}
	if !strings.Contains(r.stderr, "jsno") {
		t.Errorf("the message does not name the switch that was not recognised: %q", r.stderr)
	}
	if strings.Contains(r.stderr, target) {
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
	r := runProgram(t, aLoopbackTarget(t), "--json")
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
	// And the notices of the code by others that it links, byte for byte as
	// the tree holds them - ADR116. A binary built from an older tree, or one
	// whose embed of the notices stopped reaching it, answers with the GPL
	// alone and passes every check above.
	if want := certdoctor.License + "\n" + certdoctor.Notices; license.stdout != want {
		t.Errorf("--license printed %d bytes, want the GPL and then THIRD-PARTY-NOTICES.md, %d bytes",
			len(license.stdout), len(want))
	}
}

// ------------------------------------------------------------ group C2, L1

// resolutionRow is the body L1 fills in, decoded the way a consumer would.
type resolutionRow struct {
	Name         string   `json:"name"`
	View         string   `json:"view"`
	Resolver     *string  `json:"resolver"`
	QueryType    *string  `json:"query_type"`
	ResponseCode *string  `json:"response_code"`
	NoAnswer     *string  `json:"no_answer"`
	Addresses    []string `json:"addresses"`
	Divergence   *string  `json:"divergence"`
}

type layerRow struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	Reason   string `json:"reason"`
	Detail   string `json:"detail"`
	Findings []struct {
		Kind           string         `json:"kind"`
		NameResolution *resolutionRow `json:"name_resolution"`
	} `json:"findings"`
}

// resolutionLayer runs the binary against a name that cannot exist and returns
// L1's row, or SKIPS LOUDLY.
//
// THE SKIP IS THE POINT AND NOT AN ESCAPE HATCH - OBS46. This suite was, until
// L1, a gate that needed no network at all, and that quiet property is what made
// it repeatable in CI and on a train. L1 ends it by definition: a machine with no
// resolver configured, or with its DNS server behind a cut cable, cannot answer
// these questions. Such a run must say what went unestablished rather than pass
// having checked nothing - which is the failure shape this whole suite exists
// against.
//
// The target is under .invalid, reserved by RFC 2606 and delegated to nobody, so
// the query never leaves the user's own network and NXDOMAIN comes back from the
// local resolver. That keeps this repeatable without the internet.
func resolutionLayer(t *testing.T, args ...string) (layerRow, string) {
	t.Helper()

	r := runProgram(t, append([]string{anUnresolvableTarget, "--json"}, args...)...)
	if r.stdout == "" {
		t.Fatalf("the run produced no document at all: %s", r.stderr)
	}
	if err := render.ValidateDocument([]byte(r.stdout)); err != nil {
		t.Fatalf("a real run produced a document its own schema refuses:\n%v", err)
	}

	var document struct {
		Layers []layerRow `json:"layers"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &document); err != nil {
		t.Fatalf("decoding: %v", err)
	}

	for _, row := range document.Layers {
		if row.ID != string(layer.Resolution) {
			continue
		}
		if row.Status == "UNKNOWN" {
			t.Skipf("NOT CHECKED: this machine's name resolution could not be exercised (%s: %s), so nothing was "+
				"established about how the binary reports the two views. This is a skip, not a pass.",
				row.Reason, row.Detail)
		}
		return row, r.stdout
	}
	t.Fatalf("the document carries no row for %s at all", layer.Resolution)
	return layerRow{}, ""
}

// TestTheShippedBinaryShowsBothViewsOfAName is D3 checked on the real binary,
// against a real resolver, and it asks about STRUCTURE rather than content.
//
// WHY NOT CONTENT - OBS46. Which addresses come back is a fact about somebody's
// network and a moving one: the resolver behind a large site hands out a
// rotating subset, which this suite already reported once as a defect in our own
// output. What the product promises is that both lenses are present, labelled,
// and told apart - and that survives being run anywhere.
func TestTheShippedBinaryShowsBothViewsOfAName(t *testing.T) {
	row, _ := resolutionLayer(t)

	direct, system := 0, 0
	for _, finding := range row.Findings {
		body := finding.NameResolution
		if body == nil {
			t.Errorf("a finding of kind %q in L1 carries no resolution body", finding.Kind)
			continue
		}
		if body.Name == "" {
			t.Error("a row says nothing about which name it answers for")
		}
		switch body.View {
		case "direct":
			direct++
			// The three columns the direct view MUST fill: this is the half of the
			// K2 contract that a plausible mistake leaves empty.
			if body.Resolver == nil || *body.Resolver == "" {
				t.Error("a direct row does not name the resolver it asked")
			}
			if body.QueryType == nil || *body.QueryType == "" {
				t.Error("a direct row does not say which record type it asked for")
			}
			if body.Divergence != nil {
				t.Errorf("a direct row carries the comparison %q, which describes the pair of views", *body.Divergence)
			}
		case "system":
			system++
			// And the three it MUST NOT: the platform resolves a name without
			// saying who answered, so filling these in would be invention that
			// reads like measurement.
			if body.Resolver != nil || body.QueryType != nil || body.ResponseCode != nil {
				t.Errorf("the system row claims to know resolver=%v query_type=%v response_code=%v, "+
					"none of which this system reports", body.Resolver, body.QueryType, body.ResponseCode)
			}
		default:
			t.Errorf("a row was seen through the view %q, which is neither lens", body.View)
		}
	}

	if direct == 0 {
		t.Error("the report holds no direct view at all, so D3 is half unmet")
	}
	if system != 1 {
		t.Errorf("the report holds %d system rows, want exactly one - there is one platform to ask", system)
	}
}

// TestTheShippedBinaryRefusesAPortThatIsNotAPort keeps a mistyped URL from being
// reported as a defect in this program.
//
// MEASURED BEFORE THE FIX: ":99999" reached a finding, the report contract
// refused it, L3 was discarded with "the layer broke its own contract" - a
// sentence about certdoctor - and L4 then said the name had resolved to no
// address about a name that had resolved to four.
func TestTheShippedBinaryRefusesAPortThatIsNotAPort(t *testing.T) {
	r := runProgram(t, "https://example.com:99999", "--json")
	if r.code != exitcode.Usage.Int() {
		t.Errorf("a port outside its range ended %d, want %d", r.code, exitcode.Usage.Int())
	}
	if r.stdout != "" {
		t.Errorf("a refused run put %d bytes on standard output", len(r.stdout))
	}
	if !strings.Contains(r.stderr, "1 to 65535") {
		t.Errorf("the refusal does not say what a port may be: %q", r.stderr)
	}
}

// TestTheShippedBinaryDoesNotAskDNSAboutAnAddress is the whole of that case on
// the binary, including the half that would break the run if it were left out.
//
// THE TARGET IS IN TEST-NET-1, RESERVED BY RFC 5737, so this suite sends nothing
// at anybody's service - the same courtesy the rest of it pays with a
// documentation name. Nothing there answers, which is fine: what is being
// checked is that L1 asked no question at all and still handed the address on.
func TestTheShippedBinaryDoesNotAskDNSAboutAnAddress(t *testing.T) {
	r := runProgram(t, "https://192.0.2.1", "--json", "--probe-timeout", "1")
	if r.stdout == "" {
		t.Fatalf("the run produced no document at all: %s", r.stderr)
	}
	if err := render.ValidateDocument([]byte(r.stdout)); err != nil {
		t.Fatalf("a real run produced a document its own schema refuses:\n%v", err)
	}

	var document struct {
		Layers []layerRow `json:"layers"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &document); err != nil {
		t.Fatalf("decoding: %v", err)
	}

	for _, row := range document.Layers {
		switch row.ID {
		case string(layer.Resolution):
			if row.Status != "UNKNOWN" || row.Reason != "nothing_to_check" {
				t.Errorf("L1 answered %s/%s about a literal address, and there was nothing to resolve",
					row.Status, row.Reason)
			}
			if len(row.Findings) != 0 {
				t.Errorf("L1 produced %d row(s) about a literal address, so a query went out about it",
					len(row.Findings))
			}
		case string(layer.TCP):
			// THE HALF THAT WOULD BREAK THE RUN. L3 dials what L1 hands on, and
			// the allowed set is widened from the same list - so an L1 that
			// answered "nothing to resolve" and passed nothing on would have this
			// run refuse the address the user typed, by its own guard.
			if len(row.Findings) != 1 {
				t.Errorf("L3 produced %d row(s), want one for the address that was typed - the seam is empty",
					len(row.Findings))
			}
		}
	}
}

// TestTheShippedBinaryDoesNotBlameTheMachineForItsOwnBudget is ADR58 observed on
// the shipped binary, and it is the check the defect it fixes would have failed.
//
// MEASURED BEFORE THE FIX: "--probe-timeout 0.001" ended with L1 FAIL and exit 4
// - the code whose own table says "the run succeeded and found at least one
// failure" - on a machine that resolves the same name in 26 ms, with every row
// saying this layer had run out of time. The verdict was our arithmetic wearing
// somebody else's name.
//
// IT SKIPS LOUDLY RATHER THAN PASSING VACUOUSLY. A millisecond is not a
// guarantee that work gets dropped: a machine with a local cache could answer
// every query inside one, and then there is nothing here to check. That is a
// skip, and the suite prints its skips for exactly this reason.
func TestTheShippedBinaryDoesNotBlameTheMachineForItsOwnBudget(t *testing.T) {
	r := runProgram(t, anUnresolvableTarget, "--json", "--probe-timeout", "0.001")
	if r.stdout == "" {
		t.Fatalf("the run produced no document at all: %s", r.stderr)
	}
	if err := render.ValidateDocument([]byte(r.stdout)); err != nil {
		t.Fatalf("a real run produced a document its own schema refuses:\n%v", err)
	}

	var document struct {
		Layers []layerRow `json:"layers"`
		Notes  []struct {
			Kind  string `json:"kind"`
			Layer string `json:"layer"`
		} `json:"notes"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &document); err != nil {
		t.Fatalf("decoding: %v", err)
	}

	var resolution layerRow
	for _, row := range document.Layers {
		if row.ID == string(layer.Resolution) {
			resolution = row
		}
	}
	dropped := 0
	for _, finding := range resolution.Findings {
		if body := finding.NameResolution; body != nil && body.NoAnswer != nil && *body.NoAnswer == "not_asked" {
			dropped++
		}
	}
	if dropped == 0 {
		t.Skip("NOT CHECKED: this machine answered every query inside a millisecond, so this run dropped no work and " +
			"there was nothing here to get wrong. This is a skip, not a pass.")
	}

	if resolution.Status == "FAIL" {
		t.Errorf("%d quer(ies) were never asked because this program ran out of its own time, and the layer still "+
			"reported FAIL: %s", dropped, resolution.Detail)
	}
	// AND IT SAYS SO WHERE SOMEBODY LOOKS FOR WHAT WAS GIVEN UP. The row carries
	// it too, but a reader scanning for dropped work reads the notes.
	said := false
	for _, note := range document.Notes {
		if note.Kind == "skipped" && note.Layer == string(layer.Resolution) {
			said = true
		}
	}
	if !said {
		t.Error("the run dropped queries and no note says so, which is the silence inviolable rule 1 forbids")
	}
}

// TestTheShippedBinaryPutsTheConvertedNameOnTheWire is the international-name
// fix observed on the shipped binary rather than at a seam inside it.
//
// THE TARGET IS UNDER .invalid SO THIS NEEDS NO PARTICULAR SITE TO EXIST. What
// is being checked is the NAME THAT WAS ASKED ABOUT, which the document states
// in every direct row, and that is true whether the answer is an address or
// NXDOMAIN. Pointing it at a real international site would make this check
// depend on somebody else's DNS and somebody else's uptime.
//
// BOTH HALVES OF THE DECISION ARE PINNED HERE, because they point in opposite
// directions and each looks like a mistake on its own: the rows carry the
// A-label because that is what went on the wire, and the target line carries
// what the person typed because that is what they asked about.
func TestTheShippedBinaryPutsTheConvertedNameOnTheWire(t *testing.T) {
	const typed = "b\u00fccher.invalid"
	const wire = "xn--bcher-kva.invalid"

	r := runProgram(t, "https://"+typed, "--json")
	if r.stdout == "" {
		t.Fatalf("the run produced no document at all: %s", r.stderr)
	}
	if err := render.ValidateDocument([]byte(r.stdout)); err != nil {
		t.Fatalf("a real run produced a document its own schema refuses:\n%v", err)
	}

	var document struct {
		Run struct {
			Target string `json:"target"`
		} `json:"run"`
		Layers []layerRow `json:"layers"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &document); err != nil {
		t.Fatalf("decoding: %v", err)
	}

	if !strings.Contains(document.Run.Target, typed) {
		t.Errorf("the report shows the target as %q, and the person typed %q", document.Run.Target, typed)
	}

	direct := 0
	for _, row := range document.Layers {
		if row.ID != string(layer.Resolution) {
			continue
		}
		if row.Status == "UNKNOWN" {
			t.Skipf("NOT CHECKED: this machine's name resolution could not be exercised (%s: %s), so nothing was "+
				"established about which spelling goes on the wire. This is a skip, not a pass.", row.Reason, row.Detail)
		}
		for _, finding := range row.Findings {
			body := finding.NameResolution
			if body == nil || body.View != "direct" {
				continue
			}
			direct++
			if body.Name != wire {
				t.Errorf("a direct row asked about %q, and the A-label of that name is %q", body.Name, wire)
			}
		}
	}
	if direct == 0 {
		t.Skip("NOT CHECKED: the document carries no direct row, so the spelling on the wire was not established. " +
			"This is a skip, not a pass.")
	}
}

// TestTheShippedBinaryStillAsksWhenBothBudgetsAreSwitchedOff is the flag
// combination the documentation calls "no limit" and the program answered by
// asking nobody.
//
// WHY IT BELONGS HERE AND NOWHERE ELSE. Every part of this was individually
// correct: the entry point turned "no budget" into "no deadline", the layer
// divided a deadline it did not have, and the DNS port refused a socket it
// could not bound. The defect existed only in the whole, across the seam
// between the command line and a layer - which is the one place the unit tests
// cannot stand, and the CR that found it reached it the same way, by running
// the binary.
//
// THE ASSERTION IS THAT AN ANSWER CAME BACK, not which one. A response code -
// NXDOMAIN, for a name under .invalid - is a fact off the wire, and it is
// exactly what was missing: the broken run produced rows saying the query could
// not be sent at all, under a layer that still called itself PASS.
func TestTheShippedBinaryStillAsksWhenBothBudgetsAreSwitchedOff(t *testing.T) {
	row, _ := resolutionLayer(t, "--timeout", "0", "--probe-timeout", "0")

	answered, silent := 0, 0
	for _, finding := range row.Findings {
		body := finding.NameResolution
		if body == nil || body.View != "direct" {
			continue
		}
		if body.ResponseCode != nil && *body.ResponseCode != "" {
			answered++
			continue
		}
		silent++
	}
	if answered == 0 {
		t.Errorf("with both budgets switched off the direct view got an answer out of %d row(s) exactly none of the "+
			"time - asking for no limit must not mean asking nobody", silent)
	}
}

// TestTheShippedBinaryClassifiesTheTwoViewsAgainstEachOther is the other half of
// P3: the comparison exists, sits where ADR37 put it, and carries a class from
// the closed list.
//
// IT DOES NOT ASSERT WHICH CLASS, and that is deliberate. The class is a fact
// about the machine this runs on - superset on a host that sees AAAA records,
// agree_none for a name nobody has - and pinning one here would make this check
// fail on a correctly working machine somewhere else.
func TestTheShippedBinaryClassifiesTheTwoViewsAgainstEachOther(t *testing.T) {
	row, _ := resolutionLayer(t)

	known := map[string]bool{}
	for _, class := range report.AllDivergences {
		known[class.String()] = true
	}

	classified := 0
	for _, finding := range row.Findings {
		body := finding.NameResolution
		if body == nil || body.View != "system" || body.Divergence == nil {
			continue
		}
		classified++
		if !known[*body.Divergence] {
			t.Errorf("the two views were classified as %q, which is outside the closed list", *body.Divergence)
		}
	}
	if classified != 1 {
		t.Errorf("%d rows carry the comparison, want exactly one - there is one comparison per run", classified)
	}

	// The verdict has to follow from it rather than being decided elsewhere. A
	// name under .invalid resolves nowhere, so a layer that assessed it and stayed
	// silent about the failure would be the shape D13 was written against.
	if row.Status == "FAIL" && row.Detail == "" {
		t.Error("the layer failed and said nothing about why")
	}
}

// TestTheShippedBinaryKeepsRealResolverAddressesOutOfARedactedReport is ADR32 on
// the one surface where the addresses are real.
//
// Every test of masking inside the program feeds it invented values. This is the
// only place where the resolvers are THIS MACHINE'S, read from its own
// configuration - which is the case the rule was written for: a report pasted
// into a ticket naming somebody's internal DNS server.
func TestTheShippedBinaryKeepsRealResolverAddressesOutOfARedactedReport(t *testing.T) {
	row, _ := resolutionLayer(t, "--redact")

	named := 0
	for _, finding := range row.Findings {
		body := finding.NameResolution
		if body == nil || body.Resolver == nil || *body.Resolver == "" {
			continue
		}
		named++
		// A pseudonym, not an address. Checked by shape rather than by comparing
		// against this machine's real resolvers, because reading those here would
		// put them in the test's own output.
		if !strings.HasPrefix(*body.Resolver, "[") || !strings.HasSuffix(*body.Resolver, "]") {
			t.Errorf("a redacted report names the resolver %q, which is not a pseudonym", *body.Resolver)
		}
	}
	if named == 0 {
		t.Error("no row names a resolver at all, so nothing here established that masking reached one")
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
	env := []string{"HTTPS_PROXY=http://someone:" + secret + "@" + aPortNobodyListensOn(t)}

	target := aLoopbackTarget(t)
	for _, args := range [][]string{{target}, {target, "--json"}, {target, "--redact"}} {
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

	r := startProgram(t, invocation{env: env}, aLoopbackTarget(t), "--json")
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
	r := startProgram(t, invocation{dir: dir}, aLoopbackTarget(t), "--json", "--out", "report.json")
	if r.code != exitcode.Diagnosis.Int() {
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

// TestTheShippedBinaryShowsTheChainItWasPresented is rule 12 checked on the
// SHIPPED BINARY rather than on a fixture, for the kind of finding where the
// evidence is the product.
//
// EVERY TEST OF L4 IN THIS REPOSITORY EXCEPT THIS ONE RUNS AGAINST A CHAIN WE
// MINTED. That is the right way to test the shapes, and it cannot answer the one
// question this check asks: does a real server's chain, parsed by the real
// adapter, survive all the way onto both surfaces a person actually reads.
//
// THE FINGERPRINT IS CHECKED WHOLE, ON THE TERMINAL PAGE. Truncating it would be
// the quiet kind of shortening the evidence contract forbids, and half a
// fingerprint cannot be compared against anything - which is the entire use a
// person has for it.
func TestTheShippedBinaryShowsTheChainItWasPresented(t *testing.T) {
	needsTheInternet(t)

	var document struct {
		Layers []struct {
			ID       string `json:"id"`
			Findings []struct {
				TLSHandshake *struct {
					Address string `json:"address"`
					Chain   []struct {
						Subject     string `json:"subject"`
						Issuer      string `json:"issuer"`
						Fingerprint string `json:"fingerprint_sha256"`
					} `json:"chain"`
				} `json:"tls_handshake"`
			} `json:"findings"`
		} `json:"layers"`
	}
	if err := json.Unmarshal([]byte(runProgram(t, aRealName, "--json").stdout), &document); err != nil {
		t.Fatalf("the document does not parse: %v", err)
	}

	carrying, rows := 0, 0
	var leafPrint string
	for _, row := range document.Layers {
		if row.ID != string(layer.TLS) {
			continue
		}
		for _, finding := range row.Findings {
			if finding.TLSHandshake == nil {
				continue
			}
			rows++
			if finding.TLSHandshake.Chain == nil {
				continue
			}
			carrying++
			for i, certificate := range finding.TLSHandshake.Chain {
				if len(certificate.Fingerprint) != 64 {
					t.Errorf("certificate %d carries a fingerprint of %d characters, and SHA-256 is 64",
						i, len(certificate.Fingerprint))
				}
				if certificate.Subject == "" || certificate.Issuer == "" {
					t.Errorf("certificate %d says neither what it is nor who signed it", i)
				}
			}
			leafPrint = finding.TLSHandshake.Chain[0].Fingerprint
		}
	}

	if rows == 0 {
		t.Fatal("a real server was reached and L4 produced no rows, so nothing here was established")
	}
	// ADR45 on the shipped binary: many rows, one chain.
	if carrying != 1 {
		t.Errorf("%d of %d rows carry a chain, and exactly one may", carrying, rows)
	}
	if !strings.Contains(runProgram(t, aRealName).stdout, leafPrint) {
		t.Error("the leaf fingerprint reaches the machine readable document and not the terminal page, " +
			"so the surfaces are not at parity for the one field somebody came here for")
	}
}

// TestTheShippedBinaryNeverMasksAFingerprint is the promise that survives the
// flag a person reaches for when they are about to paste a report somewhere.
//
// --redact is chosen precisely when the report is going to a ticket - which is
// also the moment somebody needs the evidence for a claim about interception.
// Masking the fingerprint there would leave an accusation with its proof removed,
// and it would look like working software.
func TestTheShippedBinaryNeverMasksAFingerprint(t *testing.T) {
	needsTheInternet(t)

	plain := runProgram(t, aRealName, "--json").stdout
	print64 := regexp.MustCompile(`"fingerprint_sha256": "([0-9a-f]{64})"`).FindStringSubmatch(plain)
	if print64 == nil {
		t.Fatal("no fingerprint reached the plain document, so there is nothing to check masking against")
	}

	redacted := runProgram(t, aRealName, "--json", "--redact").stdout
	if !strings.Contains(redacted, print64[1]) {
		t.Errorf("the fingerprint %s does not survive --redact, and it is the evidence rule 21 requires "+
			"to travel beside any claim about interception", print64[1])
	}
	// The other side, without which the check above is satisfied by a --redact
	// that does nothing at all.
	if !strings.Contains(redacted, redact.Placeholder) && !strings.Contains(redacted, "[host-") {
		t.Error("nothing in the redacted document was masked, so this check proved nothing about masking")
	}
}

// TestTheShippedBinaryProducesAValidDocumentForARealName runs the whole path
// against a name that actually resolves.
//
// IT ESTABLISHED LESS WHEN IT WAS WRITTEN AND THE COMMENT SAYING SO WAS TRUE
// UNTIL 2026-08-17. Four layers now reach the network on this path - L1 resolves,
// L3 connects, L4 hand shakes - so this is no longer "the program survives a real
// target"; it is the whole live path producing a document its own schema accepts.
// It was written before any of that existed, which is why the change showed up in
// it rather than needing a new check.
//
// CODE 0 IS ALLOWED SINCE ADR108. Until then two layers that were never written
// stood UNKNOWN in every run, so a real name could only end with 4 or 5. Now a
// healthy name on a runner with no proxy and a complete trust store ends with
// 0, and which of the three it gets depends on that runner rather than on this
// program - so the check is that the run ended with a verdict at all.
func TestTheShippedBinaryProducesAValidDocumentForARealName(t *testing.T) {
	needsTheInternet(t)

	r := runProgram(t, aRealName, "--json")
	if err := render.ValidateDocument([]byte(r.stdout)); err != nil {
		t.Fatalf("a run against a real name produced a document its own schema refuses:\n%v", err)
	}
	switch r.code {
	case exitcode.OK.Int(), exitcode.Diagnosis.Int(), exitcode.Inconclusive.Int():
	default:
		t.Errorf("a run against a real name ended with %d, which is not a verdict about it: %s", r.code, r.stderr)
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

// TestTheShippedBinaryOffersNoCommandWhereNothingIsBroken is the measured trap
// from the product side, and the shipped binary is the only witness for it.
//
// EVERY IN-PROCESS TEST OF THIS FEEDS THE LAYER A FIXTURE. Here the real probes
// run against the real stores on this machine - six Java stores, two curl
// binaries and git, measured 2026-08-19 - and the whole matrix comes back green
// or unassessed, because a public certificate authority is trusted by all of
// them. A command anywhere in that report would be advice invented for a machine
// with nothing wrong with it, and the person who ran it would be editing a trust
// store for no reason.
//
// IT IS THE SAME SHAPE AS THE BENCH CHECK AND A DIFFERENT WITNESS. The bench
// proves a command IS produced where one belongs; this proves none is produced
// where none does, on a machine nobody arranged.
func TestTheShippedBinaryOffersNoCommandWhereNothingIsBroken(t *testing.T) {
	needsTheInternet(t)

	document := runProgram(t, aRealName, "--json").stdout

	// The check is worth nothing unless the matrix was actually built, so the
	// half that proves the layer ran comes first.
	if !strings.Contains(document, `"trust_store"`) {
		t.Fatal("no trust store row reached the document, so nothing here says anything about commands")
	}
	// A PRECONDITION, NOT AN ASSERTION - and it was spelled as one until
	// 2026-09-02, which is why this check was red on every CI runner while
	// passing on the machine it was written on. Its own sentence says the case
	// is absent, and "this is not the case this check is about" is the wording
	// of a skip: the six Java stores, two curls and git that make this machine
	// the subject are not on a runner, so the subject is MISSING rather than
	// broken. A test that fails because its scenario did not occur reports the
	// absence of a machine as a defect in the program.
	//
	// IT IS LOUD BECAUSE acceptance.sh PRINTS SKIPS AND SAYS THEY ARE THINGS
	// NOBODY CHECKED. That banner is exactly the protection this needs: a
	// precondition that quietly stopped being met would take this guard away
	// without anybody noticing, which is the failure this file exists to catch.
	if !strings.Contains(document, `"trusts_presented_chain": true`) {
		t.Skip("NOT CHECKED: no store on this machine trusted the presented chain, so the case this check is " +
			"about - a machine with nothing wrong with it - did not occur. This is a skip, not a pass.")
	}

	if !strings.Contains(document, `"fix": null`) {
		t.Error("no row carries a null fix, so either the field is missing or every row was given a command")
	}
	if strings.Contains(document, `"command"`) {
		t.Error("the report offers a command to run against a public site every store here trusts - " +
			"advice invented for a machine with nothing wrong with it")
	}
}

// TestTheShippedBinaryWritesAMarkdownReportWithNoTerminalDressing is the
// question no in-process test of this renderer can answer.
//
// EVERY TEST OF Markdown HANDS IT A REPORT AND READS THE STRING BACK. That says
// the renderer is right and says nothing about the binary: the format has to be
// selected by a flag whose declaration carries a "built" bit, dispatched by a
// function that used to have two branches, and delivered down the same pipe the
// terminal uses. Three findings in this project came from exactly that gap.
//
// THE COLOUR CHECK IS THE HALF WORTH THE MOST. The terminal renderer decides on
// colour from what is behind standard output, and this one takes no options at
// all - so a dispatch that fell through to the terminal, or a markdown renderer
// that had grown a capability question, would show up here as an escape sequence
// in a document somebody is about to paste into a ticket.
func TestTheShippedBinaryWritesAMarkdownReportWithNoTerminalDressing(t *testing.T) {
	r := runProgram(t, aLoopbackTarget(t), "--format", "md")
	if r.code != exitcode.Diagnosis.Int() {
		t.Fatalf("the run ended with %d: %s", r.code, r.stderr)
	}
	if strings.Contains(r.stdout, "\x1b") {
		t.Errorf("the markdown report carries a terminal escape sequence")
	}

	// The shape a reader expects, and the three headings this document is
	// organised by. A page that lost one of them would still be markdown.
	for _, want := range []string{"# certdoctor", "## Verdict", "## Layers", "## Notes"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("the markdown report has no %q", want)
		}
	}

	// Every declared layer, exactly once, the same claim the JSON check above
	// makes: a missing row is a silence, and silence reads as "nothing found".
	for _, id := range layer.All {
		if strings.Count(r.stdout, "| "+id.String()+" |") != 1 {
			t.Errorf("the layer overview does not carry exactly one row for %s", id)
		}
	}
}

// TestTheShippedBinaryDeliversAMarkdownReportToAFileAndNotAlsoToThePipe covers
// the delivery half, which is a different code path from the rendering one.
//
// THE FIRST DRAFT OF THIS TEST COMPARED THE TWO OUTPUTS BYTE FOR BYTE and was
// wrong in a way worth recording: two runs against a live target MEASURE
// different things - resolver timings, connection timings - so it was comparing
// the network to itself and calling the difference a renderer defect. The claim
// it was reaching for is real but belongs elsewhere: Markdown has no fields, so
// it cannot depend on where its output goes, and that is guaranteed by the type
// rather than by a run.
//
// WHAT IS LEFT IS WHAT ONLY A REAL BINARY CAN SAY: the file is written, it holds
// a document rather than a fragment, it carries no terminal dressing, and the
// pipe stays EMPTY. A report delivered to both places would be read twice by
// anything downstream, and the run that wrote it would look identical to one
// that did not.
func TestTheShippedBinaryDeliversAMarkdownReportToAFileAndNotAlsoToThePipe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.md")
	r := runProgram(t, aLoopbackTarget(t), "--format", "md", "--out", path)
	if r.code != exitcode.Diagnosis.Int() {
		t.Fatalf("the run ended with %d: %s", r.code, r.stderr)
	}
	if r.stdout != "" {
		t.Errorf("the report went to a file AND to standard output:\n%s", r.stdout)
	}

	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the report back: %v", err)
	}
	document := string(onDisk)
	if strings.Contains(document, "\x1b") {
		t.Errorf("the markdown report on disk carries a terminal escape sequence")
	}
	for _, want := range []string{"# certdoctor", "## Verdict", "## Layers", "## Notes"} {
		if !strings.Contains(document, want) {
			t.Errorf("the report on disk has no %q", want)
		}
	}
	for _, id := range layer.All {
		if strings.Count(document, "| "+id.String()+" |") != 1 {
			t.Errorf("the report on disk does not carry exactly one row for %s", id)
		}
	}
}

// TestTheShippedBinaryWritesAnHTMLPageThatFetchesNothing is the check the whole
// design of that renderer was aimed at, asked where it actually matters.
//
// EVERY IN-PROCESS TEST OF HTML HANDS IT A REPORT AND READS THE STRING BACK.
// That says the renderer is right and says nothing about the binary: the format
// has to be selected by a flag whose declaration carries a "built" bit,
// dispatched by a switch that gained a third arm, and delivered down the same
// pipe the terminal uses. The dispatch is the interesting part - its default arm
// is the terminal, so a mis-wired case does not fail, it silently ships the
// WRONG DOCUMENT, and an escape sequence in the output is what that looks like.
//
// THE SECOND HALF IS A SECURITY CLAIM AND THIS IS THE ONLY PLACE IT CAN BE MADE
// ABOUT WHAT WE SHIP. A page that carried script or reached out for a font would
// be executable content, and a beacon, arriving in the inbox of the security
// team that a report about TLS interception is written for.
func TestTheShippedBinaryWritesAnHTMLPageThatFetchesNothing(t *testing.T) {
	r := runProgram(t, aLoopbackTarget(t), "--format", "html")
	if r.code != exitcode.Diagnosis.Int() {
		t.Fatalf("the run ended with %d: %s", r.code, r.stderr)
	}
	if strings.Contains(r.stdout, "\x1b") {
		t.Errorf("the html page carries a terminal escape sequence, so the dispatch fell through")
	}
	assertAnInertPage(t, "the page on standard output", r.stdout)
}

// TestTheShippedBinaryDeliversAnHTMLPageToAFileAndNotAlsoToThePipe covers the
// delivery half, which is a different code path from the rendering one.
//
// IT DOES NOT COMPARE TWO RUNS BYTE FOR BYTE, and the markdown test beside it
// records why: two runs against a live target measure different things, so a
// comparison of them is the network being compared with itself. What only a real
// binary can say is that the file is written, holds a whole document rather than
// a fragment, and that the pipe stays EMPTY - a report delivered to both places
// would be read twice by anything downstream.
func TestTheShippedBinaryDeliversAnHTMLPageToAFileAndNotAlsoToThePipe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.html")
	r := runProgram(t, aLoopbackTarget(t), "--format", "html", "--out", path)
	if r.code != exitcode.Diagnosis.Int() {
		t.Fatalf("the run ended with %d: %s", r.code, r.stderr)
	}
	if r.stdout != "" {
		t.Errorf("the report went to a file AND to standard output:\n%s", r.stdout)
	}

	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the report back: %v", err)
	}
	assertAnInertPage(t, "the page on disk", string(onDisk))
}

// TestTheShippedBinaryAcceptsHTMLOnStandardOutput settles the question docs/24
// parked for this slice.
//
// --out DEFAULTS TO "-", so refusing this combination would have meant that
// "certdoctor --format html <url>" - the shortest thing anybody would type -
// ends in a configuration error unless a path is supplied too. It is allowed,
// for the same reason --json on a pipe is: redirecting output is how a command
// line hands a document to a file, and a format that could not be redirected
// would be the only place in this program where a format restricts a
// destination.
func TestTheShippedBinaryAcceptsHTMLOnStandardOutput(t *testing.T) {
	r := runProgram(t, aLoopbackTarget(t), "--format", "html", "--out", "-")
	if r.code != exitcode.Diagnosis.Int() {
		t.Fatalf("--format html --out - ended with %d, want a report: %s", r.code, r.stderr)
	}
	if !strings.HasPrefix(r.stdout, "<!DOCTYPE html>") {
		t.Errorf("--out - did not put the page on standard output, it starts:\n%.80s", r.stdout)
	}
}

// assertAnInertPage is everything this project promises about a report somebody
// forwards, asked in one place because two call sites would drift.
func assertAnInertPage(t *testing.T, what, page string) {
	t.Helper()

	if !strings.HasPrefix(page, "<!DOCTYPE html>") || !strings.HasSuffix(page, "</html>\n") {
		t.Errorf("%s is not a whole document", what)
	}
	if strings.Contains(page, "\x1b") {
		t.Errorf("%s carries a terminal escape sequence", what)
	}

	// The shape a reader expects, and the headings this page is organised by.
	for _, want := range []string{"<title>", "<h1>", "<h2>Layers</h2>", "<h2>Notes</h2>"} {
		if !strings.Contains(page, want) {
			t.Errorf("%s has no %q", what, want)
		}
	}

	// Every declared layer, exactly once. A missing row is a silence, and
	// silence reads as "nothing was found".
	for _, id := range layer.All {
		if got := strings.Count(page, ">"+id.String()+"<"); got != 1 {
			t.Errorf("%s carries %d cells for %s, want exactly 1", what, got, id)
		}
	}

	// NOTHING EXECUTES AND NOTHING IS FETCHED. The stylesheet is inline, there
	// is no script, and the only address on the page points inside it.
	for _, forbidden := range []string{"<script", "<iframe", "<object", "<embed", "<link ", "javascript:", "src="} {
		if strings.Contains(strings.ToLower(page), forbidden) {
			t.Errorf("%s carries %q, which either executes or fetches", what, forbidden)
		}
	}
	for _, href := range regexp.MustCompile(`href="([^"]*)"`).FindAllStringSubmatch(page, -1) {
		if !strings.HasPrefix(href[1], "#") {
			t.Errorf("%s links to %q, which is not a place inside itself", what, href[1])
		}
	}
}
