package guard

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

// The release is three workflows, a build script and a signing script that run
// on a tag, on a maintainer's machine and on a published page - ADR116. None of
// that runs on a push, so a defect in it is found at the one moment it is most
// expensive: a tag spent, a card in the reader, a page somebody has already
// read. These guards read the files on every push instead, and each asks one
// thing that, if it went wrong, would surface only then.
const (
	releaseWorkflow = ".github/workflows/release.yml"
	attestWorkflow  = ".github/workflows/attest-release.yml"
	verifyWorkflow  = ".github/workflows/verify-release.yml"
	ciWorkflow      = ".github/workflows/ci.yml"
	buildScript     = ".github/scripts/build_release.sh"
	signingScript   = ".github/scripts/sign_release.py"
	macSigning      = ".github/scripts/sign_macos.sh"
	releaseNotes    = ".github/release-notes.md"
	signingPins     = ".github/signing-certificates.txt"
	sbomRenderer    = "cmd/sbom/spdx.go"
)

// spdxPredicate is the statement type a person is told to ask gh for. The
// notes write it by hand, the attestation makes it, the verifier asks for it,
// and a mismatch answers "no attestation found" about a correct release.
const spdxPredicate = "https://spdx.dev/Document/v2.3"

// pinNames are the two certificates a release is signed with.
var pinNames = []string{"windows-code-signing", "apple-developer-id"}

// TestTheReleaseBuildsTheTargetsTheNoticesAreCheckedFor ties three lists of the
// five builds to one decision. The notices guard asks go list what each of
// releaseTargets links, the release script builds its own list, and the CI
// matrix compiles a third. A target added to the release alone would ship
// notices nobody checked against what it links, and one dropped from CI would
// ship a build no push ever compiled.
func TestTheReleaseBuildsTheTargetsTheNoticesAreCheckedFor(t *testing.T) {
	root := moduleRoot(t)
	script, err := scriptTargets(readRel(t, root, buildScript))
	if err != nil {
		t.Fatalf("%s: %v", buildScript, err)
	}
	matrix, err := ciTargets(readRel(t, root, ciWorkflow))
	if err != nil {
		t.Fatalf("%s: %v", ciWorkflow, err)
	}
	requireNoViolations(t, append(checkTargets(buildScript, script), checkTargets(ciWorkflow, matrix)...),
		"the release targets")
}

func TestTheTargetGuardCanFail(t *testing.T) {
	got, err := scriptTargets("targets=(\n  windows/amd64\n  linux/amd64\n  linux/arm64\n  darwin/arm64\n  darwin/amd64\n)\n")
	if err != nil {
		t.Fatal(err)
	}
	violations := checkTargets("fixture", got)
	requireViolation(t, violations, "does not build windows/arm64")
	requireViolation(t, violations, "builds darwin/amd64")

	matrix, err := ciTargets("jobs:\n  release-build:\n    strategy:\n      matrix:\n        include:\n" +
		"          - goos: linux\n            goarch: amd64\n          - goos: linux\n            goarch: amd64\n  next:\n")
	if err != nil {
		t.Fatal(err)
	}
	requireViolation(t, checkTargets("fixture", matrix), "builds linux/amd64 twice")

	if _, err := scriptTargets("nothing here\n"); err == nil {
		t.Error("a script with no target list was read as one")
	}
	if _, err := ciTargets("jobs:\n  test:\n"); err == nil {
		t.Error("a workflow with no release-build job was read as one")
	}
}

// TestEveryActionIsPinnedToACommit holds every workflow to the rule ci.yml
// keeps by hand: an action is named by the commit it runs, with the release it
// is beside it. A tag can be moved to other code by whoever owns the action,
// and in the release workflows that code holds a token that can write to this
// repository - inviolable rule 23.
func TestEveryActionIsPinnedToACommit(t *testing.T) {
	root := moduleRoot(t)
	workflows := workflowFiles(t, root)
	var violations []Violation
	for _, rel := range workflows {
		violations = append(violations, checkPinnedActions(rel, readRel(t, root, rel))...)
	}
	requireNoViolations(t, violations, "actions pinned to a commit")
	for _, want := range []string{ciWorkflow, releaseWorkflow, attestWorkflow, verifyWorkflow} {
		if !slices.Contains(workflows, want) {
			t.Errorf("%s is not among the workflows read, so nothing here checks it", want)
		}
	}
}

func TestThePinGuardCanFail(t *testing.T) {
	body := "steps:\n" +
		"  - uses: actions/checkout@v7\n" +
		"  - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e\n" +
		"  # uses: a/comment@v1 is a comment\n" +
		"  - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2\n"
	violations := checkPinnedActions("fixture.yml", body)
	if len(violations) != 2 {
		t.Fatalf("want two violations, a tag and a commit without its release, got %v", violations)
	}
	requireViolation(t, violations, "actions/checkout@v7")
}

// TestAScriptAWorkflowRunsIsHandedToItsInterpreter keeps the release off the
// executable bit. A file committed from Windows is recorded without it, and a
// workflow that runs such a script by its path stops with "permission denied"
// - in the other project that would have been the FIRST release build. Handed
// to bash or python, the bit does not matter. The script also has to exist.
func TestAScriptAWorkflowRunsIsHandedToItsInterpreter(t *testing.T) {
	root := moduleRoot(t)
	exists := func(rel string) bool {
		_, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel)))
		return err == nil
	}
	var violations []Violation
	calls := 0
	for _, rel := range append(workflowFiles(t, root), buildScript) {
		found, v := checkScriptCalls(rel, readRel(t, root, rel), exists)
		calls += found
		violations = append(violations, v...)
	}
	requireNoViolations(t, violations, "scripts handed to their interpreter")
	if calls == 0 {
		t.Error("no workflow names a script at all, so this checked nothing")
	}
}

func TestTheInterpreterGuardCanFail(t *testing.T) {
	exists := func(rel string) bool { return rel != ".github/scripts/gone.sh" }
	body := "run: .github/scripts/build_release.sh 1 2\n" +
		"run: bash .github/scripts/gone.sh\n" +
		"run: bash .github/scripts/build_release.sh\n" +
		"# .github/scripts/in_a_comment.sh\n"
	found, violations := checkScriptCalls("fixture.yml", body, exists)
	if found != 3 {
		t.Errorf("want three calls read, got %d", found)
	}
	requireViolation(t, violations, "runs .github/scripts/build_release.sh by its path")
	requireViolation(t, violations, "names .github/scripts/gone.sh, which is not in the tree")
}

// TestThePinnedCertificatesAreDigestsWithADate reads the one written copy of
// each certificate digest. A digest, because a name can be issued twice. One
// copy, because the signing script and the verifier each carrying their own
// is exactly the drift a pin exists to catch - so both must read the file and
// neither may hold the digest itself.
//
// The dates are logged, not asserted. A certificate expiring is a fact of life
// and a red suite on that day helps nobody. The signing script refuses to sign
// with an expired one, which is where that refusal belongs.
func TestThePinnedCertificatesAreDigestsWithADate(t *testing.T) {
	root := moduleRoot(t)
	pins, violations := parsePins(readRel(t, root, signingPins))
	requireNoViolations(t, violations, "the pinned certificates")
	for _, name := range pinNames {
		t.Logf("%s expires %s", name, pins[name].expires.Format("2006-01-02"))
	}
	// The line that reads the file, not a mention of its name - both files also
	// name it in their messages, and those would survive the reading going away.
	for rel, readers := range map[string][]string{
		signingScript:  {`PIN_FILE = os.path.join(".github", "signing-certificates.txt")`},
		verifyWorkflow: {` .github/signing-certificates.txt)"`, `Select-String -Path ../.github/signing-certificates.txt`},
	} {
		body := readRel(t, root, rel)
		for _, reader := range readers {
			if !strings.Contains(body, reader) {
				t.Errorf("%s does not read %s with %s, so it carries its own idea of which certificate signs", rel, signingPins, reader)
			}
		}
	}
	for _, rel := range append(workflowFiles(t, root), signingScript, macSigning, buildScript, releaseNotes) {
		body := readRel(t, root, rel)
		for name, p := range pins {
			if strings.Contains(body, p.digest) {
				t.Errorf("%s carries the %s digest itself, a second copy that can drift from %s", rel, name, signingPins)
			}
		}
	}
}

func TestTheCertificatePinGuardCanFail(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	_, violations := parsePins("# a comment\n\n" +
		"windows-code-signing " + digest + " 2027-08-19\n" +
		"windows-code-signing " + digest + " 2027-08-19\n" +
		"apple-developer-id " + strings.ToUpper(digest) + " 2029-10-27\n" +
		"someone-else " + digest + " 2027-08-19\n" +
		"windows-code-signing " + digest + " 19.08.2027 extra\n")
	requireViolation(t, violations, "names windows-code-signing twice")
	requireViolation(t, violations, "apple-developer-id is not a lowercase sha256")
	requireViolation(t, violations, "names someone-else")
	requireViolation(t, violations, "has 4 fields where a pin has three")
	requireViolation(t, violations, "names no apple-developer-id")

	_, violations = parsePins("apple-developer-id " + digest + " 2029-13-27\n")
	requireViolation(t, violations, "is not a date")
}

// TestTheReleaseNoteSaysHowToCheckADownload holds the note the draft opens with
// to what it has to say. A person landing on a release page has to be told
// how to check what they downloaded, with the command that works for this
// repository, the predicate the attestation really carries, and the checksum
// file the signing script writes. The repository is read from go.mod, so a
// renamed module cannot leave the commands pointing at the old name.
func TestTheReleaseNoteSaysHowToCheckADownload(t *testing.T) {
	root := moduleRoot(t)
	modulePath, err := modulePathFrom(readRel(t, root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	repository := strings.TrimPrefix(modulePath, "github.com/")
	requireNoViolations(t, checkReleaseNote(readRel(t, root, releaseNotes), repository), "what the release note says")
	if !strings.Contains(readRel(t, root, signingScript), `REPO = "`+repository+`"`) {
		t.Errorf("%s does not name %s as the repository it fetches from and uploads to", signingScript, repository)
	}
}

func TestTheReleaseNoteGuardCanFail(t *testing.T) {
	violations := checkReleaseNote("gh attestation verify x -R someone/else\n--predicate-type https://spdx.dev/Document/v2.2\n", "a/b")
	requireViolation(t, violations, "never mentions -R a/b")
	requireViolation(t, violations, "never mentions --predicate-type "+spdxPredicate)
	requireViolation(t, violations, "never mentions verify-SHA256SUMS.txt")
}

// TestEveryWorkflowNamesThePredicateTheDocumentIs ties the statement type to
// the document cmd/sbom writes. The attestation workflow checks it against the
// statement it made, but only on a release - this asks on every push, and
// asks the renderer too, so moving the document to another SPDX version moves
// the predicate with it.
func TestEveryWorkflowNamesThePredicateTheDocumentIs(t *testing.T) {
	root := moduleRoot(t)
	files := map[string]string{}
	for _, rel := range []string{releaseNotes, attestWorkflow, verifyWorkflow, sbomRenderer} {
		files[rel] = readRel(t, root, rel)
	}
	requireNoViolations(t, checkPredicate(files), "the predicate type")
}

func TestThePredicateGuardCanFail(t *testing.T) {
	violations := checkPredicate(map[string]string{
		releaseNotes:   "--predicate-type " + spdxPredicate,
		attestWorkflow: "promised=https://spdx.dev/Document/v2.2",
		verifyWorkflow: "--predicate-type " + spdxPredicate,
		sbomRenderer:   `SPDXVersion: "SPDX-3.0"`,
	})
	if len(violations) != 2 || violations[0].File != attestWorkflow {
		t.Errorf("want the attestation workflow and the renderer named, got %v", violations)
	}
	requireViolation(t, violations, "never names "+spdxPredicate)
	requireViolation(t, violations, `writes no "SPDX-2.3"`)
}

// TestTheReleaseWorkflowOpensADraftAndPublishesNothing is the fence. A tag
// starts a release and a person finishes it: the build writes nothing but an
// empty draft, the only job holding a token that can write is behind the tag,
// and the tree has to pass the three checks before anything is built. The
// verifier holds no write permission at all.
func TestTheReleaseWorkflowOpensADraftAndPublishesNothing(t *testing.T) {
	root := moduleRoot(t)
	requireNoViolations(t, checkReleaseFences(readRel(t, root, releaseWorkflow), readRel(t, root, verifyWorkflow)),
		"the release fences")
}

func TestTheFenceGuardCanFail(t *testing.T) {
	release := "permissions:\n  contents: write\n" +
		"jobs:\n" +
		"  check:\n    steps:\n      - run: echo\n" +
		"  publish:\n    permissions:\n      id-token: write\n    steps:\n" +
		"      - run: gh release create v1 --notes x\n      - run: gh release upload v1 a.zip\n"
	violations := checkReleaseFences(release, "permissions:\n  contents: write\n")
	for _, want := range []string{
		"read only by default",
		"publish can write and is not fenced behind a tag",
		"uploads to a release",
		"opens a release that is not a draft",
		"never asks whether ci passed on the commit",
		"never asks whether the changelog is closed",
		"never asks whether the tag is the version the code says",
		"can write, and a verifier that can publish",
	} {
		requireViolation(t, violations, want)
	}
}

// TestNoReleaseCheckCanHideTheOnesBehindIt keeps the verifier's single verdict
// honest. Every check carries continue-on-error so the run reaches the verdict
// whatever happened, and the verdict reads each one's outcome. A check without
// continue-on-error stops the run and hides every check behind it, and one the
// verdict does not read is a check whose failure nobody sees - in the other
// project, a published release reported one problem where there were two.
// outcome and never conclusion, because continue-on-error rewrites conclusion
// to success.
func TestNoReleaseCheckCanHideTheOnesBehindIt(t *testing.T) {
	root := moduleRoot(t)
	checked, violations := checkVerdict(readRel(t, root, verifyWorkflow))
	requireNoViolations(t, violations, "the release verdict")
	if checked < 5 {
		t.Errorf("only %d checks feed the verdict, so this is not reading the file it means to", checked)
	}
}

func TestTheVerdictGuardCanFail(t *testing.T) {
	body := "jobs:\n  verify:\n    steps:\n" +
		"      - name: which\n        id: which\n" +
		"      - name: a\n        id: a\n        continue-on-error: true\n" +
		"      - name: b\n        id: b\n" +
		"      - name: c\n        id: c\n        continue-on-error: true\n" +
		"      - name: verdict\n        env:\n          A: ${{ steps.a.outcome }}\n          B: ${{ steps.b.outcome }}\n" +
		"          C: ${{ steps.c.conclusion }}\n"
	_, violations := checkVerdict(body)
	requireViolation(t, violations, "step b stops the run when it fails")
	requireViolation(t, violations, "the verdict never reads step c")
	requireViolation(t, violations, "reads steps.c.conclusion")
}

// --------------------------------------------------------------------------- //
// the checks, kept apart from the files so each canary can feed them a broken
// one
// --------------------------------------------------------------------------- //

// scriptTargets reads the targets=( ... ) list out of the build script.
func scriptTargets(body string) ([][2]string, error) {
	body = "\n" + body
	start := strings.Index(body, "\ntargets=(\n")
	if start < 0 {
		return nil, fmt.Errorf("no targets=( list")
	}
	rest := body[start+len("\ntargets=(\n"):]
	end := strings.Index(rest, "\n)")
	if end < 0 {
		return nil, fmt.Errorf("the targets=( list is never closed")
	}
	var targets [][2]string
	for _, line := range strings.Split(rest[:end], "\n") {
		goos, goarch, ok := strings.Cut(strings.TrimSpace(line), "/")
		if ok {
			targets = append(targets, [2]string{goos, goarch})
		}
	}
	return targets, nil
}

// ciTargets reads the goos and goarch pairs of the release-build matrix.
func ciTargets(body string) ([][2]string, error) {
	lines := strings.Split(body, "\n")
	jobStart := regexp.MustCompile(`^  [A-Za-z0-9_-]+:\s*$`)
	pair := regexp.MustCompile(`^\s+(?:- )?(goos|goarch):\s*(\S+)\s*$`)
	var targets [][2]string
	inside, found := false, false
	for _, line := range lines {
		if jobStart.MatchString(line) {
			inside = strings.TrimSpace(line) == "release-build:"
			found = found || inside
			continue
		}
		if !inside {
			continue
		}
		if m := pair.FindStringSubmatch(line); m != nil {
			if m[1] == "goos" {
				targets = append(targets, [2]string{m[2], ""})
			} else if len(targets) > 0 {
				targets[len(targets)-1][1] = m[2]
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("no release-build job")
	}
	return targets, nil
}

// checkTargets compares one list of builds with releaseTargets.
func checkTargets(rel string, got [][2]string) []Violation {
	want := map[[2]string]bool{}
	for _, target := range releaseTargets {
		want[target] = true
	}
	seen := map[[2]string]bool{}
	var violations []Violation
	for _, target := range got {
		name := target[0] + "/" + target[1]
		switch {
		case seen[target]:
			violations = append(violations, Violation{rel, 0, "builds " + name + " twice"})
		case !want[target]:
			violations = append(violations, Violation{rel, 0, "builds " + name + ", which is not a release target the notices are checked for"})
		}
		seen[target] = true
	}
	for _, target := range releaseTargets {
		if !seen[target] {
			violations = append(violations, Violation{rel, 0, "does not build " + target[0] + "/" + target[1] + ", a release target"})
		}
	}
	return sortViolations(violations)
}

// workflowFiles lists the workflows, every one of them, by name.
func workflowFiles(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, ".github", "workflows"))
	if err != nil {
		t.Fatalf("the workflows could not be listed: %v", err)
	}
	var files []string
	for _, entry := range entries {
		if !entry.IsDir() && (strings.HasSuffix(entry.Name(), ".yml") || strings.HasSuffix(entry.Name(), ".yaml")) {
			files = append(files, ".github/workflows/"+entry.Name())
		}
	}
	sort.Strings(files)
	return files
}

var (
	usesLine   = regexp.MustCompile(`^\s*(?:-\s+)?uses:\s*(\S+)(.*)$`)
	pinnedUses = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$`)
	releaseTag = regexp.MustCompile(`^\s+#\s+v[0-9]`)
)

// checkPinnedActions reports every action named by anything but a commit with
// its release written beside it.
func checkPinnedActions(rel, body string) []Violation {
	var violations []Violation
	for i, line := range strings.Split(body, "\n") {
		m := usesLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		switch {
		case !pinnedUses.MatchString(m[1]):
			violations = append(violations, Violation{rel, i + 1, m[1] + " is not pinned to a commit"})
		case !releaseTag.MatchString(m[2]):
			violations = append(violations, Violation{rel, i + 1, m[1] + " does not say which release that commit is"})
		}
	}
	return violations
}

var scriptCall = regexp.MustCompile(`(\S*)\s+(\.github/scripts/[A-Za-z0-9_.-]+)|^\s*(\.github/scripts/[A-Za-z0-9_.-]+)`)

// checkScriptCalls reports a script run by its path rather than handed to an
// interpreter, and a script named that is not there. It returns how many
// calls it read, so a scan that read none can say so.
func checkScriptCalls(rel, body string, exists func(string) bool) (int, []Violation) {
	var violations []Violation
	calls := 0
	for i, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		for _, m := range scriptCall.FindAllStringSubmatch(line, -1) {
			before, script := m[1], m[2]
			if script == "" {
				before, script = "", m[3]
			}
			calls++
			command := before[strings.LastIndexAny(before, `"'(:`)+1:]
			if command != "bash" && command != "python" && command != "python3" {
				violations = append(violations, Violation{rel, i + 1,
					"runs " + script + " by its path, which needs the executable bit git does not record from Windows - hand it to bash or python"})
			}
			if !exists(script) {
				violations = append(violations, Violation{rel, i + 1, "names " + script + ", which is not in the tree"})
			}
		}
	}
	return calls, violations
}

type pin struct {
	digest  string
	expires time.Time
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// parsePins reads the pin file: a name, a lowercase sha256 and a date on each
// line, both certificates, each once.
func parsePins(body string) (map[string]pin, []Violation) {
	pins := map[string]pin{}
	var violations []Violation
	for i, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		at := func(detail string) { violations = append(violations, Violation{signingPins, i + 1, detail}) }
		fields := strings.Fields(trimmed)
		if len(fields) != 3 {
			at(fmt.Sprintf("has %d fields where a pin has three: a name, a sha256, an expiry date", len(fields)))
			continue
		}
		name, digest, date := fields[0], fields[1], fields[2]
		if !slices.Contains(pinNames, name) {
			at("names " + name + ", which is not a certificate a release is signed with")
			continue
		}
		if _, twice := pins[name]; twice {
			at("names " + name + " twice")
			continue
		}
		if !sha256Hex.MatchString(digest) {
			at(name + " is not a lowercase sha256")
			continue
		}
		expires, err := time.Parse("2006-01-02", date)
		if err != nil {
			at(name + " expires on " + date + ", which is not a date")
			continue
		}
		pins[name] = pin{digest, expires}
	}
	for _, name := range pinNames {
		if _, ok := pins[name]; !ok {
			violations = append(violations, Violation{signingPins, 0, "names no " + name})
		}
	}
	return pins, violations
}

// checkReleaseNote reports what the note never says.
func checkReleaseNote(note, repository string) []Violation {
	var violations []Violation
	for _, promised := range []string{
		"gh attestation verify",
		"-R " + repository,
		"--predicate-type " + spdxPredicate,
		"verify-SHA256SUMS.txt",
	} {
		if !strings.Contains(note, promised) {
			violations = append(violations, Violation{releaseNotes, 0, "never mentions " + promised})
		}
	}
	return violations
}

// checkPredicate reports a file that does not name the predicate, and a
// renderer writing another SPDX version than the predicate names.
func checkPredicate(files map[string]string) []Violation {
	var violations []Violation
	for _, rel := range []string{releaseNotes, attestWorkflow, verifyWorkflow} {
		if !strings.Contains(files[rel], spdxPredicate) {
			violations = append(violations, Violation{rel, 0, "never names " + spdxPredicate})
		}
	}
	version := `"SPDX-` + spdxPredicate[strings.LastIndex(spdxPredicate, "/v")+2:] + `"`
	if !strings.Contains(files[sbomRenderer], version) {
		violations = append(violations, Violation{sbomRenderer, 0,
			"writes no " + version + ", the version " + spdxPredicate + " names"})
	}
	return violations
}

var tagFence = "if: startsWith(github.ref, 'refs/tags/')"

// checkReleaseFences reports a release workflow that can publish.
func checkReleaseFences(release, verify string) []Violation {
	var violations []Violation
	at := func(rel, detail string) { violations = append(violations, Violation{rel, 0, detail}) }
	if !strings.Contains(release, "\npermissions:\n  contents: read\n") && !strings.HasPrefix(release, "permissions:\n  contents: read\n") {
		at(releaseWorkflow, "is not read only by default")
	}
	for name, job := range jobBlocks(release) {
		if (strings.Contains(job, "contents: write") || strings.Contains(job, "id-token: write")) && !strings.Contains(job, tagFence) {
			at(releaseWorkflow, "job "+name+" can write and is not fenced behind a tag")
		}
	}
	if strings.Contains(release, "gh release upload") {
		at(releaseWorkflow, "uploads to a release, and the build is not what a user downloads")
	}
	if !strings.Contains(release, "gh release create") || !strings.Contains(release, "--draft") {
		at(releaseWorkflow, "opens a release that is not a draft")
	}
	for promise, sign := range map[string]string{
		"never asks whether ci passed on the commit":              "--workflow=ci.yml",
		"never asks whether the changelog is closed":              `awk '/^## \[Unreleased\]/{f=1;next}`,
		"never asks whether the tag is the version the code says": "GITHUB_REF_NAME#v",
	} {
		if !strings.Contains(release, sign) {
			at(releaseWorkflow, promise)
		}
	}
	if strings.Contains(verify, ": write") {
		at(verifyWorkflow, "can write, and a verifier that can publish is not a verifier")
	}
	return sortViolations(violations)
}

// jobBlocks splits a workflow into its jobs, by name.
func jobBlocks(body string) map[string]string {
	jobs := map[string]string{}
	jobStart := regexp.MustCompile(`^  ([A-Za-z0-9_-]+):\s*$`)
	_, after, found := strings.Cut(body, "\njobs:\n")
	if !found {
		return jobs
	}
	name := ""
	for _, line := range strings.Split(after, "\n") {
		if m := jobStart.FindStringSubmatch(line); m != nil {
			name = m[1]
		}
		if name != "" {
			jobs[name] += line + "\n"
		}
	}
	return jobs
}

var stepStart = regexp.MustCompile(`^\s+- (?:name|uses):`)
var stepID = regexp.MustCompile(`(?m)^\s+id:\s*([A-Za-z0-9_-]+)\s*$`)
var conclusionRead = regexp.MustCompile(`steps\.([A-Za-z0-9_-]+)\.conclusion`)

// checkVerdict reports a check that can hide the ones behind it, or that the
// verdict never reads. which is the step that names the tag, not a check.
func checkVerdict(body string) (int, []Violation) {
	var steps []string
	for _, line := range strings.Split(body, "\n") {
		if stepStart.MatchString(line) || len(steps) == 0 {
			steps = append(steps, "")
		}
		steps[len(steps)-1] += line + "\n"
	}
	var violations []Violation
	checked := 0
	for _, step := range steps {
		m := stepID.FindStringSubmatch(step)
		if m == nil || m[1] == "which" {
			continue
		}
		checked++
		if !strings.Contains(step, "continue-on-error: true") {
			violations = append(violations, Violation{verifyWorkflow, 0, "step " + m[1] + " stops the run when it fails, and hides every check behind it"})
		}
		if !strings.Contains(body, "steps."+m[1]+".outcome") {
			violations = append(violations, Violation{verifyWorkflow, 0, "the verdict never reads step " + m[1]})
		}
	}
	for _, m := range conclusionRead.FindAllStringSubmatch(body, -1) {
		violations = append(violations, Violation{verifyWorkflow, 0, "reads steps." + m[1] + ".conclusion, which continue-on-error turns into success"})
	}
	return checked, violations
}

// moduleRoot is the repository root, or the test stops.
func moduleRoot(t *testing.T) string {
	t.Helper()
	root, _, err := findModuleRoot()
	if err != nil {
		t.Fatalf("the module root could not be found: %v", err)
	}
	return root
}

// readRel reads a file named relative to the root, with forward slashes.
func readRel(t *testing.T, root, rel string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("%s could not be read: %v", rel, err)
	}
	return strings.ReplaceAll(string(body), "\r\n", "\n")
}
