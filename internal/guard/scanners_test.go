package guard

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// The scanners CI runs besides the tests - Semgrep, OSV and the dependency
// review - and the two scripts that decide around them. A scanner that runs and
// decides nothing looks exactly like one that found nothing, so each script is
// asked here what it does with a report it must refuse.

const (
	semgrepGate      = ".github/scripts/semgrep_gate.py"
	scannerImage     = ".github/scripts/osv_scanner_image.sh"
	scannerDigest    = ".github/osv-scanner-digest"
	osvPullRequest   = ".github/workflows/osv-pull-request.yml"
	osvWeekly        = ".github/workflows/osv-weekly.yml"
	dependencyReview = ".github/workflows/dependency-review.yml"
	dependabotConfig = ".github/dependabot.yml"
)

// interpreter finds a program a script needs. Every CI runner carries python
// and bash, so there a missing one is a failure. On a developer machine
// without it the test says so and skips.
func interpreter(t *testing.T, names ...string) string {
	t.Helper()
	for _, name := range names {
		if path, err := exec.LookPath(name); err == nil && runnable(path) {
			return path
		}
	}
	// Git's own bash sits two folders up from git, for when the bash on PATH
	// is the WSL one runnable refuses.
	if git, err := exec.LookPath("git"); err == nil && runtime.GOOS == "windows" && names[0] == "bash" {
		bash := filepath.Join(filepath.Dir(filepath.Dir(git)), "bin", "bash.exe")
		if _, err := os.Stat(bash); err == nil {
			return bash
		}
	}
	if os.Getenv("CI") != "" {
		t.Fatalf("none of %v is on this runner, so the script cannot be asked anything", names)
	}
	t.Skipf("none of %v is on this machine, so the script cannot be asked anything", names)
	return ""
}

// runnable leaves out two Windows programs that answer to the name and run
// nothing asked of them: the python and python3 in WindowsApps, which are
// placeholders offering to install Python until it is installed, and the bash
// in System32, which is WSL and reads paths as another system would.
func runnable(path string) bool {
	if runtime.GOOS != "windows" {
		return true
	}
	dir := strings.ToLower(filepath.Dir(path))
	return !strings.HasSuffix(dir, `\windowsapps`) && !strings.HasSuffix(dir, `\system32`)
}

// exitCode runs a command and returns its exit code and what it printed.
func exitCode(t *testing.T, cmd *exec.Cmd) (int, string) {
	t.Helper()
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), string(out)
	}
	t.Fatalf("%s could not be run: %v\n%s", cmd.Path, err, out)
	return -1, ""
}

// runSemgrepGate writes one report and returns the gate's exit code.
func runSemgrepGate(t *testing.T, python string, report any) int {
	t.Helper()
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("building the report: %v", err)
	}
	path := filepath.Join(t.TempDir(), "semgrep.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("writing the report: %v", err)
	}
	code, _ := exitCode(t, exec.Command(python, filepath.Join(moduleRoot(t), semgrepGate), path))
	return code
}

func semgrepReport(results, errs []any) map[string]any {
	return map[string]any{
		"results": results,
		"errors":  errs,
		"paths":   map[string]any{"scanned": []string{"a.go", "b.go"}},
	}
}

func semgrepFinding(severity string) any {
	return map[string]any{
		"check_id": "some.rule",
		"path":     "a.go",
		"start":    map[string]any{"line": 1},
		"extra":    map[string]any{"severity": severity, "message": "something"},
	}
}

// TestTheSemgrepGateDecidesFromTheReport asks the gate about every shape of
// report it has to tell apart. The severities first: semgrep's own --severity
// knows INFO, WARNING and ERROR only, while registry rules also carry HIGH and
// CRITICAL. Then a rule that could not run, which is not a rule that found
// nothing - but only at level "error", because a healthy run of this tree
// carries dozens of entries at level "warn". Then a scan that did not happen:
// no file, a file that is not JSON, and a valid report that read no file at
// all. Exit 2 for those, so they cannot pass for either a clean or a dirty tree.
func TestTheSemgrepGateDecidesFromTheReport(t *testing.T) {
	python := interpreter(t, "python3", "python")

	cases := []struct {
		name   string
		report any
		want   int
	}{
		{"an ERROR finding", semgrepReport([]any{semgrepFinding("ERROR")}, nil), 1},
		{"a HIGH finding", semgrepReport([]any{semgrepFinding("HIGH")}, nil), 1},
		{"a CRITICAL finding", semgrepReport([]any{semgrepFinding("CRITICAL")}, nil), 1},
		{"a WARNING finding", semgrepReport([]any{semgrepFinding("WARNING")}, nil), 0},
		{"an INFO finding", semgrepReport([]any{semgrepFinding("INFO")}, nil), 0},
		{"a clean report", semgrepReport(nil, nil), 0},
		{"a rule that could not run", semgrepReport(nil, []any{map[string]any{"level": "error", "type": "SemgrepError", "message": "a rule failed"}}), 1},
		{"a snippet semgrep did not parse", semgrepReport(nil, []any{map[string]any{"level": "warn", "type": "PartialParsing", "message": "a snippet"}}), 0},
		{"a report that read no file", map[string]any{"results": []any{}, "errors": []any{}, "paths": map[string]any{"scanned": []string{}}}, 2},
		{"a report that is not an object", []any{}, 2},
	}
	for _, c := range cases {
		if got := runSemgrepGate(t, python, c.report); got != c.want {
			t.Errorf("%s made the gate exit %d, and it has to exit %d", c.name, got, c.want)
		}
	}

	dir := t.TempDir()
	notJSON := filepath.Join(dir, "semgrep.json")
	if err := os.WriteFile(notJSON, []byte("<ERROR: missing output>"), 0o600); err != nil {
		t.Fatalf("writing the report: %v", err)
	}
	for name, path := range map[string]string{
		"a report that is not JSON": notJSON,
		"a report never written":    filepath.Join(dir, "was-never-written.json"),
	} {
		if got, out := exitCode(t, exec.Command(python, filepath.Join(moduleRoot(t), semgrepGate), path)); got != 2 {
			t.Errorf("%s made the gate exit %d, and it has to exit 2\n%s", name, got, out)
		}
	}
}

// runScannerImage runs the digest check against a pretend docker that reports
// the given images, with the digest file holding digestFile.
func runScannerImage(t *testing.T, bash, digestFile, ids, digests string) (int, string) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "osv-scanner-digest")
	if err := os.WriteFile(file, []byte(digestFile), 0o600); err != nil {
		t.Fatalf("writing the digest file: %v", err)
	}
	// docker is a shell function handed to the script, so nothing on this
	// machine is asked and no image has to exist.
	// The images are sha256:1, sha256:2 and so on, and the digests of each are
	// one part of digests, the parts split by "|".
	pretend := `docker() { case "$1 $2" in "image ls") printf '%s' "$FAKE_IDS" ;; "image inspect") v="FAKE_D_${@: -1}"; v="${v/sha256:/}"; printf '%s\n' "${!v}" ;; esac; }; export -f docker; bash "$0" "$1"`
	cmd := exec.Command(bash, "-c", pretend,
		filepath.ToSlash(filepath.Join(moduleRoot(t), scannerImage)), filepath.ToSlash(file))
	cmd.Env = append(os.Environ(), "FAKE_IDS="+ids)
	for i, part := range strings.Split(digests, "|") {
		cmd.Env = append(cmd.Env, "FAKE_D_"+strconv.Itoa(i+1)+"="+part)
	}
	return exitCode(t, cmd)
}

// TestTheScannerImageScriptRunsOnlyTheRecordedImage asks the check that stands
// before every OSV scan. It has to pass the image recorded in the file and
// nothing else: another digest behind the same tag, no image at all, and a
// file that does not hold exactly one digest all stop the job. The recorded
// file itself is asked too, so a digest written there in a shape the script
// refuses is found here rather than in the next pull request.
func TestTheScannerImageScriptRunsOnlyTheRecordedImage(t *testing.T) {
	bash := interpreter(t, "bash")
	recorded := strings.TrimSpace(readRel(t, moduleRoot(t), scannerDigest))
	const repository = "ghcr.io/google/osv-scanner-action@"
	other := "sha256:" + strings.Repeat("b", 64)
	one := "sha256:" + strings.Repeat("a", 64)

	if code, out := runScannerImage(t, bash, recorded+"\n", "sha256:1", repository+recorded); code != 0 {
		t.Errorf("the image recorded in %s was refused, exit %d\n%s", scannerDigest, code, out)
	}
	for _, c := range []struct {
		name, file, ids, digests string
	}{
		{"another image behind the tag", one, "sha256:1", repository + other},
		{"two images, one of them another", one, "sha256:1\nsha256:2", repository + one + "|" + repository + other},
		{"no image on the runner", one, "", ""},
		{"an empty digest file", "", "sha256:1", repository + one},
		{"a digest split in two", one[:30] + " " + one[30:], "sha256:1", repository + one},
		{"two digests in the file", one + "\n" + other, "sha256:1", repository + one},
	} {
		if code, out := runScannerImage(t, bash, c.file, c.ids, c.digests); code != 1 {
			t.Errorf("%s: the script exited %d, and it has to stop the job with 1\n%s", c.name, code, out)
		}
	}
}

// TestTheScannersAreWiredAsDecided reads the workflows for the arguments each
// scanner was measured with. Each one is a decision with a measurement behind
// it, written beside it in the workflow, and an edit that drops one leaves
// every run green.
func TestTheScannersAreWiredAsDecided(t *testing.T) {
	root := moduleRoot(t)
	files := map[string]string{}
	for _, rel := range []string{ciWorkflow, osvPullRequest, osvWeekly, dependencyReview, dependabotConfig} {
		files[rel] = readRel(t, root, rel)
	}
	requireNoViolations(t, checkScannerWiring(files), "the scanners as decided")
}

func TestTheScannerWiringGuardCanFail(t *testing.T) {
	scanned := "      - run: bash .github/scripts/osv_scanner_image.sh\n" +
		"        uses: google/osv-scanner-action/osv-scanner-action@abc\n" +
		"            --no-call-analysis=go\n"
	violations := checkScannerWiring(map[string]string{
		ciWorkflow: "jobs:\n  semgrep:\n    steps:\n" +
			"      # --metrics=off\n" +
			"      - run: semgrep scan --config p/default --json\n",
		osvPullRequest: "jobs:\n  scan:\n    steps:\n" +
			"      - uses: google/osv-scanner-action/osv-scanner-action@abc\n" +
			"      - run: bash .github/scripts/osv_scanner_image.sh\n",
		osvWeekly:        "jobs:\n  scan:\n    steps:\n" + scanned,
		dependencyReview: "jobs:\n  review:\n    steps:\n      - uses: actions/dependency-review-action@abc\n",
		dependabotConfig: "updates:\n  - package-ecosystem: gomod\n    cooldown:\n      default-days: 7\n  - package-ecosystem: pip\n",
	})
	requireViolation(t, violations, "never says --metrics=off")
	requireViolation(t, violations, "never says .github/scripts/semgrep_gate.py")
	requireViolation(t, violations, "runs the scanner before osv_scanner_image.sh")
	requireViolation(t, violations, "scans 1 time(s) and leaves testdata in 0")
	requireViolation(t, violations, "never says fail-on-severity: moderate")
	requireViolation(t, violations, "2 ecosystem(s) and 1 cooldown(s) of a week")
}

// uncommented drops the lines of a YAML file that are comments, so a word in
// a comment cannot pass for the argument it names.
func uncommented(body string) string {
	var lines []string
	for _, line := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}

// checkScannerWiring holds the workflows to the decisions they were written on.
func checkScannerWiring(files map[string]string) []Violation {
	var violations []Violation
	at := func(rel, detail string) { violations = append(violations, Violation{rel, 0, detail}) }
	says := func(rel, body, needle, why string) {
		if !strings.Contains(body, needle) {
			at(rel, "never says "+needle+", and "+why)
		}
	}

	semgrep := uncommented(jobBlocks(files[ciWorkflow])["semgrep"])
	says(ciWorkflow, semgrep, "-r .github/requirements-semgrep.txt", "the version has to come from the file Dependabot reads")
	says(ciWorkflow, semgrep, "--config p/default", "the rules come from the registry rather than from this repository")
	says(ciWorkflow, semgrep, "--metrics=off", "this repository sends no telemetry about its own source")
	says(ciWorkflow, semgrep, semgrepGate, "the report decides, not the scanner's exit code")

	for _, rel := range []string{osvPullRequest, osvWeekly} {
		body := uncommented(files[rel])
		check := strings.Index(body, "bash "+scannerImage)
		scanner := strings.Index(body, "google/osv-scanner-action/")
		if check < 0 || (scanner >= 0 && scanner < check) {
			at(rel, "runs the scanner before osv_scanner_image.sh has compared its image with "+scannerDigest)
		}
		scans := strings.Count(body, "google/osv-scanner-action/osv-scanner-action@")
		excluded := strings.Count(body, "--x-exclude=g:**/testdata")
		uncalled := strings.Count(body, "--no-call-analysis=go")
		if scans == 0 || excluded != scans || uncalled != scans {
			at(rel, "scans "+strconv.Itoa(scans)+" time(s) and leaves testdata in "+strconv.Itoa(excluded)+
				" and the call analysis in "+strconv.Itoa(uncalled)+" - every scan needs both, the reasons are in "+osvPullRequest)
		}
	}

	says(dependencyReview, uncommented(files[dependencyReview]), "fail-on-severity: moderate",
		"a vulnerable dependency has to fail the pull request rather than warn")

	bot := uncommented(files[dependabotConfig])
	ecosystems := strings.Count(bot, "package-ecosystem:")
	cooldowns := strings.Count(bot, "default-days: 7")
	if ecosystems == 0 || cooldowns != ecosystems {
		at(dependabotConfig, strconv.Itoa(ecosystems)+" ecosystem(s) and "+strconv.Itoa(cooldowns)+
			" cooldown(s) of a week - every update waits a week before it is proposed")
	}
	return violations
}
