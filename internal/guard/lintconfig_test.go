package guard

import (
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

const lintConfig = ".golangci.yml"

// lintersEnabled is the set .golangci.yml runs, written down a second time on
// purpose. Nothing else stops a change from deleting a linter to turn a red
// build green, and a gate that has vanished cannot announce itself. Growing the
// set is free - add the name here and there. Shrinking it reddens this, and
// shrinking it is the owner's decision.
var lintersEnabled = []string{
	"errcheck",
	"errorlint",
	"exhaustive",
	"gosec",
	"ineffassign",
	"misspell",
	"nolintlint",
}

// lintersKeptOut already run elsewhere, and under golangci-lint each would be
// a different question wearing the same name. Its staticcheck does not read
// staticcheck.conf and brings families the pinned staticcheck job does not
// run, its govet carries analysers go vet does not, and unused is inside the
// pinned staticcheck as U1000.
var lintersKeptOut = []string{
	"govet",
	"staticcheck",
	"unused",
}

// gosecExcluded are the gosec rules switched off for the whole tree. Each is
// there because something else answers the same question for every file -
// errcheck, or a list in this package with the reason beside each entry - and
// two lists of the same files drift apart. A rule switched off everywhere is a
// guard weakened, so a new one reddens this until it is written here too.
var gosecExcluded = []string{
	"G103", // unsafeAllowlist
	"G104", // errcheck
	"G204", // execAllowlist
	"G304", // fileReadAllowlist
}

// errcheckExcluded are the functions errcheck does not ask about: writes with
// fmt, which here go to standard error or carry help text. What this program
// promises to deliver - a report, a tool's page - is written with Write and
// its error is checked.
var errcheckExcluded = []string{
	"fmt.Fprint",
	"fmt.Fprintf",
	"fmt.Fprintln",
}

// testRuleLinters are the linters the one allowed exclusion rule may switch
// off in test files. A test reports through t rather than a returned error,
// and gosec there is about the files a test writes into its own temporary
// directory.
var testRuleLinters = []string{"errcheck", "gosec"}

// TestTheLinterSetOnlyGrows holds .golangci.yml and the job that runs it to
// the decisions in docs/16 D28: a set named in full, nothing taken out of it
// beyond the lists above, and a finding that is wrong answered with //nolint
// and its reason at the line rather than with a rule in the configuration.
func TestTheLinterSetOnlyGrows(t *testing.T) {
	root := moduleRoot(t)
	requireNoViolations(t, checkLintConfig(map[string]string{
		ciWorkflow: readRel(t, root, ciWorkflow),
		lintConfig: readRel(t, root, lintConfig),
	}), "the linter set")
}

func TestTheLinterGuardCanFail(t *testing.T) {
	good, ci := lintFixture(), lintJob()
	// The reverse canary first: the fixtures themselves are clean, so each
	// case below fails for the one thing it changes.
	requireNoViolations(t, checkLintConfig(map[string]string{ciWorkflow: ci, lintConfig: good}), "the clean fixture")

	cases := []struct {
		name, config, ci, want string
	}{
		{"the default set", strings.Replace(good, "  default: none\n", "  default: standard\n", 1), ci, "default: none"},
		{"a linter dropped", strings.Replace(good, "    - exhaustive\n", "", 1), ci, "exhaustive is written down here"},
		{"a linter added", strings.Replace(good, "    - gosec\n", "    - gosec\n    - revive\n", 1), ci, "revive is enabled"},
		{"a linter kept out", strings.Replace(good, "    - gosec\n", "    - gosec\n    - govet\n", 1), ci, "govet is enabled"},
		{"a gosec rule off", strings.Replace(good, "        - G304\n", "        - G304\n        - G402\n", 1), ci, "G402"},
		{"an errcheck function off", strings.Replace(good, "        - fmt.Fprintln\n", "        - fmt.Fprintln\n        - (io.Closer).Close\n", 1), ci, "(io.Closer).Close"},
		{"a rule for a path", strings.Replace(good, "    rules:\n", "    rules:\n      - path: internal/core\n        linters: [exhaustive]\n", 1), ci, "internal/core"},
		{"the test rule widened", strings.Replace(good, "linters: [errcheck, gosec]", "linters: [errcheck, gosec, errorlint]", 1), ci, "errorlint"},
		{"a whole path out", strings.Replace(good, "  exclusions:\n", "  exclusions:\n    paths:\n      - cmd\n", 1), ci, "paths"},
		{"a cap on findings", strings.Replace(good, "max-same-issues: 0", "max-same-issues: 3", 1), ci, "max-same-issues"},
		{"no config verify", good, strings.Replace(ci, "golangci-lint\" config verify", "golangci-lint\" version", 1), "config verify"},
		{"two versions", good, strings.Replace(ci, "run ./...'\n      - name: windows",
			"run ./...'\n      - run: go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0 run ./...\n      - name: windows", 1),
			"different versions"},
		{"a linter off on the command line", good, strings.Replace(ci, "golangci-lint\" run ./...", "golangci-lint\" run --disable gosec ./...", 1), "--disable"},
		{"another configuration", good, strings.Replace(ci, "golangci-lint\" run ./...", "golangci-lint\" run -c other.yml ./...", 1), "-c"},
		{"Windows not run", good, strings.Replace(ci, "          GOOS: windows\n", "", 1), "as Windows builds"},
		{"never run", good, strings.ReplaceAll(ci, "golangci-lint\" run ./...", "golangci-lint\" version"), "never runs"},
		{"no job", good, "on: push\njobs:\n  test:\n    steps:\n      - run: go test ./...\n", "never runs"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			requireViolation(t, checkLintConfig(map[string]string{ciWorkflow: c.ci, lintConfig: c.config}), c.want)
		})
	}
}

// lintFixture is a configuration this guard accepts, in the shape of the real
// one.
func lintFixture() string {
	return "version: \"2\"\n" +
		"linters:\n" +
		"  default: none\n" +
		"  enable:\n" +
		"    - errcheck\n    - errorlint\n    - exhaustive\n    - gosec\n    - ineffassign\n    - misspell\n    - nolintlint\n" +
		"  settings:\n" +
		"    gosec:\n" +
		"      excludes:\n" +
		"        - G103\n        - G104\n        - G204\n        - G304\n" +
		"    errcheck:\n" +
		"      exclude-functions:\n" +
		"        - fmt.Fprint\n        - fmt.Fprintf\n        - fmt.Fprintln\n" +
		"  exclusions:\n" +
		"    rules:\n" +
		"      - path: _test[.]go\n" +
		"        linters: [errcheck, gosec]\n" +
		"issues:\n" +
		"  max-issues-per-linter: 0\n" +
		"  max-same-issues: 0\n" +
		"formatters:\n" +
		"  enable:\n" +
		"    - gofmt\n"
}

// lintJob is a linters job this guard accepts, in the shape of the real one:
// installed once and pinned, the configuration verified, run as Linux and as
// Windows build the tree.
func lintJob() string {
	return "on: push\njobs:\n  linters:\n    steps:\n" +
		"      - name: install\n" +
		"        run: GOBIN=\"$RUNNER_TEMP/bin\" go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0\n" +
		"      - name: verify\n" +
		"        run: '\"$RUNNER_TEMP/bin/golangci-lint\" config verify'\n" +
		"      - name: linux\n" +
		"        run: '\"$RUNNER_TEMP/bin/golangci-lint\" run ./...'\n" +
		"      - name: windows\n" +
		"        env:\n" +
		"          GOOS: windows\n" +
		"        run: '\"$RUNNER_TEMP/bin/golangci-lint\" run ./...'\n"
}

var (
	lintVersion = regexp.MustCompile(`^@\S+`)
	windowsRun  = regexp.MustCompile(`(?m)^\s+GOOS:\s*windows\s*$`)
	// The command-line switches that change what runs or what is reported, and
	// so would replace .golangci.yml in silence.
	lintOverride = regexp.MustCompile(`(^|\s)(--enable|-E|--disable|-D|--enable-only|--config|-c|--no-config|--new|--new-from-rev|--new-from-patch|--new-from-merge-base|--max-issues-per-linter|--max-same-issues|--fix)(\s|=|$)`)
)

// checkLintConfig reads .golangci.yml and the linters job of ci.yml.
func checkLintConfig(files map[string]string) []Violation {
	var violations []Violation
	at := func(rel, detail string) { violations = append(violations, Violation{rel, 0, detail}) }
	text := uncommented(files[lintConfig])

	if !strings.Contains(text, "\n  default: none\n") {
		at(lintConfig, "does not say `default: none`, so the set is whatever the tool ships with and moves with its releases")
	}
	enabled := yamlList(text, "enable:")
	if len(enabled) == 0 {
		at(lintConfig, "enables no linter - this guard would pass without checking anything")
	}
	for _, name := range lintersEnabled {
		if !slices.Contains(enabled, name) {
			at(lintConfig, name+" is written down here and no longer enabled - dropping a linter is the owner's decision")
		}
	}
	for _, name := range enabled {
		if !slices.Contains(lintersEnabled, name) {
			at(lintConfig, name+" is enabled and not written down in lintersEnabled, which is what stops the next change from removing it")
		}
		if slices.Contains(lintersKeptOut, name) {
			at(lintConfig, name+" is enabled and runs elsewhere already - here it would answer a different question under the same name")
		}
	}
	for _, rule := range yamlList(text, "excludes:") {
		if !slices.Contains(gosecExcluded, rule) {
			at(lintConfig, "switches gosec "+rule+" off for the whole tree - a wrong finding gets //nolint and its reason at the line")
		}
	}
	for _, function := range yamlList(text, "exclude-functions:") {
		if !slices.Contains(errcheckExcluded, function) {
			at(lintConfig, "lets errcheck skip "+function+" everywhere - a wrong finding gets //nolint and its reason at the line")
		}
	}
	violations = append(violations, checkLintExclusions(text)...)
	for _, key := range []string{"max-issues-per-linter", "max-same-issues"} {
		if !strings.Contains(text, "\n  "+key+": 0\n") {
			at(lintConfig, key+" is not 0, so a run reports part of what it found and the rest comes back after the fix")
		}
	}

	job := uncommented(jobBlocks(files[ciWorkflow])["linters"])
	versions := map[string]bool{}
	verifies, runs := false, 0
	for _, line := range strings.Split(job, "\n") {
		i := strings.LastIndex(line, "golangci-lint")
		if i < 0 {
			continue
		}
		// What follows the tool's name: its version when the line pins one,
		// then the command and its switches.
		rest := line[i+len("golangci-lint"):]
		if v := lintVersion.FindString(rest); v != "" {
			versions[v[1:]] = true
			rest = rest[len(v):]
		}
		rest = strings.TrimSpace(strings.TrimLeft(rest, `"`))
		switch {
		case strings.HasPrefix(rest, "config verify"):
			verifies = true
		case strings.HasPrefix(rest, "run ") && strings.Contains(rest, "./..."):
			runs++
		}
		if o := lintOverride.FindStringSubmatch(rest); o != nil {
			at(ciWorkflow, "the linters job passes "+o[2]+", which replaces "+lintConfig+" in silence")
		}
	}
	if runs == 0 {
		at(ciWorkflow, "the linters job never runs `golangci-lint run ./...`, so the configuration is read and nothing is checked with it")
	}
	if runs < 2 || !windowsRun.MatchString(job) {
		at(ciWorkflow, "the linters job does not also run golangci-lint as Windows builds the tree, where the probes of "+
			"the registry, the certificate stores and the processes live")
	}
	if !verifies {
		at(ciWorkflow, "the linters job never runs `golangci-lint config verify` - a plain run ignores a key the schema refuses")
	}
	if len(versions) > 1 {
		var seen []string
		for v := range versions {
			seen = append(seen, v)
		}
		sort.Strings(seen)
		at(ciWorkflow, "the linters job pins different versions of golangci-lint ("+strings.Join(seen, ", ")+"), so one schema is verified and another is run")
	}
	return violations
}

// checkLintExclusions allows one exclusion rule - test files, for the linters
// in testRuleLinters - and no excluded paths. Everything else is a finding
// switched off for a whole file or more, where the decision belongs at the
// line.
func checkLintExclusions(text string) []Violation {
	var violations []Violation
	block, found := yamlBlock(text, "  exclusions:")
	if !found {
		return []Violation{{lintConfig, 0, "has no exclusions block, so the rule for test files is gone and the tests report " +
			"what a test reports through t"}}
	}
	if strings.Contains(block, "\n    paths:") {
		violations = append(violations, Violation{lintConfig, 0, "excludes whole paths, so everything under them goes unread"})
	}
	rules, _ := yamlBlock(block, "    rules:")
	for _, item := range strings.Split(rules, "\n      - ")[1:] {
		path, linters := "", ""
		for _, line := range strings.Split(item, "\n") {
			key, value, _ := strings.Cut(strings.TrimSpace(line), ":")
			switch key {
			case "path":
				path = strings.TrimSpace(value)
			case "linters":
				linters = strings.Trim(strings.TrimSpace(value), "[]")
			}
		}
		if path != "_test[.]go" {
			violations = append(violations, Violation{lintConfig, 0, "has an exclusion rule for " + path +
				" - a wrong finding gets //nolint and its reason at the line"})
			continue
		}
		for _, name := range strings.Split(linters, ",") {
			if name = strings.TrimSpace(name); !slices.Contains(testRuleLinters, name) {
				violations = append(violations, Violation{lintConfig, 0, "the rule for test files switches " + name + " off too"})
			}
		}
	}
	return violations
}

// yamlList reads the items under the first line that is exactly key, as text
// rather than through a YAML library: the file is ours and small, and a parser
// answers about a document rather than about the lines somebody edits.
func yamlList(text, key string) []string {
	var out []string
	inside := false
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if !inside {
			inside = trimmed == key
			continue
		}
		if trimmed == "" {
			continue
		}
		if !strings.HasPrefix(trimmed, "- ") {
			break
		}
		item := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
		if i := strings.Index(item, " #"); i >= 0 {
			item = strings.TrimSpace(item[:i])
		}
		out = append(out, strings.Trim(item, `"'`))
	}
	return out
}

// yamlBlock returns the lines under a line that is exactly header, up to the
// next line indented no deeper than it.
func yamlBlock(text, header string) (string, bool) {
	depth := len(header) - len(strings.TrimLeft(header, " "))
	var lines []string
	inside := false
	for _, line := range strings.Split(text, "\n") {
		if !inside {
			inside = line == header
			continue
		}
		if strings.TrimSpace(line) != "" && len(line)-len(strings.TrimLeft(line, " ")) <= depth {
			break
		}
		lines = append(lines, line)
	}
	return "\n" + strings.Join(lines, "\n"), inside
}
