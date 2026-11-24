package guard

import (
	"regexp"
	"strings"
	"testing"
)

const staticcheckConfig = "staticcheck.conf"

// TestStaticcheckRunsTheChecksItsFileNames holds the staticcheck job to the
// file that says which checks run. The job ran for months as -checks=SA,U,
// which names no check at all - a family is SA*, and a bare SA matches nothing
// - so it passed while checking nothing, and every run looked the same as a
// clean one. Two things keep that from coming back: no check list on the
// command line, where it silently replaces the file, and a file that keeps
// staticcheck's own default set with nothing taken out of it. Taking a check
// out is a decision with a reason, made at the line it is about with
// lint:ignore, not a hole in the list.
func TestStaticcheckRunsTheChecksItsFileNames(t *testing.T) {
	root := moduleRoot(t)
	requireNoViolations(t, checkStaticcheck(map[string]string{
		ciWorkflow:        readRel(t, root, ciWorkflow),
		staticcheckConfig: readRel(t, root, staticcheckConfig),
	}), "the staticcheck checks")
}

func TestTheStaticcheckGuardCanFail(t *testing.T) {
	requireViolation(t, checkStaticcheck(map[string]string{
		ciWorkflow:        "on: push\njobs:\n  static-analysis:\n    steps:\n      - run: go run honnef.co/go/tools/cmd/staticcheck@2026.2.2 -checks=SA,U ./...\n",
		staticcheckConfig: "checks = [\"inherit\", \"-ST1005\"]\n",
	}), "passes -checks")
	requireViolation(t, checkStaticcheck(map[string]string{
		ciWorkflow:        "on: push\njobs:\n  static-analysis:\n    steps:\n      - run: go run honnef.co/go/tools/cmd/staticcheck@2026.2.2 ./...\n",
		staticcheckConfig: "checks = [\"inherit\", \"-ST1005\"]\n",
	}), "takes \"-ST1005\" out")
	requireViolation(t, checkStaticcheck(map[string]string{
		ciWorkflow:        "on: push\njobs:\n  static-analysis:\n    steps:\n      - run: echo nothing\n",
		staticcheckConfig: "checks = [\"SA\"]\n",
	}), "never runs staticcheck")
	requireViolation(t, checkStaticcheck(map[string]string{
		ciWorkflow:        "on: push\njobs:\n  static-analysis:\n    steps:\n      - run: go run honnef.co/go/tools/cmd/staticcheck@2026.2.2 ./...\n",
		staticcheckConfig: "checks = [\"SA\"]\n",
	}), "does not keep the default set")
}

var (
	staticcheckRun    = regexp.MustCompile(`honnef\.co/go/tools/cmd/staticcheck@\S+(.*)`)
	staticcheckChecks = regexp.MustCompile(`(?m)^checks\s*=\s*\[(.*)\]`)
	quotedEntry       = regexp.MustCompile(`"([^"]*)"`)
)

// checkStaticcheck reads the staticcheck job of ci.yml and staticcheck.conf.
func checkStaticcheck(files map[string]string) []Violation {
	var violations []Violation
	at := func(rel, detail string) { violations = append(violations, Violation{rel, 0, detail}) }

	var runs [][]string
	for _, line := range strings.Split(jobBlocks(files[ciWorkflow])["static-analysis"], "\n") {
		if run := staticcheckRun.FindStringSubmatch(line); run != nil && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			runs = append(runs, run)
		}
	}
	if len(runs) == 0 {
		at(ciWorkflow, "the static-analysis job never runs staticcheck")
	}
	for _, run := range runs {
		if strings.Contains(run[1], "-checks") || strings.Contains(run[1], "-conf") {
			at(ciWorkflow, "the static-analysis job passes -checks or another configuration, which replaces "+staticcheckConfig+" in silence")
		}
	}

	list := staticcheckChecks.FindStringSubmatch(files[staticcheckConfig])
	if list == nil {
		at(staticcheckConfig, "has no checks line, so what runs is whatever the tool decides")
		return violations
	}
	inherits := false
	for _, entry := range quotedEntry.FindAllStringSubmatch(list[1], -1) {
		switch {
		case entry[1] == "inherit":
			inherits = true
		case strings.HasPrefix(entry[1], "-"):
			at(staticcheckConfig, "takes \""+entry[1]+"\" out of the set - a finding that is wrong gets lint:ignore and its reason at the line")
		}
	}
	if !inherits {
		at(staticcheckConfig, "does not keep the default set (\"inherit\"), so the job runs only what is named, and a name without a star matches nothing")
	}
	return violations
}
