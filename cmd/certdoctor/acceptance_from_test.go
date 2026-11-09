//go:build acceptance

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/exitcode"
)

// TestTheShippedBinaryWritesASavedReportAgainWithoutRunning drives --from the
// way the window and a helpdesk will: a report saved with --json becomes a
// page, from a file and from standard input, the program ends with OK whatever
// the report found, and nothing but the page asked for is written.
func TestTheShippedBinaryWritesASavedReportAgainWithoutRunning(t *testing.T) {
	dir := t.TempDir()
	saved := filepath.Join(dir, "saved.json")
	run := startProgram(t, invocation{dir: dir}, aLoopbackTarget(t), "--json", "--out", saved)
	if run.code != exitcode.Diagnosis.Int() {
		t.Fatalf("the run that saves the report ended with %d: %s", run.code, run.stderr)
	}

	before := census(t, dir)
	page := filepath.Join(dir, "page.html")
	again := startProgram(t, invocation{dir: dir}, "--from", saved, "--format", "html", "--out", page)
	if again.code != exitcode.OK.Int() {
		t.Fatalf("--from ended with %d where a written report ends with 0: %s", again.code, again.stderr)
	}
	if again.stdout != "" {
		t.Errorf("--from with --out left %d bytes on standard output", len(again.stdout))
	}
	written, err := os.ReadFile(page)
	if err != nil || !strings.HasPrefix(string(written), "<!DOCTYPE html>") {
		t.Fatalf("no page at %s: %v", page, err)
	}
	if extra := appeared(before, census(t, dir)); len(extra) != 1 || extra[0] != "page.html" {
		t.Errorf("--from left %v behind, where the page alone was asked for", extra)
	}

	piped := pipeInto(t, saved, "--from", "-", "--format", "md")
	if piped.code != exitcode.OK.Int() || !strings.Contains(piped.stdout, "127.0.0.1") {
		t.Errorf("--from - ended with %d and wrote %q: %s", piped.code, piped.stdout, piped.stderr)
	}

	missing := startProgram(t, invocation{dir: dir}, "--from", filepath.Join(dir, "missing.json"))
	if missing.code != exitcode.Config.Int() || missing.stdout != "" {
		t.Errorf("a missing file ended with %d and wrote %q: %s", missing.code, missing.stdout, missing.stderr)
	}
}

// pipeInto runs the binary with a file on its standard input, which is how
// the window hands it the report it drew.
func pipeInto(t *testing.T, input string, args ...string) result {
	t.Helper()
	in, err := os.Open(input)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	cmd := exec.Command(theBinary(t), args...)
	cmd.Env = minimalEnvironment()
	cmd.Stdin = in
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	code := 0
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("the program could not be started at all: %v", err)
		}
		code = exit.ExitCode()
	}
	return result{stdout: stdout.String(), stderr: stderr.String(), code: code}
}
