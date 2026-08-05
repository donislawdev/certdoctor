//go:build acceptance

// This file drives the REAL BINARY, as a person at a terminal does.
//
// WHY IT EXISTS, AND WHY THE REST OF THIS PACKAGE'S TESTS DO NOT COVER IT.
// Every other test here runs IN PROCESS WITH THE OUTSIDE WORLD REPLACED: the
// harness swaps the disk for a map, the clock and the privilege level arrive as
// parameters, and there is no terminal. That is the right shape for testing
// units and the wrong shape for answering "does this program work". A binary
// that never starts, writes a file nobody asked for, or emits colour into a
// pipe passes every one of them.
//
// The evidence that this gap is real rather than tidy-minded: three findings in
// this project came from running the binary and from nothing else - the
// effective-user-id path executed for the first time ever, a device given to
// --out answering with a message about a temporary file nobody named, and a
// filesystem keeping the first spelling of a name. None of them were visible
// from a test.
//
// WHAT THIS SUITE DOES NOT CHECK, said here rather than assumed. It cannot say
// whether a diagnosis is TRUE. It says the program behaves like a program -
// codes, channels, files, repeatability. Whether the verdict is right is the
// oracle's question and needs the testbed, which is a separate piece of work
// with its own document.
//
// IT IS BEHIND A BUILD TAG so that an ordinary `go test ./...` does not rebuild
// the binary on every run. It is not optional for all that: it runs at the
// boundary of a piece of work, and every check in it blocks.
//
//	bash tools/acceptance.sh
package main

import (
	"errors"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// binaryVariable names the environment variable carrying the program under
// test.
const binaryVariable = "CERTDOCTOR_ACCEPTANCE_BINARY"

// theBinary is the program these checks drive.
//
// IT IS BUILT BY THE RUNNER AND NOT HERE, and the reason is a guard rather than
// taste. Building it here means creating and removing a temporary directory
// from TestMain, which has no *testing.T and therefore no t.TempDir - and the
// write guard refuses exactly that, because a test suite is the likeliest
// source of litter in somebody's working tree. Its allowlist is one file long
// and pinned by a test, so widening it for this would cost more than it buys.
//
// The split turns out to be the better shape anyway: the checks stop caring
// where the binary came from, so the same suite can be pointed at a RELEASE
// ARTEFACT rather than only at a fresh build. That is the version a user
// actually gets.
func theBinary(t *testing.T) string {
	t.Helper()
	path, set := os.LookupEnv(binaryVariable)
	if !set || path == "" {
		t.Fatalf("%s is not set, so there is no program to drive. Run this through tools/acceptance.sh, "+
			"which builds the binary and points this at it.", binaryVariable)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("%s names %s, which cannot be read: %v", binaryVariable, path, err)
	}
	return path
}

// invocation is one way of starting the program.
type invocation struct {
	// dir is the working directory. Empty means this package's own directory.
	dir string
	// env is added to the minimal environment below.
	env []string
}

// result is everything a caller of a program can observe.
type result struct {
	stdout string
	stderr string
	code   int
}

// minimalEnvironment is what the program is started with unless a test adds to
// it.
//
// IT IS MINIMAL ON PURPOSE AND THAT IS NOT TIDINESS. L0 reads twenty-three
// environment variables and puts them in the report, so a developer with
// HTTPS_PROXY set would get different output from one without - and the
// repeatability check below would then be measuring the machine rather than the
// program. Only what is needed to start a process and resolve a name stays.
func minimalEnvironment() []string {
	keep := []string{"PATH", "SystemRoot", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE", "WINDIR"}
	var env []string
	for _, name := range keep {
		if value, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+value)
		}
	}
	return env
}

// startProgram runs the binary and returns everything observable about it.
func startProgram(t *testing.T, in invocation, args ...string) result {
	t.Helper()

	cmd := exec.Command(theBinary(t), args...)
	cmd.Dir = in.dir
	cmd.Env = append(minimalEnvironment(), in.env...)

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("the program could not be started at all: %v", err)
		}
		code = exit.ExitCode()
	}
	return result{stdout: stdout.String(), stderr: stderr.String(), code: code}
}

// runProgram is startProgram in the package's own directory, which is where most
// checks want to be.
func runProgram(t *testing.T, args ...string) result {
	t.Helper()
	return startProgram(t, invocation{}, args...)
}

// census lists every file under a directory, with its size.
//
// It is how "this program writes nothing nobody asked for" stops being a
// sentence in a README. The write guard reads DECLARED IMPORTS, so it cannot
// see a write through a handle or through a subprocess - this watches the disk
// instead of the source.
func census(t *testing.T, dir string) map[string]int64 {
	t.Helper()
	seen := map[string]int64{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		seen[filepath.ToSlash(rel)] = info.Size()
		return nil
	})
	if err != nil {
		t.Fatalf("taking a census of %s: %v", dir, err)
	}
	return seen
}

// appeared names the files present in after and not in before.
func appeared(before, after map[string]int64) []string {
	var names []string
	for name := range after {
		if _, was := before[name]; !was {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// theInternetIsReachable answers whether the checks that need a network can say
// anything at all.
//
// A CHECK THAT FAILS BECAUSE SOMEBODY IS ON A TRAIN TEACHES THAT RED MEANS
// NOTHING, which costs more than the check is worth. So the network subset
// skips - and it skips LOUDLY, naming what went unchecked, because a silent
// skip is the shape this project forbids everywhere else.
func theInternetIsReachable() bool {
	conn, err := net.DialTimeout("tcp", "1.1.1.1:53", 3*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func needsTheInternet(t *testing.T) {
	t.Helper()
	if !theInternetIsReachable() {
		t.Skip("NOT CHECKED: this machine has no route to the internet, so nothing was established about how " +
			"the binary behaves against a real name. This is a skip, not a pass.")
	}
}
