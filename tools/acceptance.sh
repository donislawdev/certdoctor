#!/usr/bin/env bash
#
# Acceptance suite. Builds the real binary and drives it the way a person at a
# terminal does, then refuses a run where anything it checked went wrong.
#
# WHY THIS EXISTS WHEN THERE ARE ALREADY TESTS. Every other test of the command
# line runs IN PROCESS WITH THE OUTSIDE WORLD REPLACED - the disk is a map, the
# clock and the privilege level arrive as parameters, and there is no terminal.
# That is the right shape for testing units and it cannot answer "does this
# program work". A binary that never starts, writes a file nobody asked for, or
# sends colour into a pipe passes all of them.
#
# The gap is measured rather than suspected: three findings in this project came
# from running the binary and from nothing else. The effective user id path
# executed for the first time in the project's life. A device given to --out
# answered with a message about a temporary file the user had never named. A
# filesystem kept the first spelling of a name. None were visible from a test.
#
# WHY A SCRIPT AND NOT A LINE OF YAML, the same reason the coverage gate is one:
# CI and a person at a terminal have to run the same check. A gate living only
# inside a workflow file is one the author of a change meets after pushing.
#
# WHY IT PRINTS THE SKIPS. go test hides them without -v, and a check that
# quietly did not run is the failure this whole suite is built against. Every
# skip is a sentence saying what went unestablished.
#
# WHAT IT DOES NOT CHECK, said here rather than left to be assumed: whether a
# diagnosis is TRUE. It establishes that the program behaves like a program -
# codes, channels, files, repeatability. Whether the verdict is right is the
# oracle's question, it needs the testbed, and it is a separate piece of work.

set -o pipefail

package="./cmd/certdoctor/"
pattern='^TestTheShippedBinary|^TestTheFileCensus'

# THE BUILD HAPPENS HERE RATHER THAN INSIDE THE SUITE, and a guard is the reason.
# Doing it from TestMain means creating and removing a temporary directory with
# no *testing.T in reach, and the write guard refuses that - a test suite is the
# likeliest source of litter in somebody's working tree, and its allowlist is one
# file long and pinned by a test.
#
# The split is the better shape anyway. The suite now takes a PATH, so the same
# checks can be pointed at a release artefact instead of a fresh build - which is
# the binary a user actually gets, and the only one whose behaviour is a promise.
workspace="$(mktemp -d)"
trap 'rm -rf "$workspace"' EXIT

binary="$workspace/certdoctor"
case "$(go env GOOS)" in windows) binary="$binary.exe";; esac

echo "acceptance: building the binary"
if ! go build -o "$binary" ./cmd/certdoctor/; then
  echo "acceptance: the binary would not build, so nothing about it could be established."
  exit 1
fi

echo "acceptance: driving it the way a person at a terminal does"

# -count=1 because go test will happily report a cached result, and a cached
# pass would mean the binary in front of us was never actually run.
output="$(CERTDOCTOR_ACCEPTANCE_BINARY="$binary" \
  go test -tags acceptance -count=1 -v -run "$pattern" "$package" 2>&1)"
status=$?

echo "$output" | grep -E '^(=== RUN|--- (PASS|FAIL|SKIP)|    [a-z_]+\.go:)' || true

passed=$(echo "$output" | grep -c -- '--- PASS' || true)
failed=$(echo "$output" | grep -c -- '--- FAIL' || true)
skipped=$(echo "$output" | grep -c -- '--- SKIP' || true)

echo
echo "acceptance: $passed passed, $failed failed, $skipped skipped"

# A suite that ran nothing is not a suite that passed. This is the same failure
# the mutation register found in a byte-comparison guard: two empty results
# compare equal, and the check reports success having established nothing.
#
# AND THE WHOLE OUTPUT GOES OUT WITH IT, MEASURED 2026-09-06 - OBS120, OBS125.
# The grep above prints only the shapes a RUN produces: === RUN, --- PASS, a
# line from a .go file. A package that does not COMPILE produces none of them,
# so this branch used to print one sentence, and that sentence named the build
# tag and the run pattern - neither of which was the cause. Measured: a helper
# whose name collided with one in the tagged file left the ordinary
# "go test ./cmd/certdoctor/" GREEN, because that run does not compile the
# tagged file at all, and lit four blocking checks of which this was one. Every
# one of them described its own symptom and not one named the redeclaration.
#
# A FILTER IS A BET THAT SOMEBODY GUESSED THE SHAPE OF THE FAILURE FIRST, and
# OBS17 is the standing note that this bet is not won. So on this path there is
# no filter at all.
if [ "$passed" -eq 0 ] && [ "$failed" -eq 0 ]; then
  echo "--- everything go test said, unfiltered:"
  printf '%s\n' "$output"
  echo
  echo "acceptance: NOTHING RAN. That is a failure, not a pass."
  echo "  This suite compiles behind a build tag, so a package that will not COMPILE"
  echo "  looks from here exactly like a run pattern that matched nothing. Read the"
  echo "  lines above before reaching for the tag or the pattern."
  exit 1
fi

if [ "$skipped" -gt 0 ]; then
  echo "acceptance: the skips above are things NOBODY CHECKED. Read them."
fi

if [ $status -ne 0 ]; then
  echo "acceptance: the shipped binary does not behave as promised."
  exit 1
fi

echo "acceptance: the shipped binary behaves as promised, for everything listed above."
