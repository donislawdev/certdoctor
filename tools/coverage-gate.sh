#!/usr/bin/env bash
#
# Coverage gate. Reads the floors from tools/coverage-floor.txt, measures, and
# refuses a run where any package fell below its floor.
#
# WHY THIS IS A SCRIPT AND NOT A FEW LINES OF YAML. CI and a person at a
# terminal have to run the same check. A gate that exists only inside a
# workflow file is a gate the author of a change meets after pushing, which is
# the point at which it is most annoying and least useful.
#
# THREE FAILURES IT IS WRITTEN AGAINST, and each is a way a coverage gate looks
# like it works while checking nothing:
#
#   1. A NEW PACKAGE WITH NO FLOOR. Without the check below it would simply not
#      be measured, and the gate would cover less of the tree every month while
#      staying green. The layer guard reports a package outside its map for the
#      same reason.
#   2. A FLOOR FOR A PACKAGE THAT NO LONGER EXISTS. It protects nothing and
#      reads as protection - the same defect the write allowlist has a test for.
#   3. CACHED RESULTS. go test happily reports coverage from a previous run, so
#      a change that broke nothing yet ran nothing would pass. Hence -count=1.
#
# WHAT IT DOES NOT CHECK, said here rather than left to be assumed: whether any
# assertion was made about the statements that ran. That is the mutation
# register's question and this gate does not answer it.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
floors="$root/tools/coverage-floor.txt"

cd "$root"

declare -A floor_of
while read -r package want; do
  [ -z "${package:-}" ] && continue
  case "$package" in \#*) continue ;; esac
  floor_of["$package"]="$want"
done < <(sed 's/#.*//' "$floors")

# The measurement is captured before it is read, so that a toolchain that is
# not there can be told apart from a tree that is not covered.
#
# WHY THAT DISTINCTION IS WORTH THE EXTRA LINES. The first version piped go
# straight into the loop. Run from a shell where go was not on PATH it measured
# nothing, and then reported every package in the floor file as a stale floor -
# blaming the one file that was correct for the absence of the compiler. A check
# that misidentifies its own failure sends the reader to the wrong place, which
# is worse than a check that simply stops.
# WHY THE FAILURE IS FILTERED AND NOT JUST TAILED, MEASURED 2026-09-05. This
# used to print the last twenty lines and nothing else. On a red Windows run
# those twenty lines were filled entirely by packages that PASSED - go test
# prints them in package order, the failing one sorted early, and twenty
# successful lines pushed it out of view. The gate reported that it could not
# measure and then showed a screen of green, which sends the reader looking in
# the wrong place. That is the same failure mode the comment above describes:
# a check that misidentifies its own failure is worse than one that stops.
#
# AND WHY A FILTER WAS STILL NOT ENOUGH, MEASURED 2026-09-06 - OBS125. The
# filter looks for shapes it already knows: FAIL, --- FAIL, a panic, a line
# from a _test.go file. A package can fail in none of them - a harness giving
# up before any test runs, a TestMain exiting, a build failing after the
# compiler has finished printing - and then the only thing this gate says is
# the package's NAME. That happened: internal/adapter/probe came back red, the
# whole record was twenty-six lines, and not one of them said what went wrong.
# A filter is a bet that the failure has a shape somebody thought of first, and
# OBS17 is the standing note that this is not a bet that gets won.
#
# SO THE SECOND SECTION PRINTS A PACKAGE'S OWN OUTPUT IN FULL, AND ASKS PER
# PACKAGE. OBS125 named the narrower condition - "when no --- FAIL was found
# anywhere in the run" - and that condition has a hole: one package failing
# with a named test would hide a second one failing without. Asking it per
# package closes the hole and costs nothing on an ordinary red run, because a
# package that DID name a failing test prints nothing here.
#
# IT NEVER RE-RUNS ANYTHING, AND THAT IS THE OTHER HALF OF OBS125. The package
# that failed there passes on its own in 2.2 seconds, so a gate that reran it
# would report green and call the matter closed - retrying instead of looking.
# Everything printed comes out of the record this run already captured.
#
# The tail is kept as well, because a filter only finds what it knows to look
# for and a build failure can arrive in a shape none of these patterns matches.
report="$(go test -cover -count=1 ./... 2>&1)" || {
  echo "COULD NOT MEASURE: go test did not finish."
  echo "--- the packages that failed, and the assertions that failed in them:"
  printf '%s\n' "$report" | grep -E '^(FAIL|ok +[^ ]+ +\[|--- FAIL|# )|_test\.go:|panic:|\[build failed\]' || echo "  (nothing matched the filter - read on)"

  # A PACKAGE'S OWN OUTPUT IS EVERYTHING SINCE THE PREVIOUS PACKAGE FINISHED,
  # up to and including its FAIL line. go test writes exactly one terminal line
  # per package - "ok", "?" or "FAIL" - so those are the boundaries, and nothing
  # else about the format has to be understood or kept up to date.
  #
  # A BARE "FAIL" LINE IS NOT A BOUNDARY. go test prints one just before the
  # package's own FAIL line, so it belongs INSIDE the block, and requiring a
  # second field is what keeps it there.
  silent="$(printf '%s\n' "$report" | awk '
    $1 == "ok" || $1 == "?" { n = 0; named = 0; next }
    $1 == "FAIL" && NF >= 2 {
      if (!named) {
        print "  === " $2 " failed without naming a test, so all of its output follows:"
        for (i = 1; i <= n; i++) { print "      " buf[i] }
        print "      " $0
      }
      n = 0; named = 0; next
    }
    $1 == "---" && $2 == "FAIL:" { named = 1 }
    { n = n + 1; buf[n] = $0 }
  ')"
  if [ -n "$silent" ]; then
    echo "--- and in full, every package that failed while naming no test at all:"
    printf '%s\n' "$silent"
  fi

  echo "--- the last twenty lines, for anything neither section above caught:"
  printf '%s\n' "$report" | tail -20
  exit 1
}

declare -A measured
while read -r kind package rest; do
  case "$kind" in
    ok) percent="$(printf '%s' "$rest" | sed -n 's/.*coverage: \([0-9.]*\)% of statements.*/\1/p')"
        measured["$package"]="${percent:-0}" ;;
    '?') measured["$package"]="none" ;;
  esac
done < <(printf '%s\n' "$report")

if [ "${#measured[@]}" -eq 0 ]; then
  echo "COULD NOT MEASURE: go test produced no coverage lines at all."
  echo "  This is not a problem with the floors. Check that the Go toolchain is on PATH."
  printf '%s\n' "$report" | head -10
  exit 1
fi

problems=0

# Every package the module contains has to be named in the floor file.
while read -r package; do
  if [ -z "${floor_of[$package]+set}" ]; then
    echo "MISSING FLOOR: $package is not in tools/coverage-floor.txt."
    echo "  A package with no floor is not a package without a rule - it is a hole in this gate."
    problems=$((problems + 1))
  fi
done < <(go list ./...)

for package in "${!floor_of[@]}"; do
  want="${floor_of[$package]}"
  got="${measured[$package]-absent}"

  if [ "$got" = "absent" ]; then
    echo "STALE FLOOR: $package has a floor and is not in this module any more."
    echo "  A floor guarding nothing reads as protection. Remove the line."
    problems=$((problems + 1))
    continue
  fi

  if [ "$want" = "none" ]; then
    if [ "$got" != "none" ]; then
      echo "NOTE: $package is declared as having no tests and now reports ${got}%."
      echo "  Give it a real floor - the declaration is out of date in the good direction."
      problems=$((problems + 1))
    fi
    continue
  fi

  if [ "$got" = "none" ]; then
    echo "NO TESTS: $package has a floor of ${want}% and no test files at all."
    problems=$((problems + 1))
    continue
  fi

  if awk -v got="$got" -v want="$want" 'BEGIN { exit !(got < want) }'; then
    echo "BELOW FLOOR: $package is at ${got}%, floor is ${want}%."
    echo "  Lowering the floor to get past this is the owner's decision, not a way to get unblocked."
    problems=$((problems + 1))
  fi
done

if [ "$problems" -gt 0 ]; then
  echo
  echo "coverage gate: $problems problem(s)"
  exit 1
fi

echo "coverage gate: every package is at or above its floor"
