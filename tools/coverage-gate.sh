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

# The package list is captured once, and its failure stops the gate.
#
# IT USED TO BE READ THROUGH A PROCESS SUBSTITUTION, and bash ignores the exit
# status of one. A go list that failed would have fed the loop below nothing,
# no package would have been reported as missing a floor, and the gate would
# have carried on as if that check had run. It also feeds the table at the end
# and gives that table its order, which is go list's own and the same on every
# run.
packages="$(go list ./...)" || {
  echo "COULD NOT LIST the module's packages: go list did not finish."
  echo "  Without that list no package can be checked for a missing floor."
  exit 1
}

problems=0

# Every package the module contains has to be named in the floor file.
while read -r package; do
  [ -z "$package" ] && continue
  if [ -z "${floor_of[$package]+set}" ]; then
    echo "MISSING FLOOR: $package is not in tools/coverage-floor.txt."
    echo "  A package with no floor is not a package without a rule - it is a hole in this gate."
    problems=$((problems + 1))
  fi
done <<< "$packages"

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

verdict=0
if [ "$problems" -gt 0 ]; then
  echo
  echo "coverage gate: $problems problem(s)"
  verdict=1
else
  echo "coverage gate: every package is at or above its floor"
fi

# EVERY PACKAGE'S NUMBER IS PRINTED, ON GREEN TOO - OBS161, 2026-10-19. Until
# then a green run said one line and nothing else, and a floor can only be
# raised from a measurement. The one taken on the author's machine is not
# enough: OBS100 is a floor that held on one platform and not on the other, and
# coverage-floor.txt has a paragraph waiting for a number from a Windows runner
# that this gate never printed. A floor is now raised from a CI log, as the
# lower of the platforms that run this gate.
#
# THE TABLE COMES AFTER THE VERDICT, NEVER BEFORE THE PROBLEMS, and the order is
# the point. The wrappers that run this gate locally show the first twenty-five
# lines of a red run. A table in front would push the BELOW FLOOR line out of
# that window - the same failure, measured 2026-09-05, that the comment at the
# top of this file describes: a screen of packages that passed, and the one
# that did not, out of view.
#
# NO SORT IS CALLED, and the reason is the PATH, measured 2026-10-19 under Git
# Bash on Windows: /usr/bin/sort comes first and the system's own sort.exe is
# right behind it. The gate would be depending on that order for nothing,
# because go list already prints the packages in the same order every time.
toolchain="$(go version 2>&1)" || toolchain="an unknown toolchain"
echo
echo "coverage per package, measured with ${toolchain#go version }:"
printf '  %8s  %6s  %7s  %s\n' measured floor margin package
while read -r package; do
  [ -z "$package" ] && continue
  printf '%s %s %s\n' "$package" "${measured[$package]-absent}" "${floor_of[$package]-missing}"
done <<< "$packages" | awk '
  { margin = "-" }
  $2 ~ /^[0-9.]+$/ && $3 ~ /^[0-9.]+$/ { margin = sprintf("%+.1f", $2 - $3) }
  { printf "  %8s  %6s  %7s  %s\n", $2, $3, margin, $1 }
'

exit "$verdict"
