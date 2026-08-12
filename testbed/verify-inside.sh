#!/usr/bin/env bash
#
# The comparison itself, run inside a container whose resolv.conf names the
# bench. Started by verify.sh, which builds the binary and mounts this file.
#
# EVERY EXPECTATION IT CHECKS WAS WRITTEN BEFORE THE FIRST RUN. Nothing here
# reads certdoctor's output and calls it correct - it reads expected/ and asks
# whether certdoctor agrees. A verdict written after a run is a transcript.
set -o pipefail

binary=/w/certdoctor
expected=/w/expected

passed=0
failed=0
notes=0

# value pulls one key out of an expectation file. Lines are key=value and
# anything starting with # is prose explaining WHY, which is most of each file.
value() {
  grep -E "^$2=" "$1" 2>/dev/null | head -1 | cut -d= -f2-
}

# say records a disagreement. It never stops the run: a bench that reports the
# first difference and quits hides the other five, and somebody then fixes one
# thing per round trip. Each scenario redefines it, because a scenario with a
# known unsettled gap counts its differences differently - see check_scenario.
say() {
  echo "    DIFFERS: $1"
  failed=$((failed + 1))
}

check_scenario() {
  local name="$1"
  local file="$expected/$name.txt"
  local target want_status want_divergence forbidden want_exit pending

  target="$(value "$file" target)"
  want_status="$(value "$file" l1_status)"
  want_divergence="$(value "$file" divergence)"
  forbidden="$(value "$file" divergence_forbidden)"
  want_exit="$(value "$file" exit_code)"
  pending="$(value "$file" pending_decision)"

  # A scenario carrying pending_decision has a KNOWN gap between what the
  # contract asks for and what the code does, waiting on the owner. Its
  # differences are printed in full and counted separately - not hidden, and not
  # reddening a gate that would then be red every run.
  if [ -n "$pending" ]; then
    say() {
      echo "    UNSETTLED ($pending): $1"
      notes=$((notes + 1))
    }
  else
    say() {
      echo "    DIFFERS: $1"
      failed=$((failed + 1))
    }
  fi

  echo "  scenario $name  ->  $target"

  # THE REFERENCE TOOL RUNS FIRST AND ITS ANSWER IS PRINTED WHATEVER HAPPENS.
  # This is the half of the oracle that does not share a line of code with the
  # thing under test. If dig and certdoctor disagree, the bench itself is the
  # first suspect - and that is worth knowing before reading anything below.
  local host rcode_a rcode_aaaa
  host="$(echo "$target" | sed -e 's|^https\{0,1\}://||' -e 's|/.*$||')"
  rcode_a="$(dig +noall +comments "@172.28.0.53" "$host" A 2>/dev/null | grep -o 'status: [A-Z]*' | head -1 | cut -d' ' -f2)"
  rcode_aaaa="$(dig +noall +comments "@172.28.0.53" "$host" AAAA 2>/dev/null | grep -o 'status: [A-Z]*' | head -1 | cut -d' ' -f2)"
  echo "    dig says: A=$rcode_a AAAA=$rcode_aaaa"

  local want_a want_aaaa
  want_a="$(value "$file" direct_a)"
  want_aaaa="$(value "$file" direct_aaaa)"
  # NODATA is not a status dig prints - it is NOERROR with an empty answer - so
  # the bench's own claim is checked in the terms dig actually uses.
  [ "$want_a" = "NODATA" ] && want_a=NOERROR
  [ "$want_aaaa" = "NODATA" ] && want_aaaa=NOERROR
  if [ -n "$rcode_a" ] && [ "$rcode_a" != "$want_a" ]; then
    say "the bench itself answers $rcode_a for $host A, and expected/ says $want_a"
  fi
  if [ -n "$rcode_aaaa" ] && [ "$rcode_aaaa" != "$want_aaaa" ]; then
    say "the bench itself answers $rcode_aaaa for $host AAAA, and expected/ says $want_aaaa"
  fi

  local document code
  document="$("$binary" "$target" --json 2>/dev/null)"
  code=$?

  if [ -z "$document" ]; then
    say "certdoctor produced no document at all"
    return
  fi

  local got_status got_divergence
  got_status="$(echo "$document" | jq -r '.layers[] | select(.id=="L1") | .status')"
  got_divergence="$(echo "$document" | jq -r '[.layers[] | select(.id=="L1") | .findings[]? | .name_resolution | select(.divergence != null) | .divergence] | first // "none"')"

  if [ "$got_status" != "$want_status" ]; then
    say "L1 says $got_status, expected $want_status"
  fi

  # A pipe means the expectation names more than one acceptable class, and the
  # file says why. That is not vagueness: pinning one of them would make this
  # fail on a working machine with different IPv6 support.
  if ! echo "$want_divergence" | tr '|' '\n' | grep -qx "$got_divergence"; then
    say "the two views were classified as $got_divergence, expected one of $want_divergence"
  fi

  # The stronger half of the expectation, and the half that survives a rewrite of
  # the classifier: some classes must be impossible here whatever else changes.
  if [ -n "$forbidden" ]; then
    if echo "$forbidden" | tr ',' '\n' | grep -qx "$got_divergence"; then
      say "the class $got_divergence is one this scenario can never legitimately produce"
    fi
  fi

  if [ "$code" != "$want_exit" ]; then
    say "the run ended with $code, expected $want_exit"
  fi

  local sentence
  sentence="$(echo "$document" | jq -r '.layers[] | select(.id=="L1") | .detail')"
  echo "    certdoctor: $got_status / $got_divergence / exit $code"
  echo "    sentence:   $sentence"

  if [ "$got_status" = "$want_status" ]; then
    passed=$((passed + 1))
  fi
}

echo "testbed: asking the bench, then asking certdoctor, then comparing"
echo

check_scenario only4
echo
check_scenario dual
echo
check_scenario nope
echo
check_scenario servfail
echo

# THE HOSTS ENTRY GOES IN HERE RATHER THAN IN THE ZONE, because that is the one
# source the two views cannot share: certdoctor's own view never reads a hosts
# file under any configuration, and the platform reads it first. It is also the
# only way to make the views disjoint - a second resolver would be folded into
# the direct view's union instead (ADR31).
echo "198.51.100.30 split.ok.test" >> /etc/hosts
check_scenario split

echo
echo "testbed: $passed agreed, $failed differed, $notes noted"

if [ "$failed" -gt 0 ]; then
  echo "testbed: a difference is INFORMATION, not a failure of this bench. It means"
  echo "testbed: either the product is wrong or our understanding of the scenario is,"
  echo "testbed: and both are worth finding before a release."
  exit 1
fi

if [ "$notes" -gt 0 ]; then
  echo "testbed: certdoctor agrees with the verdicts written before it ever ran here,"
  echo "testbed: EXCEPT for $notes point(s) marked UNSETTLED above, which are waiting on a"
  echo "testbed: decision rather than on a fix. Read them - a green line underneath a"
  echo "testbed: known gap is exactly the shape this project is built against."
  exit 0
fi

echo "testbed: certdoctor agrees with verdicts written before it ever ran here."
