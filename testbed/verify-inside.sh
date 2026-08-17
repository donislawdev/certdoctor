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

  # L3 CONNECTS TO WHAT L1 FOUND, and this bench is the only place where the
  # addresses are known in advance: every one of them is from a documentation
  # range, so nothing routes and the outcome cannot depend on whose network this
  # runs on. Only the STATUS and the SHAPE of the failure are checked - which of
  # the two honest failures a machine produces is a property of that machine.
  local want_l3 want_outcome got_l3 got_outcome
  want_l3="$(value "$file" l3_status)"
  want_outcome="$(value "$file" l3_outcome)"
  got_l3="$(echo "$document" | jq -r '.layers[] | select(.id=="L3") | .status')"
  got_outcome="$(echo "$document" | jq -r '[.layers[] | select(.id=="L3") | .findings[]? | .tcp_connect.outcome] | first // ""')"

  if [ -n "$want_l3" ] && [ "$got_l3" != "$want_l3" ]; then
    say "L3 says $got_l3, expected $want_l3"
  fi
  if [ -n "$want_outcome" ] && ! echo "$want_outcome" | tr '|' '
' | grep -qx "$got_outcome"; then
    say "the first connection came out as $got_outcome, expected one of $want_outcome"
  fi

  local sentence
  sentence="$(echo "$document" | jq -r '.layers[] | select(.id=="L1") | .detail')"
  echo "    certdoctor: L1 $got_status / $got_divergence | L3 $got_l3 / ${got_outcome:-no rows} | exit $code"
  echo "    sentence:   $sentence"

  if [ "$got_status" = "$want_status" ]; then
    passed=$((passed + 1))
  fi
}

# THE BENCH IS ASKED WHETHER IT IS SERVING THE CONFIGURATION IN THIS WORKING
# TREE, BEFORE ANYTHING ELSE - and this check exists because the trap it catches
# was walked into on 2026-08-17, while adding the partner zone.
#
# The Corefile is a bind mount, so editing it changes the file the container sees
# immediately. CoreDNS reads it ONCE, at startup. "docker compose up -d" then
# reports every container started, healthy and green, while the bench answers
# from the previous configuration - a run that did less than it promised and
# looked complete, which is inviolable rule 1 from the wrong side.
#
# It is checked on partner.test because that zone is the newest, so it is the one
# a stale process is most likely to be missing.
bench_serves_this_tree() {
  local got
  got="$(dig +short "@172.28.0.53" partner.test A 2>/dev/null | head -1)"
  if [ "$got" = "172.28.0.80" ]; then
    return 0
  fi
  echo "testbed: THE BENCH IS NOT SERVING THE CONFIGURATION IN THIS WORKING TREE."
  echo "testbed: partner.test answered '${got:-nothing}', and the zone file says 172.28.0.80."
  echo "testbed: CoreDNS reads the Corefile once, at startup, and a bind mount does not"
  echo "testbed: restart it - so an edited zone is invisible until the container is."
  echo "testbed: fix:  docker compose -f testbed/compose.yml restart dns"
  return 1
}

if ! bench_serves_this_tree; then
  exit 1
fi

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

# WHAT THIS RUN DID NOT ASSESS, SAID OUT LOUD RATHER THAN LEFT AS SILENCE.
#
# P4b put two benches in place - a server that withholds its intermediate, and a
# proxy that re-signs traffic - and NOTHING HERE CAN JUDGE THEM, because the
# layer that would (L4) does not exist until P6. Their expectations are written
# down already, which is the whole point of building the bench first, but an
# expectation nobody checks is not coverage.
#
# The list builds itself: any expectation file naming l4_status is by definition
# beyond what this script can ask today. So it cannot go stale by somebody adding
# a file and forgetting this block, and it empties itself when L4 arrives.
deferred=0
for file in "$expected"/*.txt; do
  [ -e "$file" ] || continue
  if [ -n "$(value "$file" l4_status)" ]; then
    if [ "$deferred" -eq 0 ]; then
      echo "testbed: NOT ASSESSED HERE - benches whose reader does not exist yet:"
    fi
    deferred=$((deferred + 1))
    echo "    $(basename "$file" .txt)  ->  $(value "$file" target)"
    echo "        expects L4 $(value "$file" l4_status), and there is no L4 yet. Waiting for P6."
  fi
done
if [ "$deferred" -gt 0 ]; then
  echo "testbed: those $deferred expectation(s) were written from the bench's configuration"
  echo "testbed: BEFORE anything could read them, which is the only order that makes them"
  echo "testbed: an oracle rather than a transcript. Verify them by hand with openssl."
  echo
fi

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
