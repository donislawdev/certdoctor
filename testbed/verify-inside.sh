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

# check_handshake asks the chain bench and compares against what expected/ says
# about L4.
#
# IT IS A SEPARATE FUNCTION BECAUSE THE SUBJECT IS DIFFERENT, not because the
# code would not fit. In check_scenario the subject is a name and dig is the
# independent witness; here the subject is a certificate chain and openssl is.
# Folding them together would mean one function whose every line asked "which
# kind am I".
check_handshake() {
  local name="$1"
  local file="$expected/$name.txt"
  local target want_l4 want_certs

  target="$(value "$file" target)"
  want_l4="$(value "$file" l4_status)"
  want_certs="$(value "$file" chain_certs_presented)"

  say() {
    echo "    DIFFERS: $1"
    failed=$((failed + 1))
  }

  echo "  scenario $name  ->  $target"

  local host
  host="$(echo "$target" | sed -e 's|^https\{0,1\}://||' -e 's|/.*$||')"

  # THE INDEPENDENT WITNESS FIRST AND ITS ANSWER IS PRINTED WHATEVER HAPPENS.
  # openssl shares no line of code with certdoctor, so if the two disagree about
  # how many certificates are on the wire, THE BENCH is the first suspect - which
  # is worth knowing before reading anything below.
  local presented
  if command -v openssl >/dev/null 2>&1; then
    presented="$(echo | openssl s_client -connect "$host:443" -servername "$host" -showcerts 2>/dev/null |
      grep -c 'BEGIN CERTIFICATE')"
    echo "    openssl says: $presented certificate(s) on the wire"
    if [ -n "$want_certs" ] && [ "$presented" != "$want_certs" ]; then
      say "the bench itself presents $presented certificate(s), and expected/ says $want_certs"
    fi
  else
    # NOT SILENCE. Half an oracle has to say which half is missing, or the run
    # reads as though both witnesses agreed.
    echo "    NOT CHECKED: this image has no openssl, so the bench's own answer was not established."
    notes=$((notes + 1))
  fi

  local document code
  document="$("$binary" "$target" --json 2>/dev/null)"
  code=$?
  if [ -z "$document" ]; then
    say "certdoctor produced no document at all"
    return
  fi

  local got_l4 got_certs got_complete sentence
  got_l4="$(echo "$document" | jq -r '.layers[] | select(.id=="L4") | .status')"
  got_certs="$(echo "$document" | jq -r '[.layers[] | select(.id=="L4") | .findings[]? | .tls_handshake.chain | select(. != null) | length] | first // 0')"
  # tostring RATHER THAN THE // OPERATOR, AND THIS COST A RUN. jq treats false and
  # null alike as "empty", so `first // "none"` turns a chain_complete of FALSE -
  # the exact answer this scenario exists to produce - into "none", and the check
  # below then reports a difference that is not there. The assertion got a correct
  # answer to a different question, which is the shape OBS56 records.
  got_complete="$(echo "$document" | jq -r '[.layers[] | select(.id=="L4") | .findings[]? | .tls_handshake | select(.chain != null) | .chain_complete] | first | tostring')"
  sentence="$(echo "$document" | jq -r '.layers[] | select(.id=="L4") | .detail')"

  echo "    certdoctor: L4 $got_l4 / $got_certs certificate(s) / chain_complete $got_complete | exit $code"
  echo "    sentence:   $sentence"

  if [ -n "$want_l4" ] && [ "$got_l4" != "$want_l4" ]; then
    say "L4 says $got_l4, expected $want_l4"
  fi
  if [ -n "$want_certs" ] && [ "$got_certs" != "$want_certs" ]; then
    say "certdoctor reports $got_certs certificate(s) and the bench puts $want_certs on the wire"
  fi
  # THE STRUCTURAL VERDICT IS THE WHOLE OF S-5 - ADR46. The issuer of the leaf is
  # not among the certificates that arrived and the leaf did not sign itself, and
  # NO TRUST STORE WAS CONSULTED to establish that. A bench serving one
  # certificate that came back complete would mean the check reads something else.
  if [ "$(value "$file" intermediate_presented)" = "no" ] && [ "$got_complete" != "false" ]; then
    say "the chain is reported as complete ($got_complete), and the issuer of the leaf never arrived"
  fi
  # docs/21 S-5: the verdict names the SERVER. Every runtime on the machine fails
  # and the correct answer is still "do nothing here".
  if ! echo "$sentence" | grep -q 'server'; then
    say "the sentence does not name the server, and this fault is the server's"
  fi

  # WHAT THIS DOES NOT CHECK, SAID RATHER THAN LEFT AS SILENCE. expected/ carries
  # verdict_blames_forbidden=machine,runtime,store, and it CANNOT be checked by
  # looking for those words: the correct sentence says "a fact about the server
  # rather than about this machine", which contains one of them while denying it.
  # A word search would fail on the right answer and pass on a sentence that said
  # nothing at all. Judging it needs a reader.
  echo "    NOT CHECKED: whether the sentence BLAMES the machine - the right answer contains that word."
  notes=$((notes + 1))

  if [ "$got_l4" = "$want_l4" ]; then
    passed=$((passed + 1))
  fi
}

# check_trust asks what the stores on this machine make of the chain, and whether
# a command was offered - which is the half of the answer somebody RUNS.
#
# IT IS A SEPARATE FUNCTION FOR THE SAME REASON check_handshake IS: the subject
# is different and so is the independent witness. Here the witness is CURL
# ITSELF. That is worth naming, because it is the first time in this project that
# a claim about somebody else's runtime is checked against that runtime's own
# behaviour rather than against a document - certdoctor says curl will refuse
# this chain, so curl is asked whether it does.
#
# WHY CURL_CA_BUNDLE IS SET HERE. On this image curl is an OpenSSL build and
# reads that bundle anyway; naming it makes the store one certdoctor can OPEN and
# report on rather than one it can only say it cannot see. The variable changes
# which store is NAMEABLE, never which store curl uses.
check_trust() {
  local name="$1"
  local file="$expected/$name.txt"
  local target want_l4 want_l5 want_rows want_failure want_fix

  target="$(value "$file" target)"
  want_l4="$(value "$file" l4_status)"
  want_l5="$(value "$file" l5_status)"
  want_rows="$(value "$file" l5_rows_not_trusting)"
  want_failure="$(value "$file" l5_trust_failure)"
  want_fix="$(value "$file" remediation_expected)"

  say() {
    echo "    DIFFERS: $1"
    failed=$((failed + 1))
  }

  echo "  trust $name  ->  $target"

  local bundle=/etc/ssl/certs/ca-certificates.crt

  # THE RUNTIME ITSELF, FIRST, and its answer is printed whatever happens.
  local want_curl got_curl
  want_curl="$(value "$file" curl_exit_code)"
  CURL_CA_BUNDLE="$bundle" curl -sS -o /dev/null --max-time 10 "$target" 2>/dev/null
  got_curl=$?
  echo "    curl itself says: exit $got_curl"
  if [ -n "$want_curl" ] && [ "$got_curl" != "$want_curl" ]; then
    say "curl itself exits $got_curl and expected/ says $want_curl"
  fi

  local document code
  document="$(CURL_CA_BUNDLE="$bundle" "$binary" "$target" --json 2>/dev/null)"
  code=$?
  if [ -z "$document" ]; then
    say "certdoctor produced no document at all"
    return
  fi

  local got_l4 got_l5 got_rows got_failure got_fix
  got_l4="$(echo "$document" | jq -r '.layers[] | select(.id=="L4") | .status')"
  got_l5="$(echo "$document" | jq -r '.layers[] | select(.id=="L5") | .status')"
  got_rows="$(echo "$document" |
    jq -r '[.layers[] | select(.id=="L5") | .findings[]? | .trust_store | select(.trusts_presented_chain == false)] | length')"
  # tostring RATHER THAN THE // OPERATOR, for the reason recorded at the same
  # expression in check_handshake: jq treats false and null alike as empty, and
  # half the fields on this row carry their meaning when they are false.
  got_failure="$(echo "$document" |
    jq -r '[.layers[] | select(.id=="L5") | .findings[]? | .trust_store.trust_failure | select(. != null)] | first | tostring')"
  got_fix="$(echo "$document" |
    jq -r '[.layers[] | select(.id=="L5") | .findings[]? | .trust_store.fix | select(. != null)] | first | tostring')"

  echo "    certdoctor: L4 $got_l4 | L5 $got_l5 / $got_rows refusing / failure $got_failure | exit $code"

  if [ -n "$want_l4" ] && [ "$got_l4" != "$want_l4" ]; then
    say "L4 says $got_l4, expected $want_l4"
  fi
  if [ -n "$want_l5" ] && [ "$got_l5" != "$want_l5" ]; then
    say "L5 says $got_l5, expected $want_l5"
  fi
  if [ -n "$want_rows" ] && [ "$got_rows" != "$want_rows" ]; then
    say "$got_rows store(s) refused the chain, expected $want_rows"
  fi
  if [ -n "$want_failure" ] && [ "$got_failure" != "$want_failure" ]; then
    say "the refusal was classified as $got_failure, expected $want_failure"
  fi

  # THE HARDEST ASSERTION ON THIS BENCH, AND THE REASON private-root EXISTS.
  # no-intermediate produces a trust row just as red as this one, and a command
  # there would send somebody to edit a store that is perfectly fine. The two
  # scenarios differ by ONE line of nginx configuration.
  if [ "$want_fix" = "no" ] && [ "$got_fix" != "null" ]; then
    say "a remediation command was offered for a chain the SERVER broke: $got_fix"
  fi
  if [ "$want_fix" = "yes" ]; then
    if [ "$got_fix" = "null" ]; then
      say "no remediation command was offered, and this is the one case there is one for"
    else
      local command elevation placeholders wants_path
      command="$(echo "$document" |
        jq -r '[.layers[] | select(.id=="L5") | .findings[]? | .trust_store.fix | select(. != null) | .command] | first')"
      elevation="$(echo "$document" |
        jq -r '[.layers[] | select(.id=="L5") | .findings[]? | .trust_store.fix | select(. != null) | .requires_elevation] | first | tostring')"
      placeholders="$(echo "$document" |
        jq -r '[.layers[] | select(.id=="L5") | .findings[]? | .trust_store.fix | select(. != null) | .placeholders | length] | first')"
      echo "    command:    $command"

      # docs/20 rule 6: the path is the REAL one, read off this machine.
      wants_path="$(value "$file" remediation_contains)"
      if [ -n "$wants_path" ] && ! echo "$command" | grep -qF "$wants_path"; then
        say "the command does not name the real store path $wants_path"
      fi
      # docs/20 rule 5: elevated rights are announced BEFORE the command is run.
      if [ "$(value "$file" remediation_requires_elevation)" = "yes" ] && [ "$elevation" != "true" ]; then
        say "the command edits a store shared by the machine and does not say it needs elevated rights"
      fi
      if [ "$(value "$file" remediation_has_placeholders)" = "yes" ] && [ "${placeholders:-0}" -lt 1 ]; then
        say "the command declares nothing to fill in, and the certificate to import is not something this program can know"
      fi
      # THE MEASURED TRAP, FROM THE OTHER SIDE. Redirecting a runtime at another
      # bundle trades one broken site for every working one.
      local banned
      for banned in $(value "$file" remediation_forbidden | tr ',' ' '); do
        if echo "$command" | grep -qF -- "$banned"; then
          say "the command contains $banned, which redirects the runtime instead of adding to the store it already reads"
        fi
      done
    fi
  fi

  local want_code
  want_code="$(value "$file" exit_code)"
  if [ -n "$want_code" ] && [ "$code" != "$want_code" ]; then
    say "the run ended with $code, expected $want_code"
  fi

  if [ "$got_l5" = "$want_l5" ]; then
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

# THE SAME TRAP, ONE SERVICE OVER, AND IT WAS WALKED INTO ON 2026-08-19 WHILE
# ADDING THE BLOCK THIS CHECKS FOR. nginx reads its configuration once, at
# startup, and the configuration is a bind mount - so "docker compose up -d"
# reports everything healthy while the bench serves the previous file. The
# private-root scenario would then look like a product defect: the port simply
# would not answer.
bench_serves_the_complete_chain() {
  if nc -z 172.28.0.80 8443 2>/dev/null; then
    return 0
  fi
  echo "testbed: THE PARTNER IS NOT SERVING THE CONFIGURATION IN THIS WORKING TREE."
  echo "testbed: nothing is listening on 172.28.0.80:8443, and nginx.conf declares it."
  echo "testbed: nginx reads its configuration once, at startup, and a bind mount does not"
  echo "testbed: restart it - so an edited conf is invisible until the container is."
  echo "testbed: fix:  docker compose -f testbed/compose.yml restart partner"
  return 1
}

if ! bench_serves_this_tree || ! bench_serves_the_complete_chain; then
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

# S-5, AND ITS EXPECTATION HAS BEEN WAITING SINCE P4b. It was written from the
# bench's configuration BEFORE that configuration existed, which is the strongest
# form of oracle available - and until L4 arrived nothing could ask it.
check_handshake no-intermediate

echo

# THE PAIR, AND IT ONLY MEANS ANYTHING AS A PAIR. Both targets are the same
# server, the same leaf and the same private root; one sends its intermediate and
# the other does not. Both produce a trust row that is equally red. Only one of
# them may produce a command, and which one is decided by a fact from L4 rather
# than by anything a store could see.
check_trust no-intermediate
echo
check_trust private-root

echo

# WHAT THIS RUN DID NOT ASSESS, SAID OUT LOUD RATHER THAN LEFT AS SILENCE.
#
# P4b put two benches in place - a server that withholds its intermediate, and a
# proxy that re-signs traffic - and NOTHING HERE CAN JUDGE THEM, because the
# layer that would (L4) does not exist until P6. Their expectations are written
# down already, which is the whole point of building the bench first, but an
# expectation nobody checks is not coverage.
#
# The list builds itself: any expectation file naming interception_detected is by
# definition beyond what this script can ask today. So it cannot go stale by
# somebody adding a file and forgetting this block, and it empties itself when
# P6b arrives.
#
# THE KEY CHANGED FROM l4_status TO interception_detected ON 2026-08-17, WITH P6a,
# and the reason is the point of the self-building list rather than a defect in
# it. L4 now exists, so "names l4_status" stopped meaning "nothing can read this"
# - no-intermediate is checked above. What is still unreadable is DETECTING
# INTERCEPTION, which is P6b and touches load-bearing change 6.
deferred=0
for file in "$expected"/*.txt; do
  [ -e "$file" ] || continue
  if [ -n "$(value "$file" interception_detected)" ]; then
    if [ "$deferred" -eq 0 ]; then
      echo "testbed: NOT ASSESSED HERE - benches whose reader does not exist yet:"
    fi
    deferred=$((deferred + 1))
    echo "    $(basename "$file" .txt)  ->  $(value "$file" target)"
    echo "        expects interception $(value "$file" interception_detected), and nothing detects it yet. Waiting for P6b."
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
  echo "testbed: EXCEPT for $notes point(s) marked UNSETTLED or NOT CHECKED above."
  echo "testbed: THE TWO ARE DIFFERENT and both are printed in full. UNSETTLED waits on a"
  echo "testbed: DECISION; NOT CHECKED waits on a READER - an expectation this script"
  echo "testbed: cannot judge without judging English, such as whether a sentence blames"
  echo "testbed: the machine when the right answer contains that very word. Neither waits"
  echo "testbed: on a fix, and neither can be read off this line. Read them - a green line"
  echo "testbed: underneath a known gap is exactly the shape this project is built against."
  exit 0
fi

echo "testbed: certdoctor agrees with verdicts written before it ever ran here."
