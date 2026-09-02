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

# A TOKEN UNIQUE TO THIS RUN, because the proxy's access log is CUMULATIVE and
# survives a restart of everything else - slice P4c.
#
# Every request the proxy scenarios make carries it in the query string, and the
# log records the whole URL. Without it, "this request is absent" would mean
# "absent from a file nobody truncated", and yesterday's run would be part of
# today's evidence. Counting lines before and after would have the same fault the
# moment two runs overlapped.
run_token="cdrun-$(date +%s)-$$"

# Where the second opinion landed. Written by oracle-pac.sh in a container of its
# own, BEFORE this one started - see verify.sh for why it cannot live here.
oracle=/w/oracle-pac.txt

# oracle_answer pulls libproxy's verdict for one scenario out of that file. An
# empty answer means there was no second opinion this run, which is a MISSING
# WITNESS and is reported as one rather than passed over.
oracle_answer() {
  grep "^$1|" "$oracle" 2>/dev/null | head -1 | cut -d'|' -f3
}

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
  local target

  target="$(value "$file" target)"

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

  assert_trust "$file" "$document" "$code"
  assert_authority "$file" "$document"
}

# check_authority is the scenario where this machine has been GIVEN a certificate
# authority, which is the state every question about interception is really about.
#
# WHY IT BUILDS TWO STORES RATHER THAN USING THE IMAGE'S ONE. A single store can
# only ever answer "held" or "not held", and the answer this slice exists to
# produce is the DISAGREEMENT between two runtimes on one machine - which is what
# "the browser works and npm install does not" is. So one copy of the image
# bundle gets the authority appended and curl is pointed at it, another copy does
# not and git is pointed at that. Both are real files with real paths.
#
# NOTHING GLOBAL IS TOUCHED, and that is what keeps this check independent of the
# order the checks run in. The image's own bundle is left exactly as it was, and
# the git configuration is written for the length of one run and removed. An
# earlier draft appended to /etc/ssl/certs/ca-certificates.crt directly and would
# have silently changed the answer every later scenario got.
#
# THE CONTAINER IS THE REASON THIS IS ALLOWED AT ALL. docs/21 S-1 has asked for
# this import since P4b and it never happened, because on a real machine it is a
# change "docker compose down" does not undo. This container is discarded when
# the run ends.
check_authority() {
  local name="$1"
  local file="$expected/$name.txt"
  local target root work

  target="$(value "$file" target)"
  root="$(value "$file" root_pem)"

  say() {
    echo "    DIFFERS: $1"
    failed=$((failed + 1))
  }

  echo "  authority $name  ->  $target"

  if [ ! -r "$root" ]; then
    say "the authority this scenario is about is not readable at $root, so the bench could not deploy it"
    return
  fi

  # THE FILE SAYS WHICH RUNTIME IS GIVEN THE AUTHORITY AND WHICH IS NOT, AND THIS
  # FUNCTION HARD CODES THE ANSWER - so the two are checked against each other
  # rather than left to drift. An expectation nobody reads is not coverage, and
  # that includes the ones describing the setup.
  if [ "$(value "$file" root_deployed_to)" != "curl" ] || [ "$(value "$file" root_withheld_from)" != "git" ]; then
    say "expected/ describes a deployment this script does not perform - it gives the authority to curl and withholds it from git"
  fi

  work="$(mktemp -d)"
  cp /etc/ssl/certs/ca-certificates.crt "$work/deployed.crt"
  cat "$root" >> "$work/deployed.crt"
  cp /etc/ssl/certs/ca-certificates.crt "$work/withheld.crt"
  printf '[http]\n\tsslBackend = openssl\n\tsslCAInfo = %s\n' "$work/withheld.crt" > /etc/gitconfig

  # THE RUNTIME THAT WAS GIVEN THE AUTHORITY IS ASKED FIRST. An exit of 0 here is
  # the strongest evidence available that the deployment worked, because it is
  # the runtime itself saying so rather than us saying it about the runtime.
  local want_curl got_curl
  want_curl="$(value "$file" curl_exit_code)"
  CURL_CA_BUNDLE="$work/deployed.crt" curl -sS -o /dev/null --max-time 10 "$target" 2>/dev/null
  got_curl=$?
  echo "    curl with the authority deployed says: exit $got_curl"
  if [ -n "$want_curl" ] && [ "$got_curl" != "$want_curl" ]; then
    say "curl itself exits $got_curl and expected/ says $want_curl"
  fi

  local document code
  document="$(CURL_CA_BUNDLE="$work/deployed.crt" "$binary" "$target" --json 2>/dev/null)"
  code=$?
  rm -f /etc/gitconfig
  rm -rf "$work"

  if [ -z "$document" ]; then
    say "certdoctor produced no document at all"
    return
  fi

  assert_trust "$file" "$document" "$code"
  assert_authority "$file" "$document"
}

# assert_trust is every expectation about the matrix itself, asked of a document
# somebody else produced.
#
# IT IS A FUNCTION RATHER THAN TWO COPIES because both scenarios above ask the
# same questions of the same document, and a second copy of a rule is the shape
# OBS50 has taken four times in this tree - each time while somebody was tidying.
assert_trust() {
  local file="$1" document="$2" code="$3"
  local want_l4 want_l5 want_rows want_failure want_fix

  want_l4="$(value "$file" l4_status)"
  want_l5="$(value "$file" l5_status)"
  want_rows="$(value "$file" l5_rows_not_trusting)"
  want_failure="$(value "$file" l5_trust_failure)"
  want_fix="$(value "$file" remediation_expected)"

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

# assert_authority is P6b: who signed the leaf, how widely this machine holds
# them, and - the assertion this whole slice exists for - whether the program
# stayed on the right side of inviolable rule 21 while saying it.
assert_authority() {
  local file="$1" document="$2"
  local want_held want_issuer want_fp want_accuse
  local pick='[.layers[] | select(.id=="L5") | .findings[]? | select(.kind=="signing_authority")] | first'

  want_held="$(value "$file" authority_held_by)"
  [ -z "$want_held" ] && return

  local got_held got_issuer got_fp got_caveat got_sentence
  got_held="$(echo "$document" | jq -r "$pick | .signing_authority.held_by | tostring")"
  got_issuer="$(echo "$document" | jq -r "$pick | .signing_authority.issuer | tostring")"
  got_fp="$(echo "$document" | jq -r "$pick | .signing_authority.leaf_fingerprint_sha256 | tostring")"
  got_caveat="$(echo "$document" | jq -r "$pick | .signing_authority.caveat | tostring")"
  got_sentence="$(echo "$document" | jq -r "$pick | .summary | tostring")"

  echo "    authority:  held_by $got_held | issuer $got_issuer"

  if [ "$got_held" != "$want_held" ]; then
    say "the signer is reported as held by $got_held, expected $want_held"
  fi

  want_issuer="$(value "$file" authority_issuer_contains)"
  if [ -n "$want_issuer" ] && ! echo "$got_issuer" | grep -qF "$want_issuer"; then
    say "the issuer is reported as '$got_issuer' and expected/ says it contains '$want_issuer'"
  fi

  # Inviolable rule 21: the evidence travels with the claim, or the claim cannot
  # be checked by anybody who was not there.
  want_fp="$(value "$file" authority_has_fingerprint)"
  if [ "$want_fp" = "yes" ] && { [ -z "$got_fp" ] || [ "$got_fp" = "null" ]; }; then
    say "the row names an authority and carries no fingerprint, so nobody can check it"
  fi
  if [ -z "$got_caveat" ] || [ "$got_caveat" = "null" ]; then
    say "the row carries no caveat, and that is where the heuristic is named as a heuristic"
  fi

  # THE ASSERTION THE SLICE EXISTS FOR, AND IT IS A WORD SEARCH ON PURPOSE.
  #
  # intercepted.txt and internal-ca.txt reach this line with the SAME held_by
  # value, from a middlebox and from an honest internal server - measured
  # 2026-08-19, they are identical in every field certdoctor has. Until a name
  # from the inspection-product list says otherwise, neither may be accused.
  #
  # THE ONE PERMITTED USE OF THE WORD IS THE HEDGE ITSELF, which names both
  # readings and therefore accuses neither.
  want_accuse="$(value "$file" authority_accuses_interception)"
  if [ "$want_accuse" = "no" ]; then
    local sentence issuer_lower
    sentence="$(printf '%s %s' "$got_sentence" "$got_caveat" | tr 'A-Z' 'a-z')"

    # THE ISSUER IS REMOVED BEFORE THE SEARCH, AND THIS BENCH TAUGHT US WHY ON
    # ITS FIRST RUN. The middlebox here is called mitmproxy, so quoting its name
    # as evidence - which is what inviolable rule 21 REQUIRES - put the string
    # "mitm" into the sentence, and this check reported the program for accusing
    # somebody. It was a right answer to a different question, which is the
    # family OBS56 and OBS66 record: the first time this shape has appeared in a
    # check that reads English rather than JSON.
    issuer_lower="$(printf '%s' "$got_issuer" | tr 'A-Z' 'a-z')"
    if [ -n "$issuer_lower" ] && [ "$issuer_lower" != "null" ]; then
      sentence="${sentence//$issuer_lower/}"
    fi

    # The hedge names both readings, so the one word it contains is not an
    # accusation - it is the sentence saying the two cannot be told apart.
    if echo "$sentence" | grep -q "cannot tell those two apart"; then
      sentence="$(echo "$sentence" | sed 's/tls inspection looks exactly like this//')"
    fi
    local word
    for word in intercept mitm eavesdrop "man in the middle"; do
      if echo "$sentence" | grep -qF "$word"; then
        say "the report accuses with '$word' on a holding that is only a count of stores"
      fi
    done

    # AND NOTHING MAY BE NAMED EITHER. The word search above reads English; this
    # reads the field a machine consumer branches on, and they are two different
    # ways for the same mistake to arrive.
    local got_product
    got_product="$(echo "$document" | jq -r "$pick | .signing_authority.inspection.product // \"\"")"
    if [ -n "$got_product" ]; then
      say "the report named '$got_product' where nothing should be named - the structural signature here is"
      say "identical to the intercepted scenario, measured 2026-08-19, so naming on it accuses an honest server"
    fi
  fi

  # THE OTHER DIRECTION, AND WITHOUT IT EVERYTHING ABOVE IS SATISFIED BY A
  # PROGRAM THAT CANNOT SPEAK AT ALL - P6b-K2.
  #
  # Every expectation this bench carried until now was of the form "do not
  # accuse". A certdoctor that had lost the ability to name anything would pass
  # all of them and look green. This asks the opposite question of the one
  # scenario that has a sourced name: it must say the word, and it must say WHICH
  # product, because naming every issuer 'mitmproxy' would satisfy the first half.
  if [ "$want_accuse" = "yes" ]; then
    local got_product want_product lowered
    got_product="$(echo "$document" | jq -r "$pick | .signing_authority.inspection.product // \"\"")"
    want_product="$(value "$file" authority_inspection_product)"

    if [ -z "$got_product" ]; then
      say "expected/ says this issuer is on the inspection-product list and the report named nothing"
    elif [ -n "$want_product" ] && [ "$got_product" != "$want_product" ]; then
      say "the report named '$got_product' and expected/ says '$want_product'"
    fi

    lowered="$(printf '%s %s' "$got_sentence" "$got_caveat" | tr 'A-Z' 'a-z')"
    if ! echo "$lowered" | grep -qF "intercept"; then
      say "the report named a product and would not say what it means - a name with no sentence beside it"
      say "leaves the reader to work out the one thing this program exists to tell them"
    fi

    # THE HEDGE MUST HAVE CHANGED RATHER THAN SURVIVED. The caveat beside a
    # holding says these two cannot be told apart, which stops being true the
    # moment one is named - a report carrying both sentences contradicts itself
    # in two adjacent lines.
    if echo "$lowered" | grep -qF "cannot tell those two apart"; then
      say "the report named a product and kept the hedge saying it cannot tell the two apart"
    fi
  fi

  passed=$((passed + 1))
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
  if ! nc -z 172.28.0.80 8443 2>/dev/null; then
    echo "testbed: THE PARTNER IS NOT SERVING THE CONFIGURATION IN THIS WORKING TREE."
    echo "testbed: nothing is listening on 172.28.0.80:8443, and nginx.conf declares it."
    echo "testbed: nginx reads its configuration once, at startup, and a bind mount does not"
    echo "testbed: restart it - so an edited conf is invisible until the container is."
    echo "testbed: fix:  docker compose -f testbed/compose.yml restart partner"
    return 1
  fi

  # THE SAME TRAP ONE STEP FURTHER IN, AND IT WAS WALKED INTO ON 2026-08-19 WHILE
  # ADDING THE SCENARIO THAT NEEDED IT.
  #
  # The chain generator is an init container. Anything that makes compose bring
  # the stack up again can re-run it, and it MINTS A NEW ROOT when it does -
  # while nginx, which read its certificates once at startup, keeps serving the
  # old ones. Every container then reports healthy, the port answers, and the
  # root in the volume no longer signs anything on the wire.
  #
  # WHAT THAT LOOKS LIKE IF NOBODY CHECKS: internal-ca deploys the root from the
  # volume, no store accepts the server anyway, and the bench reports certdoctor
  # as having got the answer wrong. It is inviolable rule 1 from the wrong side
  # for the third time on this bench - after the Corefile and after nginx.conf.
  if openssl s_client -connect 172.28.0.80:8443 -servername partner.test \
    -CAfile /certs/root.crt </dev/null 2>/dev/null | grep -q "Verify return code: 0"; then
    return 0
  fi
  echo "testbed: THE PARTNER IS SERVING A CHAIN THE ROOT IN THE VOLUME DID NOT SIGN."
  echo "testbed: the generator mints a new chain whenever it runs again, and nginx reads"
  echo "testbed: its certificates once, at startup - so the two drift apart in silence."
  echo "testbed: every scenario about a trust store would then blame certdoctor."
  echo "testbed: fix:  docker compose -f testbed/compose.yml restart partner"
  return 1
}

# THE SAME TRAP A THIRD TIME, AND THIS ONE HAS TWO HALVES BECAUSE THE SCENARIO
# NEEDED A CHANGE TO TWO SERVICES.
#
# CoreDNS has to be serving the example.net zone from this working tree, and
# mitmproxy has to be running the reverse listener rather than the forward proxy
# alone. Neither is picked up by "docker compose up -d" on a container that is
# already running: a zone file is a bind mount read once, and a changed command
# needs the container recreated rather than restarted.
#
# WITHOUT THIS THE SCENARIO FAILS AS THOUGH THE PRODUCT WERE WRONG - the name
# would not resolve, or the connection would be refused, and the report would say
# so accurately about a bench that is not the one in this tree.
bench_serves_the_interception_path() {
  local got
  got="$(dig +short "@172.28.0.53" registry.example.net A 2>/dev/null | head -1)"
  if [ "$got" != "172.28.0.81" ]; then
    echo "testbed: THE BENCH IS NOT SERVING THE example.net ZONE FROM THIS WORKING TREE."
    echo "testbed: registry.example.net answered '${got:-nothing}', and the zone file says 172.28.0.81."
    echo "testbed: fix:  docker compose -f testbed/compose.yml restart dns"
    return 1
  fi
  if ! nc -z 172.28.0.81 443 2>/dev/null; then
    echo "testbed: THE MIDDLEBOX IS NOT RUNNING THE REVERSE LISTENER THIS TREE DECLARES."
    echo "testbed: nothing is listening on 172.28.0.81:443, and compose.yml declares it."
    echo "testbed: a changed command needs the container RECREATED, not restarted."
    echo "testbed: fix:  docker compose -f testbed/compose.yml up -d --force-recreate mitm"
    return 1
  fi
  return 0
}

# THE SAME TRAP A FOURTH AND FIFTH TIME, AND BOTH WERE WALKED INTO WHILE BUILDING
# THIS SLICE RATHER THAN BEING ANTICIPATED - slice P4c.
#
# CoreDNS reads the Corefile once, at startup, so a zone added to the working
# tree was invisible to a container that had been up for ten hours: every name in
# proxy.test came back NXDOMAIN while "docker compose up -d" reported everything
# healthy. That is OBS64 for the fourth time.
#
# And squid caches DNS answers, including the negative ones it collected while
# that zone did not exist, so restarting the resolver was not enough - the proxy
# went on believing the names did not exist. That is the same shape one service
# further along, and it is new.
#
# WITHOUT THIS CHECK BOTH FAULTS READ AS PRODUCT DEFECTS: a proxy that will not
# forward and an origin that cannot be reached, reported accurately about a bench
# that is not the one in this tree.
bench_serves_the_proxy_bench() {
  local code

  code="$(curl -s -o /dev/null -w '%{http_code}' http://pac.proxy.test/pac/proxy.pac 2>/dev/null)"
  if [ "$code" != "200" ]; then
    echo "testbed: the PAC server did not serve /pac/proxy.pac - HTTP ${code:-no answer}."
    echo "testbed: nginx reads its configuration ONCE, at startup, and that file is a bind mount."
    echo "testbed: fix:  docker compose -f testbed/compose.yml restart pac"
    return 1
  fi

  code="$(curl -s -o /dev/null -w '%{http_code}' -x http://172.28.0.128:3128 http://via.proxy.test/ 2>/dev/null)"
  if [ "$code" != "200" ]; then
    echo "testbed: the proxy did not forward on 3128 - HTTP ${code:-no answer}."
    echo "testbed: squid caches DNS, negative answers included, so a zone added after it"
    echo "testbed: started stays invisible to it however healthy the container looks."
    echo "testbed: fix:  docker compose -f testbed/compose.yml restart proxy"
    return 1
  fi

  code="$(curl -s -o /dev/null -w '%{http_code}' -x http://172.28.0.128:3129 http://auth.proxy.test/ 2>/dev/null)"
  if [ "$code" != "407" ]; then
    echo "testbed: the proxy answered ${code:-nothing} on 3129 where a challenge - 407 - was expected."
    echo "testbed: the credential rule lives in proxy/certdoctor.conf, which squid reads at startup."
    echo "testbed: fix:  docker compose -f testbed/compose.yml restart proxy"
    return 1
  fi

  # THE ORACLE ITSELF HAS TO BE READABLE BEFORE ANY SCENARIO BELIEVES IT. An
  # unreadable log would make every "absent from the proxy log" check pass for
  # the wrong reason, which is the most dangerous shape a green line can take.
  if [ ! -r /proxylog/access.log ]; then
    echo "testbed: the proxy access log is not readable at /proxylog/access.log."
    echo "testbed: every proxy scenario would then agree for the wrong reason, so none run."
    echo "testbed: fix:  docker compose -f testbed/compose.yml up -d --force-recreate proxy"
    return 1
  fi

  return 0
}

# check_proxy_env is the ONE proxy scenario with a reader today, and the reason
# this slice is not a bench waiting on a consumer - slice P4c.
#
# L2 does not exist. L0 has read the proxy variables since P2, so three claims
# can be settled now: the variable is reported, the password in it does not
# survive, and reading it does not mean OBEYING it.
#
# THE THIRD IS THE ONE THAT HAS NEVER BEEN RUN. docs/14 section 3 says the
# environment must never change WHAT the tool does, and the premise behind that -
# nothing in the product uses a transport honouring these variables - was read
# out of the imports rather than measured. Here it is measured: the same target,
# twice, once with the variables and once without.
check_proxy_env() {
  local file="$expected/proxy-env.txt"
  local target proxy_var noproxy_var secret secret2 var1 var2

  target="$(value "$file" target)"
  proxy_var="$(value "$file" env_https_proxy)"
  noproxy_var="$(value "$file" env_no_proxy)"
  secret="$(value "$file" secret_absent)"
  secret2="$(value "$file" secret_absent_2)"
  var1="$(value "$file" l0_names_variable)"
  var2="$(value "$file" l0_names_variable_2)"

  say() {
    echo "    DIFFERS: $1"
    failed=$((failed + 1))
  }

  echo "  proxy scenario proxy-env  ->  $target"

  local base base_code doc code human
  base="$(env -u HTTPS_PROXY -u https_proxy -u NO_PROXY -u no_proxy "$binary" "$target" --json 2>/dev/null)"
  base_code=$?

  # THE PROXY IS ASKED TOO, AND IT IS THE STRONGEST FORM OF THIS CLAIM.
  #
  # Comparing layer statuses shows the run came out the same. It does not show
  # that nothing was SENT to the proxy along the way - a request that went
  # through it and succeeded would leave the statuses untouched. So the log is
  # snapshotted around the run: if certdoctor obeyed the variable, squid wrote a
  # line, and the count moved.
  #
  # This is inviolable rule 16 with a witness that is not our code. The target
  # set is enforced by a guard inside the program, and a guard inside the program
  # is exactly what an outsider cannot check.
  local log_before log_after
  log_before="$(wc -l < /proxylog/access.log 2>/dev/null || echo 0)"

  doc="$(HTTPS_PROXY="$proxy_var" NO_PROXY="$noproxy_var" "$binary" "$target" --json 2>/dev/null)"
  code=$?
  human="$(HTTPS_PROXY="$proxy_var" NO_PROXY="$noproxy_var" "$binary" "$target" --no-color 2>/dev/null)"

  log_after="$(wc -l < /proxylog/access.log 2>/dev/null || echo 0)"
  if [ "$log_before" != "$log_after" ]; then
    say "the proxy log GREW during a run with the variables set - certdoctor sent something through it"
  fi

  if [ -z "$doc" ]; then
    say "certdoctor produced no document at all with the proxy variables set"
    return
  fi

  # CLAIM 1: the variables are reported. Asked of the L0 layer specifically and
  # by exact string, so a substring somewhere else in the document cannot answer
  # for it.
  local seen
  for seen in "$var1" "$var2"; do
    [ -n "$seen" ] || continue
    if ! echo "$doc" | jq -e --arg v "$seen" \
      '[.layers[] | select(.id=="L0") | .. | strings] | any(. == $v)' >/dev/null 2>&1; then
      say "L0 does not name $seen, and silence about a configured proxy is the fault OBS72 was"
    fi
  done

  # CLAIM 2: the credential does not survive. Both surfaces, because inviolable
  # rule 12 says every finding exists on all of them - which means a leak does
  # too. NO --redact is passed: masking userinfo is a property of the layer that
  # produces it, not an option a user has to remember.
  local surface
  for surface in "$doc" "$human"; do
    if echo "$surface" | grep -qF "$secret"; then
      say "THE PASSWORD SURVIVED into a report surface - inviolable rule 17"
    fi
    if echo "$surface" | grep -qF "$secret2"; then
      say "the account name survived into a report surface, which is half a credential"
    fi
  done

  # CLAIM 3: the environment changed nothing. Layer statuses and the exit code,
  # never timings - two runs differ in those by nature and comparing them would
  # make this flap.
  local base_shape shape
  base_shape="$(echo "$base" | jq -c '[.layers[] | {id, status}]' 2>/dev/null)"
  shape="$(echo "$doc" | jq -c '[.layers[] | {id, status}]' 2>/dev/null)"
  if [ "$base_shape" != "$shape" ]; then
    say "setting the proxy variables CHANGED the layer statuses - $base_shape became $shape"
  fi
  if [ "$base_code" != "$code" ]; then
    say "setting the proxy variables changed the exit code from $base_code to $code"
  fi

  echo "    certdoctor: exit $code with the variables, $base_code without | layers $shape"
  echo "    secret:     absent from both surfaces"
  echo "    proxy log:  $log_before lines before the run, $log_after after - nothing was sent through it"

  if [ "$base_shape" = "$shape" ]; then
    passed=$((passed + 1))
  fi
}

# check_pac_route is the row docs/21 section 2b called a gap by nature - and the
# reason P4c was given a job that document did not foresee.
#
# TWO WITNESSES, NEITHER OF THEM OUR CODE. libproxy says what the PAC MEANS.
# squid's access log says whether the request ARRIVED. Between them they answer
# two of the three questions that row was really asking, and the third - whether
# a given runtime would read this PAC and obey it - stays open and is named.
#
# 🔴 THE CLIENT IS DRIVEN BY THE ORACLE'S ANSWER, NOT BY THIS SCRIPT. That is the
# whole design. If the PAC had said something else, libproxy would have said so
# and curl would have gone somewhere else - so a request appearing in the log is
# caused by the routing rule rather than by a proxy address written in here. An
# absence means the same thing in reverse, which is the only way an absence is
# evidence at all.
check_pac_route() {
  local name="$1"
  local file="$expected/$name.txt"
  local target host want_answer want_log want_http want_tag pending

  target="$(value "$file" target)"
  host="$(value "$file" pac_host)"
  want_answer="$(value "$file" pac_expect)"
  want_log="$(value "$file" proxy_log_expect)"
  want_http="$(value "$file" http_expect)"
  want_tag="$(value "$file" proxy_log_tag)"
  pending="$(value "$file" pending_decision)"

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

  echo "  proxy scenario $name  ->  $target"

  local got_answer
  got_answer="$(oracle_answer "$name")"
  if [ -z "$got_answer" ]; then
    echo "    NOT CHECKED: there was no second opinion this run - libproxy was not available."
    echo "        The bench can still be run, but this scenario proved nothing."
    notes=$((notes + 1))
    return
  fi

  # THE SECOND OPINION IS PRINTED WHATEVER HAPPENS, exactly as dig is in
  # check_scenario. When it disagrees with the expectation, the first suspect is
  # the PAC file or our reading of it - not the product, which has not been asked
  # anything yet.
  echo "    libproxy says: $host -> $got_answer"
  if [ "$got_answer" != "$want_answer" ]; then
    say "libproxy reads this PAC as $got_answer, and expected/ says $want_answer"
  fi

  local -a client
  case "$got_answer" in
    direct://)
      client=(--noproxy '*')
      ;;
    http://*)
      client=(-x "$got_answer")
      ;;
    *)
      say "libproxy answered $got_answer, which this bench cannot turn into a request"
      return
      ;;
  esac

  # THE TOKEN GOES IN THE PATH, NOT IN A QUERY STRING, AND THAT IS A MEASUREMENT
  # RATHER THAN A PREFERENCE. Measured 2026-09-02 on the first run of this bench:
  # squid strips everything after "?" from a logged URL by default, so a request
  # that had visibly succeeded through the proxy was reported as never having
  # arrived. The configuration now turns that off, and the token moved anyway - a
  # witness that can be silenced by a privacy setting on the thing being watched
  # is not a witness worth relying on.
  local token got_http
  token="$run_token-$name"
  got_http="$(curl -s -o /dev/null -w '%{http_code}' "${client[@]}" "${target%/}/$token" 2>/dev/null)"

  if [ -n "$want_http" ] && [ "$got_http" != "$want_http" ]; then
    say "the client following that answer got HTTP $got_http, expected $want_http"
  fi

  # Squid writes unbuffered, but the request returning and the line landing are
  # still two events. A bounded wait beats a race that would be blamed on the
  # product the first time it lost.
  local seen="absent" i=0 line=""
  while [ "$i" -lt 25 ]; do
    line="$(grep -F "$token" /proxylog/access.log 2>/dev/null | head -1)"
    if [ -n "$line" ]; then
      seen="present"
      break
    fi
    i=$((i + 1))
    sleep 0.2
  done

  if [ "$seen" != "$want_log" ]; then
    say "the proxy log says this request was $seen, expected $want_log"
  fi

  if [ -n "$want_tag" ] && [ -n "$line" ] && ! echo "$line" | grep -qF "$want_tag"; then
    say "the proxy logged this as something other than $want_tag"
  fi

  echo "    proxy log:  $seen${line:+  ->  $(echo "$line" | awk '{print $4, $6, $7}')}"

  if [ "$got_answer" = "$want_answer" ] && [ "$seen" = "$want_log" ]; then
    passed=$((passed + 1))
  fi
}

if ! bench_serves_this_tree || ! bench_serves_the_complete_chain || ! bench_serves_the_interception_path || ! bench_serves_the_proxy_bench; then
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

# THE SECOND PAIR, AND IT ONLY MEANS ANYTHING AS A PAIR TOO - this one is the
# whole of P6b.
#
# Both scenarios below deploy a certificate authority into ONE of this machine's
# two stores and withhold it from the other, which is what a group policy push
# does. One of them is a middlebox re-signing somebody else's traffic. The other
# is an honest internal server under a company's own authority, doing nothing
# wrong whatsoever.
#
# MEASURED 2026-08-19: THEY PRODUCE THE SAME ANSWER IN EVERY FIELD certdoctor
# HAS. That is why neither may be accused of interception here, and why the file
# for the honest one exists at all - it is the false positive inviolable rule 21
# calls harm, written down before the code that could commit it.
check_authority intercepted
echo
check_authority internal-ca

echo

# THE PROXY BENCH - slice P4c, and the first scenarios here whose witness is
# somebody else's LOG rather than somebody else's TOOL.
#
# proxy-env is checkable end to end today, because L0 has read these variables
# since P2. The three that follow are the oracle for a claim L2 will make later:
# they establish what the PAC means and where the request went, so that when P8
# arrives the expectation it is measured against was written first.
#
# THE THREE ROUTING SCENARIOS ONLY MEAN ANYTHING TOGETHER. via, direct and auth
# resolve to one address on one server returning one body. The PAC is the only
# difference between them.
check_proxy_env

echo

check_pac_route proxy-pac-via
echo
check_pac_route proxy-pac-direct
echo
check_pac_route proxy-auth

# 🔴 say() IS GLOBAL IN BASH EVEN WHEN IT IS DEFINED INSIDE A FUNCTION, and the
# scenario immediately above carries a pending_decision - so it has just left
# say() as the UNSETTLED variant, which counts a note instead of a failure.
#
# Nothing below uses it today, so this changes no result. It is here because the
# next person to add a scenario after this line would inherit that quietly: a
# real disagreement would be printed as a parked question and the run would stay
# green. Every function above redefines say() before using it, which is what has
# kept this harmless so far - this restores the default rather than relying on
# that habit holding forever.
say() {
  echo "    DIFFERS: $1"
  failed=$((failed + 1))
}

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

# THE SECOND SELF-BUILDING LIST, AND IT EXISTS FOR THE SAME REASON THE FIRST ONE
# DOES - slice P4c, waiting for P8.
#
# L2 is the one layer of the eight that has nothing behind it but an identifier
# in internal/core/layer/layer.go. Every expectation naming a key that starts
# with l2_ is therefore beyond what this script can ask, however well the bench
# around it works.
#
# IT KEYS ON THE PREFIX RATHER THAN ON ONE FIELD NAME because the shape of an L2
# finding is not settled - ADR75 approved adding the finding kind and the fields
# in P8-K3 without saying what they are called. A list keyed on a name nobody has
# chosen yet would go stale the day somebody chose it. It empties itself when the
# layer arrives, exactly as the interception list will.
pending_l2=0
for file in "$expected"/*.txt; do
  [ -e "$file" ] || continue
  if grep -qE '^l2_' "$file" 2>/dev/null; then
    if [ "$pending_l2" -eq 0 ]; then
      echo "testbed: NOT ASSESSED HERE - expectations about L2, which does not exist yet:"
    fi
    pending_l2=$((pending_l2 + 1))
    echo "    $(basename "$file" .txt)  ->  $(value "$file" target)"

    # A DECISION WAITING ON THE OWNER IS PRINTED HERE OR IT IS INVISIBLE. The
    # pending_decision mechanism only turns a DIFFERENCE into a note, and a layer
    # nothing reads produces no differences at all - so a question parked in one
    # of these files would sit unread until somebody opened it by chance. Naming
    # it on every run is the difference between a parked question and a lost one.
    decision="$(value "$file" pending_decision)"
    if [ -n "$decision" ]; then
      echo "        AWAITING A DECISION: $decision"
    fi
  fi
done
if [ "$pending_l2" -gt 0 ]; then
  echo "testbed: those $pending_l2 expectation(s) were written from the bench's configuration"
  echo "testbed: and from the product's contract BEFORE the layer existed. What the bench"
  echo "testbed: CAN establish today is checked above: what the PAC means, according to an"
  echo "testbed: evaluator that is not ours, and where the request actually went, according"
  echo "testbed: to a log that is not ours either. The layer that will read them is P8."
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
