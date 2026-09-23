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
  # snapshotted around the run, and this is inviolable rule 16 with a witness
  # that is not our code: the target set is enforced by a guard inside the
  # program, and a guard inside the program is exactly what an outsider cannot
  # check.
  #
  # THE CLAIM WAS NARROWED ON 2026-09-07 AND THE OLD ONE WOULD NOW BE FALSE -
  # OBS127. It read "the log did not grow at all", which stopped being true the
  # moment L2 began ASKING a proxy whether it wants credentials: that question
  # is a real request and squid writes a real line for it. Reading that line as
  # "certdoctor obeyed the variable" would fail this bench for the feature
  # working.
  #
  # WHAT REPLACES IT IS NOT WEAKER, AND THAT IS THE POINT OF WRITING IT THIS WAY.
  # The log must grow by EXACTLY the number of questions the run SAYS it asked -
  # one line per proxy_challenge row that reports asked. A run that routed its
  # diagnosis through the proxy would add lines beyond the ones it admits to, and
  # a run that asked nothing must still move the count by nothing. So the witness
  # is now "certdoctor's own account of what it sent agrees with somebody else's
  # record of what arrived", which is a stronger sentence than the one it
  # replaces.
  #
  # THE HUMAN RUN IS OUTSIDE THE BRACKET DELIBERATELY. Two runs inside it would
  # double the count and make the arithmetic depend on how many surfaces this
  # check happens to render.
  local log_before log_after grew admitted
  log_before="$(wc -l < /proxylog/access.log 2>/dev/null || echo 0)"

  doc="$(HTTPS_PROXY="$proxy_var" NO_PROXY="$noproxy_var" "$binary" "$target" --json 2>/dev/null)"
  code=$?

  log_after="$(wc -l < /proxylog/access.log 2>/dev/null || echo 0)"
  grew=$((log_after - log_before))
  admitted="$(echo "$doc" | jq '[.layers[] | select(.id=="L2") | .findings[]?
    | select(.proxy_challenge != null and .proxy_challenge.asked == true)] | length' 2>/dev/null)"
  [ -n "$admitted" ] || admitted=0
  if [ "$grew" != "$admitted" ]; then
    say "the proxy log grew by $grew line(s) while the run admits to asking $admitted question(s) - certdoctor sent something it does not report"
  fi

  human="$(HTTPS_PROXY="$proxy_var" NO_PROXY="$noproxy_var" "$binary" "$target" --no-color 2>/dev/null)"

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
  #
  # L2 IS EXCLUDED FROM THE COMPARISON FROM 2026-09-06, AND THE EXCLUSION IS THE
  # POINT OF THE LAYER RATHER THAN A CONCESSION. This claim asks whether reading
  # a proxy variable REROUTED the diagnosis. L2 exists to READ those variables
  # and say what they hold, so its row differing between a run with them and a
  # run without them is the product working - measured, UNKNOWN becomes WARN -
  # and a check that forbade it would forbid the layer.
  #
  # WHAT STILL WITNESSES THE CLAIM, and it is three things rather than one: the
  # OTHER SEVEN layers, which have no business noticing a proxy variable; the
  # EXIT CODE, which is the whole run's answer; and the PROXY LOG above, which is
  # the only one of the three that is not our own code. Dropping L2 costs the
  # weakest of the witnesses.
  local base_shape shape
  base_shape="$(echo "$base" | jq -c '[.layers[] | select(.id!="L2") | {id, status}]' 2>/dev/null)"
  shape="$(echo "$doc" | jq -c '[.layers[] | select(.id!="L2") | {id, status}]' 2>/dev/null)"
  if [ "$base_shape" != "$shape" ]; then
    say "setting the proxy variables CHANGED the layer statuses - $base_shape became $shape"
  fi
  if [ "$base_code" != "$code" ]; then
    say "setting the proxy variables changed the exit code from $base_code to $code"
  fi

  # CLAIM 4: L2 SAYS WHAT THE VARIABLES HOLD. Written into this file before the
  # layer existed and deferred ever since - the deferral was the point, because
  # an expectation written after the code is a transcript rather than an oracle.
  local l2_status l2_proxy l2_source l2_bypass
  l2_status="$(value "$file" l2_status)"
  l2_proxy="$(value "$file" l2_proxy)"
  l2_source="$(value "$file" l2_source)"
  l2_bypass="$(value "$file" l2_bypass_names)"

  local said_status said_proxy said_stack said_bypass
  said_status="$(echo "$doc" | jq -r '.layers[] | select(.id=="L2") | .status' 2>/dev/null)"
  said_proxy="$(echo "$doc" | jq -r '[.layers[] | select(.id=="L2") | .findings[]?
    | select(.proxy_stack != null and .proxy_stack.selected != null)
    | .proxy_stack.selected.address] | first // ""' 2>/dev/null)"
  said_stack="$(echo "$doc" | jq -r '[.layers[] | select(.id=="L2") | .findings[]?
    | select(.proxy_stack != null and .proxy_stack.selected != null)
    | .proxy_stack.stack] | first // ""' 2>/dev/null)"
  said_bypass="$(echo "$doc" | jq -r '[.layers[] | select(.id=="L2") | .findings[]?
    | select(.proxy_stack != null) | .proxy_stack.bypass] | join(" ")' 2>/dev/null)"

  [ "$said_status" = "$l2_status" ] || say "L2 answered $said_status where the bench expects $l2_status"
  [ "$said_proxy" = "$l2_proxy" ] || say "L2 names the proxy $said_proxy where the bench expects $l2_proxy"
  [ "$said_stack" = "$l2_source" ] || say "L2 says the proxy comes from $said_stack where the bench expects $l2_source"
  case "$said_bypass" in
    *"$l2_bypass"*) ;;
    *) say "L2 does not name $l2_bypass among the exceptions, and a proxy named without its exceptions is half an answer" ;;
  esac

  echo "    L2:         $said_status, $said_proxy from $said_stack, exceptions $said_bypass"
  echo "    certdoctor: exit $code with the variables, $base_code without | layers $shape"
  echo "    secret:     absent from both surfaces"
  echo "    proxy log:  grew by $grew line(s), and the run admits to asking $admitted question(s)"

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

  # --- W4: WHAT certdoctor MAKES OF THE SAME FILE ---
  #
  # THIS ROW LEFT THE "NOT ASSESSED HERE" LIST ON 2026-09-06. Until then nothing
  # could ask it: only the Windows stacks carry an AutoConfigURL, proxyconf reads
  # nothing at all on Linux, and this bench is Linux - so the layer could never
  # learn about pac.proxy.test however well the server answered. --pac-url is
  # what closed that, and closing it is the reason the flag exists.
  #
  # IT IS ASKED AFTER libproxy AND THE LOG, NOT INSTEAD OF THEM. Those two say
  # what the PAC MEANS and where a request actually WENT; this one says what
  # certdoctor REPORTS. A run where all three agree is the only one that proves
  # anything, and the first two are not our code.
  local pac_url want_status want_proxy want_source want_forbidden
  local want_reason want_reason_forbidden want_auth
  pac_url="$(value "$file" pac_url)"
  want_status="$(value "$file" l2_status)"
  want_proxy="$(value "$file" l2_proxy)"
  want_source="$(value "$file" l2_source)"
  want_forbidden="$(value "$file" verdict_forbidden)"
  # THE THREE KEYS THAT LEFT THE "NOT ASSESSED HERE" LIST ON 2026-09-07, and they
  # are the last three in this bench that were written before the code and had
  # never been read. proxy-auth.txt named credentials_required as the tenth
  # UNKNOWN reason while it deliberately did not exist yet; P8-K3c is the slice
  # that can produce it. The other two scenarios name none of these keys, and an
  # empty expectation is skipped rather than compared against nothing.
  want_reason="$(value "$file" l2_reason)"
  want_reason_forbidden="$(value "$file" l2_reason_forbidden)"
  want_auth="$(value "$file" l2_auth_required)"
  # THE TWO LAYERS AFTER THE CONNECTION, ASKED HERE SINCE ADR100. Every target in
  # these scenarios is http://, and L4 used to try a handshake on the plain HTTP
  # port and call the silence a FAIL - measured on proxy-auth 2026-09-22, and
  # never caught, because nothing in this function read L4 at all. The answer does
  # not depend on whether L3 reached anything, so it can be declared outright.
  local want_l4 want_l4_reason want_l5
  want_l4="$(value "$file" l4_status)"
  want_l4_reason="$(value "$file" l4_reason)"
  want_l5="$(value "$file" l5_status)"

  local env_proxy doc said_status said_proxy said_source said_detail
  env_proxy="$(value "$file" env_https_proxy)"
  # The environment is set exactly as the file declares it, because the scenario
  # is "a proxy IS configured AND the PAC overrides it". Without it the negative
  # half would be trivially true.
  doc="$(HTTPS_PROXY="$env_proxy" "$binary" "$target" --pac-url "$pac_url" --json 2>/dev/null)"

  if [ -z "$doc" ]; then
    say "certdoctor produced no document at all for this PAC"
  else
    said_status="$(echo "$doc" | jq -r '.layers[] | select(.id=="L2") | .status' 2>/dev/null)"
    said_detail="$(echo "$doc" | jq -r '.layers[] | select(.id=="L2") | .detail' 2>/dev/null)"
    # THE PROXY COMES OFF THE SCRIPT ROW AND NOT OFF A STACK, which is the whole
    # point of these two scenarios: the stacks say one thing and the script
    # decides another.
    said_proxy="$(echo "$doc" | jq -r '[.layers[] | select(.id=="L2") | .findings[]?
      | select(.pac_script != null and .pac_script.selected != null)
      | .pac_script.selected.endpoint] | first // ""' 2>/dev/null)"
    said_source=""
    if [ -n "$(echo "$doc" | jq -r '[.layers[] | select(.id=="L2") | .findings[]?
      | select(.pac_script != null and .pac_script.selected != null)] | first // ""' 2>/dev/null)" ]; then
      said_source="pac"
    fi
    # DIRECT names no endpoint, and the expectation spells that "none".
    [ -n "$said_proxy" ] || said_proxy="none"

    [ "$said_status" = "$want_status" ] || say "L2 answered $said_status where the bench expects $want_status"
    [ "$said_proxy" = "$want_proxy" ] || say "L2 names the proxy $said_proxy where the bench expects $want_proxy"
    [ -z "$want_source" ] || [ "$said_source" = "$want_source" ] || say "L2 says the decision comes from ${said_source:-nothing} where the bench expects $want_source"

    # THE REASON, WHICH IS WHAT THIS SCENARIO WAS ALWAYS FOR. A proxy asking who
    # you are is neither a broken proxy nor a broken machine, so the word has to
    # be UNKNOWN with a reason of its own - and it must never be access_denied,
    # which ADR70 and ADR80 each removed from a place it did not belong.
    local said_reason said_auth said_asked
    said_reason="$(echo "$doc" | jq -r '.layers[] | select(.id=="L2") | .reason // ""' 2>/dev/null)"
    if [ -n "$want_reason" ] && [ "$said_reason" != "$want_reason" ]; then
      say "L2 gives the reason ${said_reason:-none} where the bench expects $want_reason"
    fi
    if [ -n "$want_reason_forbidden" ] && [ "$said_reason" = "$want_reason_forbidden" ]; then
      say "L2 gives the reason $said_reason, which this scenario forbids outright"
    fi

    # THE PROXY WAS ACTUALLY ASKED, which is the half no status can show. A run
    # reporting credentials_required without a row saying it put the question
    # would have concluded it from the configuration rather than from the proxy.
    if [ -n "$want_auth" ]; then
      said_asked="$(echo "$doc" | jq -r '[.layers[] | select(.id=="L2") | .findings[]?
        | select(.proxy_challenge != null and .proxy_challenge.asked == true and .proxy_challenge.status == 407)
        | .proxy_challenge.endpoint] | first // ""' 2>/dev/null)"
      said_auth=no
      [ -z "$said_asked" ] || said_auth=yes
      if [ "$said_auth" != "$want_auth" ]; then
        say "L2 says a credential is required: $said_auth, where the bench expects $want_auth"
      fi
      if [ "$want_auth" = yes ] && [ -n "$said_asked" ] && [ "$said_asked" != "$want_proxy" ]; then
        say "L2 asked $said_asked for credentials where the bench expects $want_proxy"
      fi
      echo "    challenge:  a 407 from ${said_asked:-nobody}"
    fi

    local said_l4 said_l4_reason said_l5
    said_l4="$(echo "$doc" | jq -r '.layers[] | select(.id=="L4") | .status' 2>/dev/null)"
    said_l4_reason="$(echo "$doc" | jq -r '.layers[] | select(.id=="L4") | .reason // ""' 2>/dev/null)"
    said_l5="$(echo "$doc" | jq -r '.layers[] | select(.id=="L5") | .status' 2>/dev/null)"
    [ -z "$want_l4" ] || [ "$said_l4" = "$want_l4" ] || say "L4 answered $said_l4 where the bench expects $want_l4"
    [ -z "$want_l4_reason" ] || [ "$said_l4_reason" = "$want_l4_reason" ] || say "L4 gives the reason ${said_l4_reason:-none} where the bench expects $want_l4_reason"
    [ -z "$want_l5" ] || [ "$said_l5" = "$want_l5" ] || say "L5 answered $said_l5 where the bench expects $want_l5"

    # THE FORBIDDEN SENTENCES ARE THE POINT OF proxy-pac-direct. A report saying
    # "a proxy is configured" and stopping has told somebody the opposite of what
    # is happening on their machine, so those words were written down before the
    # layer that could get them wrong existed.
    if [ -n "$want_forbidden" ]; then
      local phrase
      echo "$want_forbidden" | tr ',' '\n' | while IFS= read -r phrase; do
        [ -n "$phrase" ] || continue
        case "$said_detail" in
          *"$phrase"*) echo "    DIFFERS: the verdict says \"$phrase\" about a URL this PAC decides" ;;
        esac
      done
    fi

    echo "    certdoctor: L2 $said_status, proxy $said_proxy from ${said_source:-the machine} | L4 $said_l4 / ${said_l4_reason:-no reason} | L5 $said_l5"
  fi

  if [ "$got_answer" = "$want_answer" ] && [ "$seen" = "$want_log" ]; then
    passed=$((passed + 1))
  fi
}

# check_pac_file asks certdoctor about a PAC file the bench serves and nothing
# else - no proxy log, no second evaluator, because these two scenarios are not
# about routing.
#
# THE HOSTILE ONE IS THE GUARD docs/24 MAKES MANDATORY FOR THIS SLICE, and this
# is the only place it is asked over the WHOLE PATH: fetched over plain HTTP from
# an address in the configuration, parsed, evaluated, refused. The unit test
# exercises the evaluator; between the two there is room for a fault neither
# alone would find.
#
# THE BROKEN ONE IS WHERE libproxy IS DELIBERATELY NOT THE ORACLE. Measured
# 2026-09-02: it warns and answers direct://, which is a silent fallback - the
# exact behaviour this product exists to interrupt. So the expectation file says
# oracle_is_authoritative=no and this check does not ask it.
#
# IT GREW A SECOND OPINION AND A LIST OF NAMES ON 2026-09-07, WITH P8-K3e. Three
# scenarios arrived that route on what DNS says rather than on how a name is
# spelled, and for those libproxy IS the oracle and has to be asked - the same
# discipline check_pac_route applies, without the client and the proxy log, which
# proxy-pac-via already holds. A file naming pac_expect is asked live; a file
# naming oracle_libproxy_says instead has its answer PRINTED and not compared,
# which is how a scenario says the two engines are answering different questions.
check_pac_file() {
  local name="$1"
  local file="$expected/$name.txt"
  local target pac_url want_status want_reason want_result must_not_say forbidden

  target="$(value "$file" target)"
  pac_url="$(value "$file" pac_url)"
  want_status="$(value "$file" l2_status)"
  want_reason="$(value "$file" l2_reason)"
  want_result="$(value "$file" l2_pac_result)"
  must_not_say="$(value "$file" l2_must_not_say)"

  say() {
    echo "    DIFFERS: $1"
    failed=$((failed + 1))
  }

  echo "  pac scenario $name  ->  $pac_url"

  # THE SECOND OPINION COMES FIRST, exactly as it does in check_pac_route: it
  # says what the PAC MEANS, and it has not been told anything about what
  # certdoctor is going to say. When it disagrees with the expectation the first
  # suspect is the PAC file or our reading of it, not the product.
  local want_oracle got_oracle recorded
  want_oracle="$(value "$file" pac_expect)"
  recorded="$(value "$file" oracle_libproxy_says)"
  if [ -n "$want_oracle" ]; then
    got_oracle="$(oracle_answer "$name")"
    if [ -z "$got_oracle" ]; then
      echo "    NOT CHECKED: there was no second opinion this run - libproxy was not available."
      echo "        The rest of this scenario still runs, but nothing independent read this PAC."
      notes=$((notes + 1))
    else
      echo "    libproxy says: $(value "$file" pac_host) -> $got_oracle"
      [ "$got_oracle" = "$want_oracle" ] || say "libproxy reads this PAC as $got_oracle, and expected/ says $want_oracle"
    fi
  elif [ -n "$recorded" ]; then
    # 🔴 PRINTED RATHER THAN COMPARED, AND THE FILE SAYS WHY. For lookups.pac the
    # two engines are not disagreeing - libproxy has no allowance of its own, so
    # it answers the question "what does this file mean" while certdoctor answers
    # "what may this run rest a verdict on". Comparing them would fail this bench
    # for the product working.
    echo "    libproxy says: $recorded - recorded, NOT compared (oracle_is_authoritative=$(value "$file" oracle_is_authoritative))"
  fi

  local doc said_status said_reason said_answer
  doc="$("$binary" "$target" --pac-url "$pac_url" --json 2>/dev/null)"
  if [ -z "$doc" ]; then
    say "certdoctor produced no document at all for this PAC"
    return
  fi

  said_status="$(echo "$doc" | jq -r '.layers[] | select(.id=="L2") | .status' 2>/dev/null)"
  said_reason="$(echo "$doc" | jq -r '.layers[] | select(.id=="L2") | .reason // ""' 2>/dev/null)"
  said_answer="$(echo "$doc" | jq -r '[.layers[] | select(.id=="L2") | .findings[]?
    | select(.pac_script != null) | .pac_script.answer] | first // ""' 2>/dev/null)"

  [ -z "$want_status" ] || [ "$said_status" = "$want_status" ] || say "L2 answered $said_status where the bench expects $want_status"
  [ -z "$want_reason" ] || [ "$said_reason" = "$want_reason" ] || say "L2 gave the reason ${said_reason:-none} where the bench expects $want_reason"
  [ -z "$want_result" ] || [ "$said_answer" = "$want_result" ] || say "the script answered $said_answer where the bench expects $want_result"

  # THE ONE ANSWER THAT MUST NEVER COME OUT OF A BROKEN PAC. It is what libproxy
  # says, it is what most software does, and it would make certdoctor agree with
  # the machine's own silence instead of breaking it.
  if [ -n "$must_not_say" ]; then
    case "$doc" in
      *"\"kind\": \"$must_not_say\""*) say "the report names $must_not_say for a PAC that will not parse" ;;
    esac
  fi

  # EVERY LEAK NAME THE HOSTILE FILE CAN RETURN. Each is a directive it produces
  # only if the matching global was reachable, so any one of them in the document
  # is the sandbox failing loudly - which is why that file answers instead of
  # throwing.
  local leaks phrase leaked=0
  leaks="$(value "$file" leak_forbidden),$(value "$file" leak_forbidden_2)"
  if [ "$leaks" != "," ]; then
    for phrase in $(echo "$leaks" | tr ',' ' '); do
      [ -n "$phrase" ] || continue
      case "$doc" in
        *"$phrase"*) say "the sandbox LEAKED: the script reported $phrase"; leaked=1 ;;
      esac
    done
    if [ "$leaked" -eq 0 ]; then
      echo "    sandbox:    no host object reached the script - $(echo "$leaks" | tr ',' ' ' | wc -w) probes, none found"
    fi
  fi

  # --- THE NAMES THAT LEFT THIS MACHINE - P8-K3e ---
  #
  # 🔴 THIS IS THE ONE THING NO OTHER WITNESS ON THIS BENCH CAN SEE. libproxy
  # says what the file MEANS and the proxy log says where a request WENT, and
  # neither of them can say which names a script sent to a resolver while it
  # decided. ADR93 part 4 says that channel is invisible to every guard in the
  # program by construction - the resolver is in the allowed set, so a hostile
  # file chooses not a destination but a QUESTION - and that printing it is the
  # only honest answer. So this is where the printing is checked.
  #
  # AN EMPTY LIST AND A MISSING ONE ARE BOTH REPORTED AS "(none)" HERE, which is
  # coarser than the document is - ADR20 keeps null and [] apart and the JSON
  # renderer honours it. The distinction is exercised by the unit tests; what a
  # bench can add is that the names are the RIGHT ones, in the right order, on a
  # real network.
  local want_asked want_asked_max want_caveat said_asked said_asked_n
  want_asked="$(value "$file" l2_asked)"
  want_asked_max="$(value "$file" l2_asked_fewer_than)"
  want_caveat="$(value "$file" l2_caveat_says)"

  if [ -n "$want_asked" ] || [ -n "$want_asked_max" ]; then
    said_asked="$(echo "$doc" | jq -r '[.layers[] | select(.id=="L2") | .findings[]?
      | select(.pac_script != null) | .pac_script.asked] | first
      | if . == null then "(none)" else join(",") end' 2>/dev/null)"
    said_asked_n="$(echo "$doc" | jq -r '[.layers[] | select(.id=="L2") | .findings[]?
      | select(.pac_script != null) | .pac_script.asked] | first
      | if . == null then 0 else length end' 2>/dev/null)"
    [ -n "$said_asked_n" ] || said_asked_n=0
    echo "    asked:      ${said_asked:-(none)}"
  fi

  # THE EXACT LIST, ORDER INCLUDED. The order is the order of FIRST asking, so a
  # name appearing twice in the file and once here is the cache doing what ADR93
  # part 3 calls part of the ceiling rather than an optimisation.
  if [ -n "$want_asked" ] && [ "$said_asked" != "$want_asked" ]; then
    say "the script asked a resolver about ${said_asked:-(none)} where the bench expects $want_asked"
  fi

  # THE BOUND, AND IT NAMES THE FILE'S NUMBER RATHER THAN OURS. Zero fails it as
  # surely as six does: a run that asked about nothing has not exercised a
  # ceiling, it has exercised a missing resolver, and those are the two states
  # this whole slice exists to keep apart.
  if [ -n "$want_asked_max" ]; then
    if [ "$said_asked_n" -ge "$want_asked_max" ]; then
      say "the script got $said_asked_n name(s) resolved where the bench expects fewer than $want_asked_max"
    elif [ "$said_asked_n" -eq 0 ]; then
      say "the script got no name resolved at all, which is a missing resolver rather than a spent allowance"
    fi
  fi

  # THE SENTENCE THAT MAKES THE VERDICT READABLE. Without it an UNKNOWN looks
  # arbitrary, which is the fault OBS133 found on the terminal in this same
  # slice - and a caveat reaching only the JSON was how it hid.
  if [ -n "$want_caveat" ]; then
    if ! echo "$doc" | jq -e --arg p "$want_caveat" '[.layers[] | select(.id=="L2") | .findings[]?
      | select(.pac_script != null) | .pac_script.caveats[]?] | any(contains($p))' >/dev/null 2>&1; then
      say "no caveat on the script row says \"$want_caveat\", so the verdict above has no stated reason"
    fi
  fi

  echo "    certdoctor: L2 $said_status${said_reason:+ $said_reason}${said_answer:+, script said \"$said_answer\"}"
  passed=$((passed + 1))
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

# THE TWO SCENARIOS THAT ARE NOT ABOUT ROUTING. One asks whether a file that will
# not parse is reported rather than quietly routed; the other is the guard docs/24
# makes mandatory for this slice, asked over the whole path rather than in a unit
# test.
check_pac_file pac-broken
echo
check_pac_file pac-hostile
echo

# THE THREE SCENARIOS THAT ARE ABOUT THE RESOLVER BEHIND THE HELPERS - P8-K3e,
# and the gap OBS134 named the day that slice closed.
#
# 🔴 EVERY OTHER PAC FILE ON THIS BENCH DECIDES BY TEXT ALONE, which is the
# measurement ADR91 rested on and the reason the resolver could be left unwired
# for a whole slice. It also meant this bench could not tell a run WITH a
# resolver from a run without one, so ADR93 shipped checked by unit tests and by
# the owner's own machine and by no independent witness at all.
#
# THE FIRST TWO ARE A PAIR AND ONLY MEAN ANYTHING AS ONE. Same file, same rule,
# two names from one zone that differ in nothing a PAC file can read as text -
# so an answer that differs between them was caused by an address.
#
# 🔴 THEY RUN AFTER check_proxy_env BECAUSE THAT CHECK BRACKETS ITS OWN RUN WITH
# A LINE COUNT OF THE PROXY LOG, AND ONE OF THESE THREE DOES MOVE THAT COUNT.
# The first draft of this comment claimed they add nothing, which was written
# from "they drive no client" and was FALSE - measured 2026-09-08, one run each:
#
#   resolve.pac via   log grew by 1    challenge rows 1, of which asked 1
#   resolve.pac gw    log grew by 0    challenge rows 0
#   lookups.pac       log grew by 0    challenge rows 0
#
# They drive no client of their own - the routing witness is proxy-pac-via's and
# is not repeated here. But certdoctor's own run asks a proxy it was told about
# whether it wants credentials, which since P8-K3c is a real request that squid
# writes a real line for, so the scenario whose script names a proxy adds exactly
# one. The other two name none: gw takes the DIRECT branch, and lookups did not
# settle, so there is no endpoint to ask about.
#
# THE ORDERING IS THEREFORE LOAD BEARING RATHER THAN TIDY. Run before
# check_proxy_env these would sit inside somebody else's arithmetic - and that
# arithmetic is the witness OBS127 narrowed on purpose, so breaking it would cost
# a claim rather than a line of output.
check_pac_file pac-resolve-via
echo
check_pac_file pac-resolve-gw
echo
check_pac_file pac-lookups
echo

# THE SCENARIO THAT ASKS THE CALENDAR - P8-K3f, and the same gap one helper
# family along.
#
# 🔴 THE DAY BEFORE THIS WENT IN, THIS FILE WOULD HAVE BEEN CALLED BROKEN.
# Ports.Now was never wired in production, so the three time helpers threw and
# the layer graded a legal file malformed with the reason it keeps for one that
# will not parse. No PAC file on this bench asked the clock, so nothing here
# could see it - which is exactly what OBS134 said about the resolver.
check_pac_file pac-clock

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
  # proxy-env LEFT THIS LIST ON 2026-09-06, and it is the first one to. Its L2
  # keys are checked by claim 4 of check_proxy_env above, because everything they
  # name - which place holds the proxy, which entry applies, what the exception
  # list says - is read from this machine's own configuration and needs no
  # network. The scenarios below still need a PAC file fetched and a proxy asked,
  # which is work that opens a connection.
  case "$(basename "$file" .txt)" in
    # proxy-env LEFT ON 2026-09-06 with the layer. THE FOUR AFTER IT LEFT THE
    # SAME DAY with --pac-url, which is what made the layer able to see a script
    # on a machine that does not name one - and this bench is such a machine.
    #
    # proxy-auth LEFT ON 2026-09-07 WITH P8-K3c, AND IT IS THE LAST ONE. Its keys
    # needed a proxy to be ASKED rather than only read, which is the work that
    # slice added - so this list has now emptied itself exactly as the paragraph
    # above said it would. THE BLOCK STAYS: it is self-building, so the next
    # scenario written before its reader exists lands on it without anybody
    # having to remember this file.
    #
    # THE THREE ADDED ON 2026-09-07 WITH P8-K3e WERE NEVER ON THIS LIST, and
    # that is worth one line rather than none: they are the first expectations on
    # this bench written for a reader that already existed. Every scenario above
    # them was written before its layer and waited here; these were written the
    # day after ADR93, to check something that had shipped without a witness.
    proxy-env | proxy-pac-via | proxy-pac-direct | pac-broken | pac-hostile | proxy-auth) continue ;;
    pac-resolve-via | pac-resolve-gw | pac-lookups | pac-clock) continue ;;
  esac
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
