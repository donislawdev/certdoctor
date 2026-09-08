#!/bin/sh
#
# The independent PAC evaluator - slice P4c. Started by verify.sh, in a container
# of its own, BEFORE the comparison run.
#
# WHY A SEPARATE CONTAINER AND NOT A FEW LINES INSIDE verify-inside.sh. The
# verification container's resolver is the bench, and the bench answers NXDOMAIN
# for every name it does not own - deliberately, so that a run behaves the same
# on a train as in CI. Nothing can be installed there. This container keeps its
# own resolver and is handed the bench's address for the PAC server explicitly,
# so it can fetch a package AND reach the bench, while the bench has no way to
# influence what it concludes.
#
# WHAT IT IS FOR. docs/21 section 2 wants an oracle that shares no code with the
# thing under test. libproxy is somebody else's implementation of the same twelve
# PAC helper functions ADR10 requires certdoctor to write for itself, so asking
# it the same question about the same bytes is the strongest independent check
# available for what a PAC file MEANS.
#
# MEASURED BEFORE IT WAS TRUSTED, 2026-09-02, libproxy 0.5.12: it distinguishes
# three branches of one file - shExpMatch to DIRECT, dnsDomainIs to a proxy, an
# exact host to another proxy - so it is evaluating rather than echoing.
#
# 🔴 WHERE IT IS NOT AN ORACLE, AND THE BENCH SAYS SO RATHER THAN FINDING OUT
# LATER. On a PAC that will not parse, libproxy warns and then answers direct://.
# That silent fallback is the opposite of this product's contract. Files that
# record it say oracle_is_authoritative=no, and this script never compares those.
#
# 🔴 IT INSTALLS FIRST AND SWITCHES ITS RESOLVER TO THE BENCH SECOND - added
# 2026-09-07 with P8-K3e, and until then this script did not need a resolver at
# all. Every PAC file on this bench decided by text alone, which is the
# measurement ADR91 rested on when it left pac.Ports.Resolve unwired. ADR93 wired
# it, and resolve.pac and lookups.pac now route on what DNS says - so an oracle
# asking Docker's resolver while the run asks the bench would read a DIFFERENT
# WORLD, and the difference would look like a difference in PAC semantics rather
# than in whose resolver answered.
#
# The two orders cannot be swapped: the package comes from the internet, and the
# bench answers NXDOMAIN for everything it does not own. So the package is
# fetched with the resolver this container started with, and only then is the
# file rewritten. Measured 2026-09-07, probe S17: the write goes through, musl
# reads the file per lookup so no restart is needed, and curl still reaches the
# PAC server afterwards.
set -o pipefail

expected=/w/expected
out=/w/oracle-pac.txt
work=/tmp/pac

mkdir -p "$work"
: > "$out"

value() {
  grep -E "^$2=" "$1" 2>/dev/null | head -1 | cut -d= -f2-
}

echo "oracle: installing libproxy, the second opinion"
if ! apk add -q libproxy-bin 2>&1; then
  echo "oracle: libproxy could not be installed, so there is NO second opinion this run."
  echo "oracle: that is a missing witness, not a passing one - verify-inside.sh will say so."
  echo "unavailable=libproxy could not be installed" >> "$out"
  exit 0
fi
echo "oracle: $(apk info -e libproxy-bin) - $(command -v proxy)"

# THE SWITCH, AND IT IS CHECKED RATHER THAN ASSUMED. gw.proxy.test exists only in
# the bench's zone file - verify.sh hands this container an /etc/hosts entry for
# pac.proxy.test and for nothing else - so resolving it is proof that the queries
# are now going to the bench and not to the resolver this container started with.
#
# 🔴 A FAILED SWITCH STOPS THE ORACLE RATHER THAN DEGRADING IT, and that is the
# one place this script is allowed to be conservative. It cannot tell which of
# the questions below depend on DNS, because it does not read the PAC files - so
# a run where the switch did not take would mix answers from two worlds and
# nothing downstream could separate them. A missing witness is reported as
# missing and costs the run some coverage. A witness answering about a different
# world costs the run its meaning.
printf 'nameserver 172.28.0.53\n' > /etc/resolv.conf 2>/dev/null
if getent hosts gw.proxy.test >/dev/null 2>&1; then
  echo "oracle: resolver switched to the bench - gw.proxy.test resolves here now"
else
  echo "oracle: the resolver could NOT be switched to the bench, so every answer below"
  echo "oracle: would be about a different world than the run's. There is NO second"
  echo "oracle: opinion this run - verify-inside.sh will say so."
  echo "unavailable=the oracle's resolver could not be pointed at the bench" >> "$out"
  exit 0
fi

# THE LIST BUILDS ITSELF FROM THE EXPECTATIONS. Any file naming a pac_url and a
# pac_host contributes one question. So a scenario added later cannot be
# forgotten here, and this script cannot go stale by naming names of its own.
for file in "$expected"/*.txt; do
  [ -e "$file" ] || continue

  url="$(value "$file" pac_url)"
  host="$(value "$file" pac_host)"
  [ -n "$url" ] || continue
  [ -n "$host" ] || continue

  name="$(basename "$file" .txt)"
  local_pac="$work/$name.pac"

  # THE BYTES THE BENCH IS SERVING, NOT THE BYTES IN THE WORKING TREE. Those two
  # have come apart on this bench three times already - OBS64, OBS75 - and a PAC
  # file read from the tree while the server hands out an older one would make
  # the oracle agree with a bench nobody is running.
  if ! curl -sf -o "$local_pac" "$url"; then
    echo "$name|$host|FETCH-FAILED|$url" >> "$out"
    echo "oracle: could not fetch $url"
    continue
  fi

  # pac+file rather than pac+http ON PURPOSE. libproxy has its own downloader and
  # its own idea of when it is online - measured 2026-09-02, it declined a URL it
  # should have fetched - and none of that has anything to do with what the PAC
  # MEANS. Fetching with curl first takes the downloader out of the question and
  # leaves the evaluator, which is the part being asked.
  answer="$(http_proxy="pac+file://$local_pac" proxy "http://$host/" 2>/dev/null | tail -1)"
  [ -n "$answer" ] || answer="NO-ANSWER"

  echo "$name|$host|$answer|$url" >> "$out"
  printf "oracle: %-20s %-24s -> %s\n" "$name" "$host" "$answer"
done

echo "oracle: wrote $(grep -c '|' "$out" 2>/dev/null || echo 0) answer(s) for the run to compare against"
