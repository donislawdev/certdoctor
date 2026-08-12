#!/usr/bin/env bash
#
# Runs certdoctor against the DNS bench and compares what it said with the
# verdicts written in expected/ BEFORE it was ever pointed here.
#
# WHY certdoctor RUNS IN A CONTAINER RATHER THAN ON THIS MACHINE. It asks the
# resolvers a machine is CONFIGURED to use and has no switch for "ask that one" -
# by design, because inviolable rule 16 says a run reaches only what it was
# pointed at. A container whose resolv.conf names the bench is therefore the only
# honest way to aim it, and it happens to be the shape a user in a container has
# anyway.
#
# WHY netshoot RATHER THAN alpine. It carries dig and jq, and dig is the second
# half of the oracle: docs/21 asks for a REFERENCE TOOL independent of our code,
# because two runs of our own code prove nothing beyond the first.
#
# THIS SCRIPT DOES NOT SAY WHETHER certdoctor IS CORRECT ABOUT THE WORLD. It says
# whether it agrees with a bench that knows the truth, because the bench made the
# truth up: the zone file decides what these names resolve to.
set -o pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"

if ! docker compose -f "$here/compose.yml" ps --status running 2>/dev/null | grep -q dns; then
  echo "testbed: the DNS bench is not running."
  echo "testbed: start it with  docker compose -f testbed/compose.yml up -d"
  exit 1
fi

workspace="$(mktemp -d)"
trap 'rm -rf "$workspace"' EXIT

echo "testbed: building the binary this bench will question"
if ! (cd "$repo" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$workspace/certdoctor" ./cmd/certdoctor/); then
  echo "testbed: the binary would not build, so nothing could be established."
  exit 1
fi

cp "$here/verify-inside.sh" "$workspace/verify-inside.sh"
cp -r "$here/expected" "$workspace/expected"
chmod +x "$workspace/certdoctor" "$workspace/verify-inside.sh"

# TWO DIFFERENT PATH PROBLEMS ON ONE LINE, AND THEY PULL IN OPPOSITE DIRECTIONS.
#
# The HOST side has to be a path the Docker daemon can resolve. Under Git Bash
# mktemp hands back something like /tmp/tmp.abc, which is a real directory to
# this shell and nothing at all to a daemon that thinks in Windows paths - so it
# is converted when cygpath is there and left alone everywhere else.
#
# The CONTAINER side has to survive Git Bash NOT rewriting it: /w is a container
# path, and the shell would happily turn it into C:/Program Files/Git/w. That is
# what MSYS_NO_PATHCONV switches off, and it is the same trap docs/17 section 6d
# records for a mounted Corefile.
mount="$workspace"
if command -v cygpath >/dev/null 2>&1; then
  mount="$(cygpath -m "$workspace")"
fi

MSYS_NO_PATHCONV=1 docker run --rm \
  --network certdoctor-testbed_testbed \
  --dns 172.28.0.53 \
  -v "$mount:/w" \
  nicolaka/netshoot \
  /w/verify-inside.sh
