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
# WHY netshoot RATHER THAN alpine. It carries dig, jq, openssl and curl, and the
# first three are the oracle: docs/21 asks for a REFERENCE TOOL independent of
# our code, because two runs of our own code prove nothing beyond the first. curl
# is the fourth and is a different kind of witness - it is the RUNTIME this bench
# makes claims about, so it can be asked whether it behaves as we said it would.
#
# PINNED TO A VERSION, NEVER TO :latest - inviolable rule 23, the same rule
# compose.yml states at every image it pins and the one this line was breaking
# until 2026-08-19. An unpinned tag means the bench a contributor runs and the
# bench CI runs stop being the same bench, and the day one of them answers
# differently there is nothing to compare against.
#
# v0.16 is the newest published tag - checked at
# https://hub.docker.com/v2/repositories/nicolaka/netshoot/tags on 2026-08-19,
# last updated 2026-07-01, the same day as latest. The GitHub repository
# publishes no releases at all, so the registry is the only place a version can
# be read. The image reports Alpine 3.24.1 and curl 8.21.0 on OpenSSL 3.5.7.
#
# WHAT A PINNED TAG STILL DOES NOT GIVE, said here as compose.yml says it: a tag
# is a name and can be re-pushed. Only a digest is immutable. "Pinned" here means
# one declared version, not byte-identical for ever.
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
  nicolaka/netshoot:v0.16 \
  /w/verify-inside.sh
