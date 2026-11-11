#!/usr/bin/env bash
# Build the window, certdoctor-gui, on the system it is for.
#
#   bash .github/scripts/build_window.sh <goos>/<goarch> <empty directory outside the checkout>
#
# Run from the root of a clean checkout, on a machine of the target it is asked
# for. The release workflow runs it on three runners, one for each target D21
# ships the window for, and hands what it leaves to build_release.sh, which
# packs it with the command line.
#
# What it leaves in the directory it is given:
#
#   certdoctor-gui         Linux and macOS
#   certdoctor-gui.exe     Windows
#   opengl/                Windows only - the software renderer, fetched and
#                          checked by fetch_software_renderer.sh
#
# WHY ON THE MACHINE IT IS FOR, AND NOT CROSS COMPILED LIKE THE COMMAND LINE.
# The window reaches OpenGL and the windowing system through C - the GLFW
# library the toolkit compiles in - so it is built with cgo, and cgo builds for
# the system the C compiler is for. The command line has no C in it and is
# built for all five of its targets on one runner.
#
# NOTHING IS WRITTEN INSIDE THE CHECKOUT, for the reason build_release.sh gives:
# the binary records whether the tree had changes, an untracked file counts,
# and the bill of materials refuses a build of no commit.
set -euo pipefail

die() { echo "build_window: $*" >&2; exit 1; }

if [ "$#" -ne 2 ]; then
  echo "usage: build_window.sh <goos>/<goarch> <empty directory outside the checkout>" >&2
  exit 2
fi
target="$1"
out="$2"

if [ ! -f go.mod ] || [ ! -d cmd/certdoctor-gui ]; then
  die "run this from the root of the repository"
fi

# Asked of the toolchain on this machine, because that is what the binary will
# be built for. A runner that is not the one the workflow names would build a
# window for another system under this one's name.
here="$(go env GOOS)/$(go env GOARCH)"
[ "$here" = "$target" ] || die "this machine builds for $here, and it was asked for $target"

if [ -n "$(git status --porcelain)" ]; then
  git status --short >&2
  die "the checkout has changes that are not committed, and a build from it
records a commit that does not describe it. The bill of materials refuses such a
build. Commit them, or build from a clean clone."
fi

mkdir -p "$out"
root="$(pwd -P)"
out="$(cd "$out" && pwd -P)"
case "$out/" in
  "$root/"*) die "$out is inside the checkout, and every file written there makes the
build a build of no commit. Give a directory outside it." ;;
esac
if [ -n "$(ls -A "$out")" ]; then
  die "$out is not empty. What is in it would be packed with this release."
fi

binary="certdoctor-gui"
flags=(-trimpath)
if [ "${target%/*}" = "windows" ]; then
  binary="certdoctor-gui.exe"
  # A program for the Windows subsystem rather than the console one. Without
  # it Windows opens a console window behind the window, and keeps it for as
  # long as the window is open.
  flags+=(-ldflags=-H=windowsgui)
fi

# CGO_ENABLED=1 named rather than left to the default, because the default is
# 0 wherever no C compiler is found, and a window built without cgo starts,
# says it cannot open and ends (cmd/certdoctor-gui/run_nocgo.go).
CGO_ENABLED=1 go build "${flags[@]}" -o "$out/$binary" ./cmd/certdoctor-gui

# What the toolchain was told and what it recorded, read back out of the
# binary rather than trusted from the line above.
info="$(go version -m "$out/$binary")"
printf '%s\n' "$info" | grep -qE '^[[:space:]]+path[[:space:]]+github\.com/donislawdev/certdoctor/cmd/certdoctor-gui$' ||
  die "$binary is not a build of cmd/certdoctor-gui"
for want in "CGO_ENABLED=1" "vcs.modified=false" "GOOS=${target%/*}" "GOARCH=${target#*/}"; do
  printf '%s\n' "$info" | grep -qE -- "[[:space:]]${want}$" || die "$binary does not record $want"
done
if [ "${target%/*}" = "windows" ]; then
  printf '%s\n' "$info" | grep -qF -- "-ldflags=-H=windowsgui" || die "$binary does not record -H=windowsgui"
fi
echo "built $binary for $target"

# The software renderer beside it, on Windows alone: Linux has Mesa in the
# system, and macOS has never offered the toolkit less OpenGL than it needs.
# Here rather than in the step that packs the archives, because 7z, which reads
# the archive Mesa is published in, is on the Windows runner (ADR125 point 5).
if [ "${target%/*}" = "windows" ]; then
  bash .github/scripts/fetch_software_renderer.sh "$out"
fi

ls -l "$out"
