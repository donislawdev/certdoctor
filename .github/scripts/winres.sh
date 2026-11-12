#!/usr/bin/env bash
# Make the Windows resources of both binaries: the icon, and what the Details
# tab of the file's properties says - who made it, what it is, which version.
#
#   bash .github/scripts/winres.sh            writes them beside each main package
#   bash .github/scripts/winres.sh <dir>      writes them under <dir> instead
#
# Run from the root of the repository. CI runs it with a directory and asks
# for the same bytes as the committed files, so a resource that drifted from
# its description, its icon or the version is found by the build.
#
# THE RESOURCES ARE COMMITTED, NOT BUILT, because the Go toolchain links every
# rsrc_windows_<arch>.syso it finds in a main package by the name alone and
# runs no generator of its own. The name carries GOOS and GOARCH, so other
# platforms leave the file alone. The command line still builds with CGO off
# and nothing beyond Go.
#
# THE VERSION IS NOT WRITTEN IN winres.json. It is read here from
# certdoctor.go, the one place it lives and the only place the owner sets it,
# and handed to go-winres, which puts it in the fixed version and in both
# version strings. A copy in the JSON would be a second place to forget.
#
# WHICH BINARY FOR WHICH ARCHITECTURE follows the release (ADR116, D21): the
# command line ships for amd64 and arm64, the window for amd64 only.
#
# go-winres v0.3.3 is the newest release, published 2024-04-11 per the GitHub
# releases API, read 2026-10-27, 0BSD. It is a build tool, run by hand or in
# CI and never linked. No manifest: a manifest changes how Windows runs a
# program, and the JSON files name none.
set -euo pipefail
export LC_ALL=C

winres="github.com/tc-hib/go-winres@v0.3.3"

die() { echo "winres: $*" >&2; exit 1; }

[ -f certdoctor.go ] || die "certdoctor.go is not here - run this from the root of the repository"

version="$(sed -n 's/^const Version = "\(.*\)"$/\1/p' certdoctor.go)"
[ -n "$version" ] || die "certdoctor.go has no line const Version = \"...\", so there is no version to write"
[ "$(printf '%s\n' "$version" | wc -l)" -eq 1 ] || die "certdoctor.go has more than one const Version line"

out="${1:-}"

# make_one <main package> <architectures>
make_one() {
  local package="$1" arches="$2" target="$1"
  [ -f "$package/winres.json" ] || die "$package/winres.json is not here"
  if [ -n "$out" ]; then
    target="$out/$package"
    mkdir -p "$target"
  fi
  go run "$winres" make --in "$package/winres.json" --arch "$arches" --out "$target/rsrc" \
    --product-version "$version" --file-version "$version"
  echo "winres: $package for $arches, version $version"
}

make_one cmd/certdoctor amd64,arm64
make_one cmd/certdoctor-gui amd64
