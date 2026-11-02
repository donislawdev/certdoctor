#!/usr/bin/env bash
# Build every release target from this checkout, write the bill of materials
# over the five binaries, and pack each one with the files that travel with it.
#
#   bash .github/scripts/build_release.sh <version> <directory outside the checkout>
#
# Run from the root of a clean checkout. The release workflow runs exactly this,
# and so can anybody with Go and a Unix shell, which is the reason it is a
# script rather than lines in a workflow: a build that only a tag can start is a
# build nobody tries before the tag.
#
# What it leaves in the directory it is given:
#
#   dist/certdoctor_<version>_<os>_<arch>.zip      Windows
#   dist/certdoctor_<version>_<os>_<arch>.tar.gz   Linux and macOS
#   dist/verify-certdoctor_<version>.spdx.json     the bill of materials
#   work/                                          the binaries and what was packed
#
# NOTHING IS WRITTEN INSIDE THE CHECKOUT, and that is a rule rather than tidiness.
# Go records in every binary whether the tree it was built from had changes that
# are not committed, and cmd/sbom refuses a build that says it had - an untracked
# file counts. So an archive written into the checkout after the first build
# would make the second one a build of no commit, and the bill of materials
# would refuse the release.
set -euo pipefail

die() { echo "build_release: $*" >&2; exit 1; }

if [ "$#" -ne 2 ]; then
  echo "usage: build_release.sh <version> <directory outside the checkout>" >&2
  exit 2
fi
version="$1"
out="$2"

if [ ! -f go.mod ] || [ ! -d cmd/certdoctor ]; then
  die "run this from the root of the repository"
fi

# The five builds ADR116 decision 2 ships, and the one list of them in this
# repository that a build reads. internal/guard holds this list, the CI matrix
# and the list the notices are checked against to the same five.
#
# No darwin/amd64: Intel Macs are not supported, so nothing is built for them
# and nothing pretends to be.
targets=(
  windows/amd64
  windows/arm64
  linux/amd64
  linux/arm64
  darwin/arm64
)

# Asked before anything is built, because the bill of materials asks it after,
# and a refusal at the end of a build reads like a fault in the build.
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
next build a build of no commit. Give a directory outside it." ;;
esac
if [ -n "$(ls -A "$out")" ]; then
  die "$out is not empty. What is in it would be packed or published with this release."
fi
dist="$out/dist"
work="$out/work"
mkdir -p "$dist" "$work/build" "$work/package"

# Go calls it darwin and almost nobody else does. The name on a download is
# read by somebody deciding whether it is the file for their machine, so the
# label says macos. The compiler is still told darwin.
label_of() {
  case "$1" in
    darwin) echo "macos" ;;
    *) echo "$1" ;;
  esac
}

binaries=()
for target in "${targets[@]}"; do
  os="${target%/*}"
  arch="${target#*/}"
  binary="certdoctor"
  if [ "$os" = "windows" ]; then
    binary="certdoctor.exe"
  fi
  built="$work/build/${os}_${arch}/${binary}"

  # CGO_ENABLED=0 so the binary is static and runs in a container with no C
  # library at all. -trimpath keeps the build machine's directory names out of
  # a file that is published.
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -o "$built" ./cmd/certdoctor

  # What the toolchain was told, read back out of the binary rather than
  # trusted from the line above.
  if ! go version -m "$built" | grep -q 'CGO_ENABLED=0'; then
    die "$target does not record CGO_ENABLED=0, so it is not the static build a container needs"
  fi
  binaries+=("$built")
  echo "built $target"
done

# The one build this machine can start, started. Everything above proves the
# binaries were made, and nothing above proves one of them runs.
host="$(go env GOHOSTOS)_$(go env GOHOSTARCH)"
for built in "${binaries[@]}"; do
  case "$built" in
    "$work/build/${host}/"*)
      said="$("$built" --version | head -n 1)"
      [ "$said" = "certdoctor: ${version}" ] ||
        die "the ${host} build says \"${said}\", and this release is ${version}"
      echo "the ${host} build starts and says ${said}"
      ;;
  esac
done

# Written from the five binaries at once, so the document describes what was
# built rather than what the tree says would be. cmd/sbom refuses when a build
# links a module, a version or a toolchain THIRD-PARTY-NOTICES.md does not
# name, and prints every disagreement.
#
# verify- rather than certdoctor-, because GitHub lists a release's downloads by
# file name and by nothing else. The prefix puts the files a person checks a
# download with together at the end, under the archives they check.
go version -m "${binaries[@]}" | go run ./cmd/sbom > "$dist/verify-certdoctor_${version}.spdx.json"

for target in "${targets[@]}"; do
  os="${target%/*}"
  arch="${target#*/}"
  base="certdoctor_${version}_$(label_of "$os")_${arch}"
  pack="$work/package/$base"
  mkdir -p "$pack"

  binary="certdoctor"
  if [ "$os" = "windows" ]; then
    binary="certdoctor.exe"
  fi
  cp "$work/build/${os}_${arch}/${binary}" "$pack/${binary}"

  # macOS gets a bundle, and it is not decoration: a bare binary cannot carry a
  # notarisation ticket, so Gatekeeper refuses it even signed and notarised. A
  # link goes beside it, so a person still types ./certdoctor.
  if [ "$os" = "darwin" ]; then
    bash .github/scripts/make_app_bundle.sh "$pack" "$binary" "com.donislawdev.certdoctor" "$version"
  fi

  # The notices travel with the binary because the licences in them ask for
  # it, and they are also inside the binary, for the copy that leaves the
  # archive. The licence and the readme are for the person who downloaded an
  # archive and nothing else.
  cp LICENSE THIRD-PARTY-NOTICES.md README.md "$pack/"

  if [ "$os" = "windows" ]; then
    (cd "$pack" && zip -q -r -X "$dist/${base}.zip" .)
    listed="$(unzip -Z1 "$dist/${base}.zip")"
  else
    tar -czf "$dist/${base}.tar.gz" -C "$pack" .
    listed="$(tar -tzf "$dist/${base}.tar.gz" | sed 's#^\./##')"
  fi

  # What went in is asked of the archive, not of the directory it was made
  # from, because the archive is what a person gets.
  wanted=(LICENSE THIRD-PARTY-NOTICES.md README.md "$binary")
  if [ "$os" = "darwin" ]; then
    wanted+=("${binary}.app/Contents/MacOS/${binary}" "${binary}.app/Contents/Info.plist")
  fi
  for name in "${wanted[@]}"; do
    printf '%s\n' "$listed" | grep -qxF -- "$name" || die "${base} does not carry ${name}"
  done
  echo "packed ${base}"
done

ls -l "$dist"
