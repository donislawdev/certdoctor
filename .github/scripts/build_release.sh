#!/usr/bin/env bash
# Build every release target of the command line from this checkout, take the
# window's builds the three runners made, write one bill of materials over all
# eight binaries, and pack each with the files that travel with it.
#
#   bash .github/scripts/build_release.sh <version> <directory outside the checkout> <window builds>
#
# <window builds> is the directory the release workflow downloads the window
# job's builds into: one directory for each target, certdoctor-gui_<os>_<arch>,
# each holding what .github/scripts/build_window.sh left on that runner. The
# window is built with cgo on the system it is for (that script says why) and
# packed here, so the command line in the window's archive is the very file the
# command line's archive carries, and every archive is checked in one place.
#
# Without it this makes the five archives of the command line and nothing
# else, and says that this is not a release - the window ships with every
# release since D21. The release workflow always gives it, and a guard in
# internal/guard holds the workflow to that.
#
# Run from the root of a clean checkout. The release workflow runs exactly this,
# and so can anybody with Go and a Unix shell, which is the reason it is a
# script rather than lines in a workflow: a build that only a tag can start is a
# build nobody tries before the tag.
#
# What it leaves in the directory it is given:
#
#   dist/certdoctor_<version>_<os>_<arch>.zip          the command line, Windows
#   dist/certdoctor_<version>_<os>_<arch>.tar.gz       the command line, Linux and macOS
#   dist/certdoctor-gui_<version>_<os>_<arch>.zip      the window, Windows
#   dist/certdoctor-gui_<version>_<os>_<arch>.tar.gz   the window, Linux and macOS
#   dist/verify-certdoctor_<version>.spdx.json         the bill of materials of both
#   work/                                              the binaries and what was packed
#
# NOTHING IS WRITTEN INSIDE THE CHECKOUT, and that is a rule rather than tidiness.
# Go records in every binary whether the tree it was built from had changes that
# are not committed, and cmd/sbom refuses a build that says it had - an untracked
# file counts. So an archive written into the checkout after the first build
# would make the second one a build of no commit, and the bill of materials
# would refuse the release.
set -euo pipefail

die() { echo "build_release: $*" >&2; exit 1; }

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
  echo "usage: build_release.sh <version> <directory outside the checkout> <window builds>" >&2
  exit 2
fi
version="$1"
out="$2"
windows="${3:-}"

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

# The three builds D21 ships the window for, held by the same guard to the
# list the window's notices are checked against and to the matrix of the
# window job in the release workflow. Each is also a target of the command
# line, whose build for it goes into the window's archive.
window_targets=(
  windows/amd64
  linux/amd64
  darwin/arm64
)

if [ -z "$windows" ]; then
  echo "build_release: no window builds were given, so this makes the five archives of the command line" >&2
  echo "and nothing else. That is not a release: every release carries the window as well." >&2
fi

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

# The software renderer's files, by the pin they were fetched by: path in the
# archive, sum and size. The window job checked them against it on the runner,
# and they are checked again here, after the trip through the workflow's
# artefact storage, because these are the bytes that are packed.
renderer=()
while IFS= read -r line; do
  renderer+=("$line")
done < <(grep '^file=' .github/mesa-dist-win | cut -d= -f2-)
[ "${#renderer[@]}" -gt 0 ] || die ".github/mesa-dist-win names no file of the software renderer"

# take_window copies one runner's build of the window into work/, and refuses
# it unless it is exactly what that runner was to leave: the binary built for
# that target with cgo, and on Windows the software renderer beside it, file
# for file as pinned - and nothing else, because what is in the directory is
# what would be packed.
take_window() {
  local os="$1" arch="$2" from to binary expected got info line inside sum size name
  from="$windows/certdoctor-gui_${os}_${arch}"
  to="$work/build/window_${os}_${arch}"
  binary="certdoctor-gui"
  if [ "$os" = "windows" ]; then
    binary="certdoctor-gui.exe"
  fi
  [ -f "$from/$binary" ] || die "$from has no $binary, so there is no window for ${os}/${arch}"

  expected="$binary"
  if [ "$os" = "windows" ]; then
    for line in "${renderer[@]}"; do
      read -r inside sum size <<<"$line"
      expected="$expected"$'\n'"opengl/$(basename "$inside")"
    done
  fi
  got="$(cd "$from" && find . -type f | sed 's#^\./##' | LC_ALL=C sort)"
  expected="$(printf '%s\n' "$expected" | LC_ALL=C sort)"
  [ "$got" = "$expected" ] || die "$from holds
$got
and the window for ${os}/${arch} is
$expected"

  mkdir -p "$to"
  cp -R "$from/." "$to/"
  # A workflow artefact keeps no file modes, so the binary arrives without the
  # bit that lets it run.
  chmod 755 "$to/$binary"

  info="$(go version -m "$to/$binary")"
  printf '%s\n' "$info" | grep -qE '^[[:space:]]+path[[:space:]]+github\.com/donislawdev/certdoctor/cmd/certdoctor-gui$' ||
    die "$from/$binary is not a build of cmd/certdoctor-gui"
  for want in "CGO_ENABLED=1" "GOOS=${os}" "GOARCH=${arch}"; do
    printf '%s\n' "$info" | grep -qE -- "[[:space:]]${want}$" || die "$from/$binary does not record $want"
  done

  if [ "$os" = "windows" ]; then
    for line in "${renderer[@]}"; do
      read -r inside sum size <<<"$line"
      name="$(basename "$inside")"
      (cd "$to/opengl" && echo "${sum}  ${name}" | sha256sum -c - >/dev/null) ||
        die "opengl/${name} from the window job is not the file .github/mesa-dist-win pins"
      [ "$(wc -c < "$to/opengl/$name" | tr -d '[:space:]')" = "$size" ] ||
        die "opengl/${name} from the window job is not $size bytes"
    done
  fi
  echo "took the window for ${os}/${arch}"
}

window_binaries=()
if [ -n "$windows" ]; then
  [ -d "$windows" ] || die "$windows is not a directory of window builds"
  windows="$(cd "$windows" && pwd -P)"
  for target in "${window_targets[@]}"; do
    take_window "${target%/*}" "${target#*/}"
    binary="certdoctor-gui"
    if [ "${target%/*}" = "windows" ]; then
      binary="certdoctor-gui.exe"
    fi
    window_binaries+=("$work/build/window_${target%/*}_${target#*/}/$binary")
  done
fi

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

# Written from every binary at once, so the document describes what was built
# rather than what the tree says would be. cmd/sbom refuses when a build links
# a module, a version or a toolchain the notices of its program do not name,
# or comes from another commit than the rest, and prints every disagreement.
#
# verify- rather than certdoctor-, because GitHub lists a release's downloads by
# file name and by nothing else. The prefix puts the files a person checks a
# download with together at the end, under the archives they check.
go version -m "${binaries[@]}" "${window_binaries[@]}" | go run ./cmd/sbom > "$dist/verify-certdoctor_${version}.spdx.json"

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

# The window's archives: the window, the command line it runs, the software
# renderer on Windows, and the notices of both - THIRD-PARTY-NOTICES.md answers
# for the command line in it, THIRD-PARTY-NOTICES-GUI.md for the window
# (ADR127 decision 4).
for target in "${window_targets[@]}"; do
  [ -n "$windows" ] || break
  os="${target%/*}"
  arch="${target#*/}"
  base="certdoctor-gui_${version}_$(label_of "$os")_${arch}"
  pack="$work/package/$base"
  mkdir -p "$pack"

  window="certdoctor-gui"
  binary="certdoctor"
  if [ "$os" = "windows" ]; then
    window="certdoctor-gui.exe"
    binary="certdoctor.exe"
  fi
  cp "$work/build/window_${os}_${arch}/${window}" "$pack/${window}"
  # The command line's own build for this target - the file its archive
  # carries, rather than a second build of the same thing.
  cp "$work/build/${os}_${arch}/${binary}" "$pack/${binary}"
  if [ "$os" = "windows" ]; then
    cp -R "$work/build/window_${os}_${arch}/opengl" "$pack/opengl"
  fi

  # One bundle with both programs in it, because the window starts certdoctor
  # from its own folder, which on macOS is Contents/MacOS. It has the window's
  # identifier (ADR127 decision 1), and a link to each program beside it.
  if [ "$os" = "darwin" ]; then
    bash .github/scripts/make_app_bundle.sh "$pack" "$window" "com.donislawdev.certdoctor-gui" "$version" "$binary"
  fi

  cp LICENSE THIRD-PARTY-NOTICES.md THIRD-PARTY-NOTICES-GUI.md README.md "$pack/"

  if [ "$os" = "windows" ]; then
    (cd "$pack" && zip -q -r -X "$dist/${base}.zip" .)
    listed="$(unzip -Z1 "$dist/${base}.zip")"
  else
    tar -czf "$dist/${base}.tar.gz" -C "$pack" .
    listed="$(tar -tzf "$dist/${base}.tar.gz" | sed 's#^\./##')"
  fi

  wanted=(LICENSE THIRD-PARTY-NOTICES.md THIRD-PARTY-NOTICES-GUI.md README.md "$window" "$binary")
  if [ "$os" = "windows" ]; then
    for line in "${renderer[@]}"; do
      read -r inside sum size <<<"$line"
      wanted+=("opengl/$(basename "$inside")")
    done
  fi
  if [ "$os" = "darwin" ]; then
    wanted+=("${window}.app/Contents/MacOS/${window}" "${window}.app/Contents/MacOS/${binary}"
      "${window}.app/Contents/Info.plist" "${window}.app/Contents/Resources/icon.icns")
  fi
  for name in "${wanted[@]}"; do
    printf '%s\n' "$listed" | grep -qxF -- "$name" || die "${base} does not carry ${name}"
  done
  echo "packed ${base}"
done

ls -l "$dist"
if [ -z "$windows" ]; then
  echo "build_release: the five archives of the command line and no window - not a release." >&2
fi
