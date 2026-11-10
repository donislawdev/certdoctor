#!/usr/bin/env bash
# Put the software renderer beside the window binary, for the Windows archive:
# the two files of Mesa's llvmpipe the window loads when the graphics driver
# gives it no OpenGL - a virtual machine without 3D acceleration, a remote
# desktop, a server.
#
#   bash .github/scripts/fetch_software_renderer.sh <directory the window binary is in>
#
# What it leaves is <directory>/opengl with exactly the files .github/mesa-dist-win
# names, and nothing else anywhere. The window asks for them by that path and
# by no other - cmd/certdoctor-gui/software.go.
#
# THE ARCHIVE IS CHECKED BEFORE ANYTHING IS UNPACKED. A download that does not
# match its sum is an archive nobody read, and unpacking it first would put two
# files nobody read next to a program that loads them. After that each file is
# checked on its own, by sum and by size: the archive's sum already covers
# them, and these are the numbers the notices print, so a person can compare
# what is in a release with what was reviewed without downloading the archive.
#
# The version, the sums and the sizes come from .github/mesa-dist-win and
# nowhere else. A guard in internal/guard holds that file to the section of
# THIRD-PARTY-NOTICES-GUI.md that reproduces the licences of these two files.
set -euo pipefail

die() { echo "fetch_software_renderer: $*" >&2; exit 1; }

if [ "$#" -ne 1 ]; then
  echo "usage: fetch_software_renderer.sh <directory the window binary is in>" >&2
  exit 2
fi
into="$1"
pin=".github/mesa-dist-win"
project="pal1000/mesa-dist-win"

[ -f "$pin" ] || die "run this from the root of the repository - there is no $pin here"
[ -d "$into" ] || die "$into is not a directory"

# One value for a key, or a refusal. A key given twice would let the line a
# reviewer read and the line this script used be different lines.
value_of() {
  local key="$1" found
  found="$(grep -c "^${key}=" "$pin" || true)"
  [ "$found" = "1" ] || die "$pin names ${key} ${found} time(s), and it is named once"
  grep "^${key}=" "$pin" | cut -d= -f2-
}
version="$(value_of version)"
archive="$(value_of archive)"
sha256="$(value_of sha256)"

# Each value ends up in a path or in an address, so its shape is asked before
# it is used.
printf '%s' "$version" | grep -qE '^[0-9]+(\.[0-9]+)+$' ||
  die "$pin gives the version as \"$version\", which is not a version"
printf '%s' "$archive" | grep -qE '^[A-Za-z0-9][A-Za-z0-9._-]*\.7z$' ||
  die "$pin gives the archive as \"$archive\", which is not the name of a 7z archive"
printf '%s' "$sha256" | grep -qE '^[0-9a-f]{64}$' ||
  die "$pin gives the archive's sum as \"$sha256\", which is not a SHA-256"

files=()
while IFS= read -r line; do
  files+=("$line")
done < <(grep '^file=' "$pin" | cut -d= -f2-)
[ "${#files[@]}" -gt 0 ] || die "$pin names no file to take out of the archive"
for line in "${files[@]}"; do
  printf '%s' "$line" | grep -qE '^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)* [0-9a-f]{64} [0-9]+$' ||
    die "$pin has the line \"file=$line\", and a file is a path, a SHA-256 and a size"
done

command -v sha256sum >/dev/null 2>&1 || die "there is no sha256sum here, so nothing could be checked"

# 7z on the Windows runner, bsdtar where libarchive is installed instead. GNU
# tar does not read this format, and is not tried.
unpack=""
for tool in 7z 7zz bsdtar; do
  if command -v "$tool" >/dev/null 2>&1; then
    unpack="$tool"
    break
  fi
done
[ -n "$unpack" ] || die "neither 7z nor bsdtar is installed, and the archive is a 7z"

dest="$into/opengl"
if [ -e "$dest" ]; then
  die "$dest is already there. What is in it was not put there by this run, so it was not checked by it."
fi

# Beside the target rather than in the system's temporary directory, so the
# download and the files it becomes are on one disk and under one owner.
fetched="$(mktemp -d "$into/.software-renderer.XXXXXX")"
trap 'rm -rf "$fetched"' EXIT

url="https://github.com/${project}/releases/download/${version}/${archive}"
echo "fetching ${url}"
curl --silent --show-error --fail --location --retry 3 --output "$fetched/$archive" "$url" ||
  die "could not download $url"
(cd "$fetched" && echo "${sha256}  ${archive}" | sha256sum -c - >/dev/null) ||
  die "$archive does not have the SHA-256 $pin names, so it was not unpacked"
echo "${archive}: the sum is the pinned one"

# Unpacked and checked in the same hidden directory, and moved into place only
# when every file has passed, so a refusal half way leaves no opengl folder that
# looks like a finished one.
stage="$fetched/opengl"
mkdir "$fetched/out" "$stage"
for line in "${files[@]}"; do
  read -r inside sum size <<<"$line"
  name="$(basename "$inside")"
  case "$unpack" in
    bsdtar)
      bsdtar -xf "$fetched/$archive" -C "$fetched/out" "$inside" ||
        die "$archive does not unpack $inside"
      mv "$fetched/out/$inside" "$stage/$name"
      ;;
    *)
      "$unpack" e -bso0 -bsp0 -o"$stage" "$fetched/$archive" "$inside" ||
        die "$archive does not unpack $inside"
      ;;
  esac
  [ -f "$stage/$name" ] || die "$archive holds no $inside"
  (cd "$stage" && echo "${sum}  ${name}" | sha256sum -c - >/dev/null) ||
    die "$inside does not have the SHA-256 $pin names"
  got="$(wc -c < "$stage/$name" | tr -d '[:space:]')"
  [ "$got" = "$size" ] || die "$inside is $got bytes, and $pin names $size"
  echo "opengl/${name}: ${size} bytes, the sum is the pinned one"
done

# As many files as the pin names and no more, or the folder is not what the
# notices describe.
count="$(find "$stage" -type f | wc -l | tr -d '[:space:]')"
[ "$count" = "${#files[@]}" ] ||
  die "the archive gave $count file(s), and $pin names ${#files[@]}"
mv "$stage" "$dest"
echo "the software renderer is in $dest"
