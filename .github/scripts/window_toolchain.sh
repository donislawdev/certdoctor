#!/usr/bin/env bash
# Hold what the C compiler linked into the window of its own to the list the
# window's notices were written for (OBS208, ADR125).
#
#   bash .github/scripts/window_toolchain.sh <goos>/<goarch> <linker map> <C compiler>
#
# build_window.sh runs it after every build of the window, with the map the
# linker wrote for that build and the compiler cgo used. It reads two things
# and refuses when either differs from .github/window-toolchain:
#
#   the files of the compiler's own the link took code from - every object
#   file it linked whole and every archive it took a member out of, named by
#   file name, Go's own objects and the system's shared libraries left out.
#
#   the version of each library whose notices the window quotes, asked of the
#   compiler's own headers, because the notices quote that version's texts.
#
# WHY THE LINKER'S MAP AND NOT THE BINARY. The notices guard in internal/guard
# reads what go list says is compiled, and the compiler's runtime is not in
# this tree: it comes with the compiler on the runner and moves when the runner
# image does. The symbols in a binary only suggest where code came from, and
# the same function can come from more than one library. The map is the
# linker's own record of which file each piece came from.
#
# WHY BOTH DIRECTIONS. A file the list names and the link no longer takes is a
# notice nobody needs and a claim in the notices that is no longer true, and
# it is found here as cheaply as a new one.
set -euo pipefail
# sort and comm compare in one collation, whatever the runner's locale.
export LC_ALL=C

pin=".github/window-toolchain"

die() { echo "window_toolchain: $*" >&2; exit 1; }

if [ "$#" -ne 3 ]; then
  echo "usage: window_toolchain.sh <goos>/<goarch> <linker map> <C compiler>" >&2
  exit 2
fi
target="$1"
map="$2"
cc="$3"

[ -f "$pin" ] || die "$pin is not here - run this from the root of the repository"
[ -s "$map" ] || die "the linker wrote no map at $map, so nothing says what it linked. A build linked by
Go's own linker writes none - the window is linked by the C compiler's, and a build that
was not is not the build this list was written for."

# toolchain_files prints the file names, one per line, sorted and each once.
#
# Both formats name Go's own objects by a path in the temporary directory the
# go command links in, and go.o is always one of them, so that directory is
# found by go.o rather than by its name, which the go command does not promise.
# Paths are read with / for \, because the Windows linker writes both.
toolchain_files() {
  local goos="$1" file="$2"
  case "$goos" in
    darwin)
      # ld64: "# Object files:" lists "[  n] <path>" for every input, an
      # archive member as "<archive>(<member>)", up to "# Sections:".
      tr -d '\r' < "$file" | tr '\\' '/' | awk '
        /^# Object files:/ { inside = 1; next }
        /^# / { inside = 0 }
        !inside { next }
        {
          sub(/^\[ *[0-9]+\] /, "")
          if ($0 == "linker synthesized" || $0 == "") next
          n++; path[n] = $0
          if ($0 ~ /\/go\.o$/) { godir = $0; sub(/\/[^\/]*$/, "", godir) }
        }
        END {
          if (godir == "") { print "no go.o among the inputs" > "/dev/stderr"; exit 3 }
          for (i = 1; i <= n; i++) {
            p = path[i]
            if (match(p, /\.a\(/)) { p = substr(p, 1, RSTART + 1) }
            else if (p ~ /\.(tbd|dylib)$/) continue
            dir = p; sub(/\/[^\/]*$/, "", dir)
            if (dir == godir) continue
            sub(/^.*\//, "", p)
            print p
          }
        }' | sort -u
      ;;
    *)
      # GNU ld: "Archive member included to satisfy reference by file
      # (symbol)" opens the map with one "<archive>(<member>)" line at the
      # left margin for each member the link took, the file that wanted it
      # indented below or beside it. Then "LOAD <path>" for every input the
      # linker opened - an object file is linked whole, an archive only for
      # the members above, and a shared library or a linker script is not
      # copied into the binary at all.
      tr -d '\r' < "$file" | tr '\\' '/' | awk '
        /^Archive member included/ { members = 1; next }
        /^(Discarded input sections|Allocating common symbols|Memory Configuration)/ { members = 0 }
        members && /^[^ \t]/ && match($0, /\.a\(/) {
          a = substr($0, 1, RSTART + 1); sub(/^.*\//, "", a); archive[a] = 1; next
        }
        /^LOAD / {
          p = substr($0, 6)
          n++; path[n] = p
          if (p ~ /\/go\.o$/) { godir = p; sub(/\/[^\/]*$/, "", godir) }
        }
        END {
          if (godir == "") { print "no go.o among the inputs" > "/dev/stderr"; exit 3 }
          for (a in archive) print a
          for (i = 1; i <= n; i++) {
            p = path[i]
            if (p !~ /\.(o|obj)$/) continue
            dir = p; sub(/\/[^\/]*$/, "", dir)
            if (dir == godir) continue
            sub(/^.*\//, "", p)
            print p
          }
        }' | sort -u
      ;;
  esac
}

# library_version asks the compiler which version of a library it builds
# against, from the macros of that library's own headers.
library_version() {
  local library="$1" header major minor bugfix defines
  case "$library" in
    mingw-w64) header="_mingw_mac.h"; major="__MINGW64_VERSION_MAJOR"; minor="__MINGW64_VERSION_MINOR"; bugfix="__MINGW64_VERSION_BUGFIX" ;;
    glibc) header="features.h"; major="__GLIBC__"; minor="__GLIBC_MINOR__"; bugfix="" ;;
    *) die "$pin names a version of $library, and this script knows no way to ask a compiler for one" ;;
  esac
  defines="$(printf '#include <%s>\n' "$header" | "$cc" -E -dM -x c - 2>/dev/null)" ||
    die "$cc cannot compile against <$header>, so it is not a compiler with $library"
  macro() { printf '%s\n' "$defines" | awk -v name="$1" '$1 == "#define" && $2 == name { print $3 }'; }
  local version
  version="$(macro "$major").$(macro "$minor")"
  [ -n "$bugfix" ] && version="$version.$(macro "$bugfix")"
  case "$version" in
    *[!0-9.]*|.*|*.|*..*) die "$cc answers $version as the version of $library from <$header>" ;;
  esac
  printf '%s\n' "$version"
}

found="$(toolchain_files "${target%/*}" "$map")" || die "cannot read $map as a map of the ${target%/*} linker"

# The list, for this target: "link <target> <file> <library>" and
# "version <target> <library> <version>" lines, or one "nothing <target>".
expected="$(awk -v t="$target" '$1 == "link" && $2 == t { print $3 }' "$pin" | sort -u)"
nothing="$(awk -v t="$target" '$1 == "nothing" && $2 == t' "$pin")"
if [ -z "$expected" ] && [ -z "$nothing" ]; then
  die "$pin says nothing about $target - a build it was not written for"
fi

echo "the C compiler's own files linked into the window for $target:"
if [ -n "$found" ]; then printf '%s\n' "$found" | sed 's/^/  /'; else echo "  none"; fi

extra="$(comm -23 <(printf '%s\n' "$found" | sed '/^$/d') <(printf '%s\n' "$expected" | sed '/^$/d'))"
missing="$(comm -13 <(printf '%s\n' "$found" | sed '/^$/d') <(printf '%s\n' "$expected" | sed '/^$/d'))"
if [ -n "$extra" ] || [ -n "$missing" ]; then
  if [ -n "$extra" ]; then
    echo "linked and not in $pin: $(printf '%s\n' "$extra" | tr '\n' ' ')" >&2
  fi
  if [ -n "$missing" ]; then
    echo "in $pin and not linked: $(printf '%s\n' "$missing" | tr '\n' ' ')" >&2
  fi
  die "the compiler on this runner links other code of its own into the window than
$pin names, and the window's notices were written for that list. Find whose
each file is and what its licence asks of a binary copy, change the notices,
then the list - the notices guard holds the two together."
fi

while read -r _ _ library version; do
  have="$(library_version "$library")"
  [ "$have" = "$version" ] || die "the compiler builds against $library $have, and the window's notices quote
the texts of $library $version. Read the licence texts of $have, change the notices, then $pin."
  echo "  $library $have, as the notices quote it"
done < <(awk -v t="$target" '$1 == "version" && $2 == t' "$pin")
