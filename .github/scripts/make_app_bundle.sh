#!/usr/bin/env bash
# Wrap the macOS binary in a .app bundle, because that is the only shape that
# can carry a notarisation ticket.
#
#   bash .github/scripts/make_app_bundle.sh <workdir> <binary> <bundle-id> <version> [<another binary>...]
#
# The binary the bundle opens is <binary>. Each other binary named after the
# version goes into the bundle beside it, in Contents/MacOS: the window starts
# certdoctor from its own folder and from nowhere else (ADR121 point 1), so on
# macOS the command line it runs is inside its bundle. Every binary gets a link
# beside the bundle, so a person types ./certdoctor-gui or ./certdoctor.
#
# Measured in the maintainer's other Go project on 2026-08-28, on a real
# Developer ID certificate and two real notarisations:
#
#   * a bare Mach-O binary cannot be stapled at all. stapler exits 66, and
#     Gatekeeper then refuses the binary (spctl exits 3) even when it is signed
#     AND notarised;
#   * a .dmg staples and does not help: the binary INSIDE a stapled dmg is still
#     refused, because the ticket describes the container;
#   * a .app staples, is accepted, and the ticket survives being packed into
#     tar.gz and unpacked again.
#
# Without a ticket in the file, macOS asks Apple over the network whether the
# program is notarised. The people this program is for are exactly the ones
# whose network gets in the way of that.
#
# A link goes next to the bundle so that a person still types ./certdoctor. The
# binary must NOT be lifted out of the bundle - a copy of it on its own is
# refused with "invalid resource directory", because the signature covers the
# bundle, not the file.
set -euo pipefail

if [ "$#" -lt 4 ]; then
  echo "usage: make_app_bundle.sh <workdir> <binary> <bundle-id> <version> [<another binary>...]" >&2
  exit 2
fi

work="$1"
binary="$2"
bundle_id="$3"
version="$4"
shift 4
inside=("$binary" "$@")

for name in "${inside[@]}"; do
  if [ ! -f "${work}/${name}" ]; then
    echo "make_app_bundle: ${work}/${name} is not there, nothing to wrap" >&2
    exit 1
  fi
done

# The icon, refused rather than skipped when it is missing. A bundle without one
# shows a blank sheet of paper in the Finder, which is what a program macOS
# knows nothing about looks like. The file is in the repository rather than made
# here, because this runs where Apple's icon tools are not: the macOS binary is
# cross compiled on Linux. assets/icon/appicon.py draws it - ADR117.
here="$(cd "$(dirname "$0")" && pwd)"
icon="${here}/../../assets/icon/certdoctor.icns"
if [ ! -f "${icon}" ]; then
  echo "make_app_bundle: no icon at ${icon}, so the bundle would show a blank page" >&2
  exit 1
fi

app="${work}/${binary}.app"
mkdir -p "${app}/Contents/MacOS" "${app}/Contents/Resources"
for name in "${inside[@]}"; do
  mv "${work}/${name}" "${app}/Contents/MacOS/${name}"
  chmod +x "${app}/Contents/MacOS/${name}"
done
cp "${icon}" "${app}/Contents/Resources/icon.icns"

# LSMinimumSystemVersion is 13.0 because that is the oldest macOS the Go
# toolchain this is built with supports: "For Go 1.27 and later: macOS 13
# Ventura or newer" - https://go.dev/wiki/MinimumRequirements, read 2026-11-02.
# It moves when go.mod moves past a release that raises it.
#
# NSHighResolutionCapable is "a Boolean value indicating whether the Cocoa app
# supports high-resolution displays" - Apple's Information Property List
# reference, read 2026-11-11 - and the window is one. The maintainer's other Go
# project sets it for its window for that reason, and what macOS does with a
# window from a bundle without it was not measured here. The command line
# draws nothing, and the key costs it nothing.
#
# NSHumanReadableCopyright is "a human-readable copyright notice for the
# bundle" - the same reference, read 2026-11-12. The same words as the
# LegalCopyright of the Windows binaries in cmd/*/winres.json, so the author
# reads the same on both systems.
cat > "${app}/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleExecutable</key>
	<string>${binary}</string>
	<key>CFBundleIconFile</key>
	<string>icon</string>
	<key>CFBundleIdentifier</key>
	<string>${bundle_id}</string>
	<key>CFBundleName</key>
	<string>${binary}</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleShortVersionString</key>
	<string>${version}</string>
	<key>CFBundleVersion</key>
	<string>${version}</string>
	<key>LSMinimumSystemVersion</key>
	<string>13.0</string>
	<key>NSHighResolutionCapable</key>
	<true/>
	<key>NSHumanReadableCopyright</key>
	<string>Copyright (C) 2026 DonislawDev. Licensed under the GNU General Public License version 3.</string>
</dict>
</plist>
PLIST

# Relative, so it still points at the binary after the archive is unpacked
# anywhere.
#
# On a filesystem that cannot make links, ln quietly makes a COPY instead, and a
# copy is far worse than nothing here: a binary outside the bundle is refused by
# Gatekeeper, so the archive would carry something that looks like the program
# and will not run. Measured in that same project, by accident: a build on
# Windows made exactly that.
for name in "${inside[@]}"; do
  ln -s "${binary}.app/Contents/MacOS/${name}" "${work}/${name}"
  if [ ! -L "${work}/${name}" ]; then
    echo "make_app_bundle: ${name} beside the bundle is a copy, not a link." >&2
    echo "A copy of the binary outside the bundle is refused by Gatekeeper." >&2
    exit 1
  fi
done

echo "wrapped ${inside[*]} in ${binary}.app (${bundle_id}, ${version})"
