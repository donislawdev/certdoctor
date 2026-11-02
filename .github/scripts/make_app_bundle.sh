#!/usr/bin/env bash
# Wrap the macOS binary in a .app bundle, because that is the only shape that
# can carry a notarisation ticket.
#
#   bash .github/scripts/make_app_bundle.sh <workdir> <binary> <bundle-id> <version>
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

if [ "$#" -ne 4 ]; then
  echo "usage: make_app_bundle.sh <workdir> <binary> <bundle-id> <version>" >&2
  exit 2
fi

work="$1"
binary="$2"
bundle_id="$3"
version="$4"

if [ ! -f "${work}/${binary}" ]; then
  echo "make_app_bundle: ${work}/${binary} is not there, nothing to wrap" >&2
  exit 1
fi

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
mv "${work}/${binary}" "${app}/Contents/MacOS/${binary}"
chmod +x "${app}/Contents/MacOS/${binary}"
cp "${icon}" "${app}/Contents/Resources/icon.icns"

# LSMinimumSystemVersion is 13.0 because that is the oldest macOS the Go
# toolchain this is built with supports: "For Go 1.27 and later: macOS 13
# Ventura or newer" - https://go.dev/wiki/MinimumRequirements, read 2026-11-02.
# It moves when go.mod moves past a release that raises it.
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
</dict>
</plist>
PLIST

# Relative, so it still points at the binary after the archive is unpacked
# anywhere.
ln -s "${binary}.app/Contents/MacOS/${binary}" "${work}/${binary}"

# On a filesystem that cannot make links, ln quietly makes a COPY instead, and a
# copy is far worse than nothing here: a binary outside the bundle is refused by
# Gatekeeper, so the archive would carry something that looks like the program
# and will not run. Measured in that same project, by accident: a build on
# Windows made exactly that.
if [ ! -L "${work}/${binary}" ]; then
  echo "make_app_bundle: ${binary} beside the bundle is a copy, not a link." >&2
  echo "A copy of the binary outside the bundle is refused by Gatekeeper." >&2
  exit 1
fi

echo "wrapped ${binary} in ${binary}.app (${bundle_id}, ${version})"
