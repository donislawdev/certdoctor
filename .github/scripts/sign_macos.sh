#!/usr/bin/env bash
# Sign, notarise and staple the macOS archive of a release. Runs ON THE MAC,
# copied there and started by .github/scripts/sign_release.py.
#
#   bash sign_macos.sh <directory> <certificate-sha256> <notarytool-profile>
#
# The Developer ID key lives in a keychain on the maintainer's Mac and Apple's
# notary service only talks to credentials stored there. The Windows card and
# this key are on two different machines, so the release is signed in two
# places and the checksums are written once, at the end, over everything.
#
# What it refuses, and why each refusal is there. Each was measured in the
# maintainer's other Go project on 2026-08-28, on real hardware, and several are
# refusals precisely because the failure is SILENT otherwise:
#
#  * a locked keychain. codesign then exits 1 with errSecInternalComponent and
#    leaves the file UNSIGNED. An ssh session is its own security session, so
#    unlocking the keychain in the Mac's own Terminal does NOT carry over here;
#  * a missing notarytool profile - told apart from a locked keychain, which
#    reports the same error, rather than blaming the person for work they did;
#  * a certificate that is not the pinned one. A second Developer ID on the same
#    machine signs just as willingly and the release looks identical;
#  * notarisation that came back anything but Accepted;
#  * a staple that did not take, or a bundle Gatekeeper still refuses. Without
#    this last one the script would hand back an archive that fails on the
#    first machine that downloads it.
set -uo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: sign_macos.sh <directory> <certificate-sha256> <profile>" >&2
  exit 2
fi

DIR="$1"
PIN="$(echo "$2" | tr '[:lower:]' '[:upper:]')"
PROFILE="$3"

say() { echo "  $*"; }
die() { echo "sign_macos: $*" >&2; exit 1; }

# Asked for on the terminal rather than taken as an argument or an environment
# variable - a password in argv is visible in ps to every process on the
# machine. It asks every time and does NOT claim to know whether it needed to:
# over ssh, show-keychain-info answers "User interaction is not allowed" even
# when the keychain is unlocked, so a test of it would report a locked keychain
# that is not locked. Unlocking an unlocked keychain changes nothing, and the
# real proof that the key is reachable is codesign itself, further down.
unlock_keychain() {
  echo
  echo "  An ssh session is its own security session and cannot see whether the"
  echo "  keychain is unlocked, so it asks. If it is already unlocked, press"
  echo "  Enter. Otherwise this is your Mac password."
  echo
  if ! security unlock-keychain "$HOME/Library/Keychains/login.keychain-db"; then
    die "the keychain would not unlock, so nothing has been signed.
Run this by hand on the Mac and try again:
  security unlock-keychain ~/Library/Keychains/login.keychain-db"
  fi
  say "keychain reachable"
}

check_profile() {
  local out rc
  out="$(xcrun notarytool history --keychain-profile "$PROFILE" 2>&1)"
  rc=$?
  if [ $rc -eq 0 ]; then
    say "notarytool profile '$PROFILE' answers"
    return 0
  fi
  case "$out" in
    *keychainLocked*)
      die "the keychain locked itself again between two steps. Nothing signed." ;;
    *"No Keychain password item"*)
      die "there is no notarytool profile called '$PROFILE' on this Mac.
Create it once, in the Mac's own Terminal rather than over ssh:

  xcrun notarytool store-credentials \"$PROFILE\" --apple-id <your-apple-id> --team-id <your-team-id>

It asks for an APP-SPECIFIC password from appleid.apple.com, not the password
to the Apple account itself. A profile made for another project works too -
pass its name to sign_release.py with --notary-profile." ;;
  esac
  die "notarytool would not answer: $out"
}

# codesign selects by SHA-1 and SHA-1 is not worth pinning anything to, so the
# pin is a SHA-256 and the selector is derived from it here. That also settles
# the ambiguity of the name: the same certificate is installed in both the login
# and the system keychain, so "Developer ID Application" names two entries.
find_identity() {
  local sha1
  sha1="$(security find-certificate -a -c "Developer ID Application" -Z 2>/dev/null |
    awk -v pin="$PIN" '
      /^SHA-256 hash:/ { s256 = $3 }
      /^SHA-1 hash:/   { if (s256 == pin) { print $3; exit } }')"
  [ -n "$sha1" ] ||
    die "no Developer ID certificate on this Mac hashes to the pin $PIN.
A renewal is a DIFFERENT certificate, and its line in .github/signing-certificates.txt
has to move with it."
  security find-identity -v -p codesigning 2>/dev/null | grep -qi "$sha1" ||
    die "the pinned certificate is installed but has no private key here, so it cannot sign"
  echo "$sha1"
}

# The certificate that ACTUALLY signed a bundle, read back out of it. Nothing
# here changes directory: the path arrives relative, and in the other project a
# cd before this made it name nothing, so a correctly signed bundle was refused
# as "signed by a DIFFERENT certificate, got none". A refusal that is right
# about there being a problem and wrong about what it is sends somebody to look
# at the wrong machine.
certificate_of() {
  local bundle="$1" tmp
  tmp="$(mktemp -d)"
  codesign -d --extract-certificates="$tmp/cert" "$bundle" >/dev/null 2>&1
  if [ ! -f "$tmp/cert0" ]; then
    rm -rf "$tmp"
    echo "none"
    return
  fi
  shasum -a 256 "$tmp/cert0" | awk '{ print toupper($1) }'
  rm -rf "$tmp"
}

sign_archive() {
  local archive="$1" identity="$2"
  local name work app
  name="$(basename "$archive")"
  work="${archive}.unpacked"
  rm -rf "$work"
  mkdir -p "$work"
  tar -xzf "$archive" -C "$work" || die "$name did not unpack"

  app="$work/certdoctor.app"
  [ -d "$app" ] ||
    die "$name holds no certdoctor.app. The release build makes one, because a bare
binary cannot carry a notarisation ticket at all."
  [ -L "$work/certdoctor" ] ||
    die "$name does not carry a link called certdoctor beside the bundle"

  say "$name"
  say "  signing $(basename "$app")"
  # --options runtime is the hardened runtime, which notarisation requires.
  # --timestamp is what keeps the signature alive past the certificate.
  codesign --force --options runtime --timestamp --sign "$identity" "$app" >/dev/null 2>&1 ||
    die "codesign failed on $(basename "$app") in $name.
The usual cause is a locked keychain, which fails as errSecInternalComponent and
leaves the file unsigned. Unlock it on the Mac and run this again:
  security unlock-keychain ~/Library/Keychains/login.keychain-db"

  local actual
  actual="$(certificate_of "$app")"
  [ "$actual" = "$PIN" ] ||
    die "$(basename "$app") was signed by a DIFFERENT certificate
  expected $PIN
  got      $actual
Nothing has been handed back."

  say "  notarising, this takes a few minutes"
  # Apple takes a zip, a pkg or a dmg, and not the tar.gz that is published, so
  # the zip exists only to carry the bundle there. What gets stapled and handed
  # back is the bundle itself. No cd here either, for the reason above.
  local zip="${work}/notarise.zip"
  ditto -c -k --keepParent "$app" "$zip" ||
    die "could not zip $(basename "$app") for notarisation"

  local out
  out="$(xcrun notarytool submit "$zip" --keychain-profile "$PROFILE" --wait 2>&1)"
  echo "$out" | grep -q "status: Accepted" ||
    die "notarisation did not come back Accepted for $name:
$out"
  rm -f "$zip"

  say "  stapling"
  xcrun stapler staple "$app" >/dev/null 2>&1 ||
    die "the ticket would not staple onto $(basename "$app") in $name"

  # The two questions worth asking after the fact, because a staple that did not
  # take and a bundle Gatekeeper refuses both look like success up to here.
  xcrun stapler validate "$app" >/dev/null 2>&1 ||
    die "$(basename "$app") does not validate against its own ticket"
  spctl -a -t exec "$app" >/dev/null 2>&1 ||
    die "Gatekeeper still refuses $(basename "$app") after signing and stapling"

  say "  repacking"
  rm -f "$archive"
  # -C and . so the archive keeps the shape it had, the link included.
  tar -czf "$archive" -C "$work" . || die "could not repack $name"
  rm -rf "$work"
  say "  done, signed and stapled"
}

main() {
  [ -d "$DIR" ] || die "$DIR is not a directory"

  echo "[1/4] the keychain"
  unlock_keychain

  echo "[2/4] the credentials"
  check_profile

  echo "[3/4] the certificate"
  local identity
  identity="$(find_identity)" || exit 1
  say "signing with the pinned certificate"

  echo "[4/4] the archive"
  local archives=()
  while IFS= read -r line; do
    archives+=("$line")
  done < <(find "$DIR" -maxdepth 1 -name '*_macos_*.tar.gz' | sort)

  if [ "${#archives[@]}" -ne 1 ]; then
    die "expected one macOS archive and found ${#archives[@]}"
  fi
  sign_archive "${archives[0]}" "$identity"

  echo
  echo "The macOS archive is signed, notarised and stapled."
}

main "$@"
