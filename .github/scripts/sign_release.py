#!/usr/bin/env python3
"""Sign a release on the two machines that hold its keys, then hand it back.

    python .github/scripts/sign_release.py v0.1.0 --macos-host user@mac
    python .github/scripts/sign_release.py v0.1.0 --macos-host user@mac --dry-run

Run it from the root of a clone of this repository, on the Windows machine with
the card reader, after release.yml has finished for the tag. On Windows, start
it from Git Bash: its ssh is the one found first there, and Windows' own ssh.exe
refuses a private key whose file permissions it does not like.

Why this is a step a person runs
--------------------------------
The Windows key lives on a cryptographic card in a USB reader and cannot be
exported - that is the whole value of it - so no GitHub hosted runner can reach
it. A self hosted runner could, and on a public repository a self hosted runner
is a machine strangers can aim a pull request at. So the build
happens where builds belong and the signature happens where the card is, and
this script is the seam between them.

The Apple key is the same problem with a different shape: Apple's notary service
only talks to credentials held in a keychain, and that keychain is on the
maintainer's Mac. So three of the five archives are signed here, in two places,
and the checksums are written once at the end over everything.

What it does, in order, and what it refuses
-------------------------------------------
 1. downloads the unsigned build release.yml produced for this tag;
 2. **verifies that build's provenance** before touching it. Signing something
    you did not check is how a supply chain gets a signature on it;
 3. finds the pinned certificate among those the card offers;
 4. signs the two Windows programs with the card, each with an RFC 3161
    timestamp - **without a timestamp a signature dies when the certificate
    expires** - and reads the certificate back OUT of each signed file, refusing
    to go on unless it hashes to the pin in .github/signing-certificates.txt;
 5. hands the macOS archive to the Mac, which signs the .app bundle inside it,
    notarises it with Apple and staples the ticket on;
 6. writes verify-SHA256SUMS.txt over everything it is about to publish, signed
    and unsigned alike;
 7. uploads the lot to the DRAFT release and asks attest-release.yml for the
    statement about the signed bytes;
 8. waits for that statement and confirms the draft is complete, because a
    draft missing one file looks almost exactly like a finished one.

It refuses without a Mac, and asks the Mac before the card signs anything: a
build with two signed archives and one unsigned macOS archive is a release page
that cannot say so.

Nothing here publishes. The release stays a draft until a person reads it and
presses the button.

The mechanics and the refusals come from the release script of the maintainer's
other Go project, where each of them was paid for on a real release - the notes
beside them say where.
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import zipfile

REPO = "donislawdev/certdoctor"
ATTEST_WORKFLOW = "attest-release.yml"
TIMESTAMP_URL = "http://time.certum.pl/"

# The archives that get a Windows signature. A Linux archive is the finished
# article here, and the statement the build made about it stays true because its
# bytes do not move.
SIGNED_ARCHIVES = ("_windows_amd64.zip", "_windows_arm64.zip")
MACOS_ARCHIVE = "_macos_arm64.tar.gz"
ARCHIVES = 5

# The files a person uses to CHECK a download rather than download itself. GitHub
# lists a release's downloads by file name and nothing else - not the upload
# order, not a label - so the prefix is what puts these at the end of the page.
AUX_PREFIX = "verify-"

# The one written copy of each certificate digest. Read here rather than copied,
# because two written copies of one digest is exactly the drift a pin exists to
# catch.
PIN_FILE = os.path.join(".github", "signing-certificates.txt")
WINDOWS_PIN = "windows-code-signing"
APPLE_PIN = "apple-developer-id"

# The OID, not the display name. Measured in the other project on 2026-08-28:
# filtering certificates by the friendly name "Code Signing" returns NOTHING on
# a Polish Windows, which calls it "Podpisywanie kodu" - and the script would
# then report a missing card while the card was plugged in and working.
CODE_SIGNING_OID = "1.3.6.1.5.5.7.3.3"

# The tag goes into a directory name on the Mac and into a command line there,
# so it is held to the shape of a version before anything uses it.
TAG_SHAPE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$")


def run(argv, **kw):
    """Run something and let it print. A failure raises."""
    print("    $ %s" % " ".join(str(a) for a in argv))
    return subprocess.run(argv, check=True, **kw)


def powershell(script, env=None):
    """Run a PowerShell 7 script.

    Values the script needs go in env, never in the script's text: a file name
    with a quote in it would end the string and the rest would run as
    PowerShell, and -LiteralPath does not help, because the quote is parsed
    before the parameter is.
    """
    out = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True,
        env=None if env is None else {**os.environ, **env})
    if out.returncode != 0:
        raise SystemExit("sign_release: pwsh failed:\n%s" % out.stderr.strip())
    # PowerShell errors are NON TERMINATING by default, so a script can print a
    # page of complaints and still exit zero. Reading stderr only on a non-zero
    # code threw away the one sentence that said what went wrong - it cost an
    # hour in the other project, blaming a missing card that was in the reader.
    if out.stderr.strip():
        print("    pwsh also said:")
        for line in out.stderr.strip().splitlines():
            print("      %s" % line)
    return out.stdout


def pinned(name):
    """The digest a certificate is pinned to, read from the pin file."""
    with open(PIN_FILE, encoding="utf-8") as handle:
        for line in handle:
            fields = line.split()
            if len(fields) == 3 and fields[0] == name:
                if not re.fullmatch(r"[0-9a-f]{64}", fields[1]):
                    raise SystemExit("sign_release: %s in %s is not a sha256" % (name, PIN_FILE))
                return fields[1]
    raise SystemExit("sign_release: no %s line in %s" % (name, PIN_FILE))


def find_signtool():
    """The newest x64 signtool.exe from the Windows SDK, or a clear refusal."""
    kits = r"C:\Program Files (x86)\Windows Kits\10\bin"
    if os.path.isdir(kits):
        for version in sorted(os.listdir(kits), reverse=True):
            candidate = os.path.join(kits, version, "x64", "signtool.exe")
            if os.path.isfile(candidate):
                return candidate
    raise SystemExit(
        "sign_release: no signtool.exe under %s - install the Windows SDK "
        "(the Signing Tools component is enough)." % kits)


def expiry_notice(not_after, now):
    """What to say about a certificate that will not last forever."""
    if not not_after:
        return ["  the certificate does not say when it expires"]
    try:
        when = datetime.datetime.fromisoformat(str(not_after).replace("Z", "+00:00"))
    except ValueError:
        return ["  cannot read the expiry date: %s" % not_after]
    if when.tzinfo:
        when = when.replace(tzinfo=None)
    days = (when - now).days
    if days < 0:
        raise SystemExit(
            "sign_release: the certificate expired on %s. Nothing can be signed with it.\n"
            "A renewal is a DIFFERENT certificate, so its line in %s has to move with it."
            % (when.date(), PIN_FILE))
    if days < 90:
        return ["  %d days left on this certificate." % days,
                "     A renewal is a DIFFERENT certificate, so its line in %s goes with it."
                % PIN_FILE]
    return ["  %d days left on this certificate" % days]


def signing_thumbprint(pin):
    """The SHA-1 thumbprint of the certificate whose DER bytes hash to the pin.

    signtool selects by SHA-1 because that is the only selector it takes, and
    the repository pins SHA-256 because that is the digest worth pinning.
    Resolving one to the other here means the two never drift apart.

    The store is opened through .NET rather than through the Cert: drive. The
    drive belongs to a PowerShell module, and in the other project a shell
    started from another shell came up without it - it answered "Cannot find
    drive", exited zero, and the script reported a missing card while the card
    was in the reader. X509Store is in the runtime, not in a module.
    """
    script = (
        "$out = @(); "
        "foreach ($where in 'CurrentUser', 'LocalMachine') { "
        "  $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', $where); "
        "  try { $store.Open('ReadOnly') } catch { continue }; "
        "  foreach ($c in $store.Certificates) { "
        "    $eku = @(); "
        "    foreach ($x in $c.Extensions) { "
        "      if ($x -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) { "
        "        foreach ($u in $x.EnhancedKeyUsages) { $eku += $u.Value } } }; "
        "    if ($eku -notcontains '%s') { continue }; "
        "    $h = [System.Security.Cryptography.SHA256]::Create().ComputeHash($c.RawData); "
        "    $out += [pscustomobject]@{ "
        "      sha256 = (($h | ForEach-Object { $_.ToString('x2') }) -join ''); "
        "      thumb = $c.Thumbprint; subject = $c.Subject; "
        "      notAfter = $c.NotAfter.ToString('s') } }; "
        "  $store.Close() "
        "}; ConvertTo-Json -InputObject @($out) -Compress" % CODE_SIGNING_OID
    )
    entries = json.loads(powershell(script).strip() or "[]")
    if isinstance(entries, dict):
        entries = [entries]
    for entry in entries:
        if entry.get("sha256") == pin:
            # The common name only. The rest of the subject carries a town and
            # a region, and a terminal gets pasted into chats.
            print("  certificate: %s" % entry.get("subject", "").split(",")[0])
            for line in expiry_notice(entry.get("notAfter"), datetime.datetime.now()):
                print(line)
            return entry["thumb"]
    raise SystemExit(
        "sign_release: the pinned certificate (%s...) is not in the Windows store.\n"
        "Plug in the card reader and check the card manager can see it. If the "
        "certificate was renewed, its line in %s has to move with it." % (pin[:16], PIN_FILE))


def certificate_of(path):
    """The sha256 of the certificate that actually signed a file.

    The path reaches PowerShell as an environment variable and never as part
    of the script's text.
    """
    script = (
        "$s = Get-AuthenticodeSignature -LiteralPath $env:CERTDOCTOR_SIGNED_FILE; "
        "if ($s.Status -ne 'Valid') { Write-Error ('signature status: ' + $s.Status); exit 1 }; "
        "if (-not $s.TimeStamperCertificate) { Write-Error 'the signature carries no timestamp'; exit 1 }; "
        "$h = [System.Security.Cryptography.SHA256]::Create()"
        ".ComputeHash($s.SignerCertificate.RawData); "
        "(($h | ForEach-Object { $_.ToString('x2') }) -join '')"
    )
    return powershell(script, env={"CERTDOCTOR_SIGNED_FILE": path}).strip()


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def gh_json(*args):
    out = subprocess.run(["gh", *args], capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit("sign_release: gh %s failed:\n%s" % (args[0], out.stderr.strip()))
    return json.loads(out.stdout or "null")


def files_in(directory):
    """The files directly in a directory, sorted. Never a directory."""
    return sorted(n for n in os.listdir(directory)
                  if os.path.isfile(os.path.join(directory, n)))


def files_under(work):
    """Every file under work, as a path relative to it with forward slashes.

    Recursive on purpose. In the other project the archive was put back
    together from a listing of the top level, which names a directory and none
    of its contents, so a subdirectory came out of the signing EMPTY, with no
    error and a valid archive.
    """
    found = []
    for base, _dirs, names in os.walk(work):
        for name in names:
            found.append(os.path.relpath(os.path.join(base, name), work).replace(os.sep, "/"))
    return sorted(found)


# --------------------------------------------------------------------------- #
# the phases
# --------------------------------------------------------------------------- #

def reach_the_mac(host):
    """Ask the Mac for nothing at all, before the card signs anything.

    BatchMode, so a key that is refused fails here in seconds rather than
    asking for a password nobody expects.
    """
    ssh = shutil.which("ssh") or "ssh"
    print("  ssh is %s" % ssh)
    out = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", host, "true"],
                         capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit(
            "sign_release: %s does not answer over ssh, so the macOS archive cannot be "
            "signed and nothing has been.\n%s\n"
            "On Windows, run this from Git Bash: Windows' own ssh.exe refuses a private "
            "key whose file permissions it does not like. A Mac with its screen locked "
            "stops answering ssh as well." % (host, out.stderr.strip()))
    print("  %s answers" % host)


def fetch_build(tag, into):
    """The build release.yml made for this tag.

    A missing artefact is the ordinary case rather than a crash: the tag has not
    been pushed, the build is still running, or it failed.
    """
    if os.path.isdir(into):
        shutil.rmtree(into)
    os.makedirs(into)
    try:
        run(["gh", "run", "download", "--repo", REPO, "--name",
             "unsigned-build-%s" % tag, "--dir", into])
    except subprocess.CalledProcessError:
        raise SystemExit(
            "sign_release: there is no build called unsigned-build-%s.\n"
            "Either the tag has not been pushed, or release.yml has not finished, "
            "or it failed. Look at the run before signing anything." % tag)
    names = files_in(into)
    print("  %d file(s): %s" % (len(names), ", ".join(names)))


def archives_in(directory):
    return [n for n in files_in(directory) if n.endswith(".zip") or n.endswith(".tar.gz")]


def verify_before_touching(directory):
    """Refuse to sign a build whose own statement does not check out.

    The step that makes the rest worth anything: the whole attack on a person
    with a key is to hand them something that is not what they think it is.
    """
    bundle = os.path.join(directory, "build.provenance.sigstore.json")
    if not os.path.isfile(bundle):
        raise SystemExit(
            "sign_release: the build carries no provenance bundle, so there is "
            "nothing to check it against. Do not sign it.")
    archives = archives_in(directory)
    if len(archives) != ARCHIVES:
        raise SystemExit("sign_release: the build carries %d archive(s), and a release is %d: %s"
                         % (len(archives), ARCHIVES, ", ".join(archives) or "none"))
    for name in archives:
        run(["gh", "attestation", "verify", os.path.join(directory, name),
             "-R", REPO, "--bundle", bundle])
    print("  %d archive(s) verified against the build's own statement" % len(archives))


def windows_archives(directory):
    """The archives that get a signature, refusing a surprise in the count."""
    found = [n for n in files_in(directory) if n.endswith(SIGNED_ARCHIVES)]
    if len(found) != len(SIGNED_ARCHIVES):
        raise SystemExit(
            "sign_release: expected %d Windows archives to sign and found %d: %s\n"
            "Signing one of them would publish an unsigned program next to a signed one."
            % (len(SIGNED_ARCHIVES), len(found), ", ".join(found) or "none"))
    return found


def sign_archive(path, thumbprint, pin, signtool, dry_run):
    """Sign the program inside one archive and put the archive back together whole."""
    work = path + ".unpacked"
    if os.path.isdir(work):
        shutil.rmtree(work)
    os.makedirs(work)
    with zipfile.ZipFile(path) as archive:
        archive.extractall(work)
    inside = files_under(work)
    programs = [n for n in inside if n.endswith(".exe")]
    if programs != ["certdoctor.exe"]:
        raise SystemExit("sign_release: %s holds %s, and an archive holds certdoctor.exe alone"
                         % (os.path.basename(path), ", ".join(programs) or "no program"))
    target = os.path.join(work, programs[0])
    command = [signtool, "sign", "/sha1", thumbprint, "/fd", "sha256",
               "/tr", TIMESTAMP_URL, "/td", "sha256", "/v", target]
    if dry_run:
        print("    DRY RUN, would run: %s" % " ".join(command))
        shutil.rmtree(work)
        return
    run(command)
    run([signtool, "verify", "/pa", "/v", target])
    actual = certificate_of(target)
    if actual != pin:
        raise SystemExit(
            "sign_release: %s in %s was signed by a DIFFERENT certificate\n"
            "  expected %s\n  got      %s\nNothing has been uploaded."
            % (programs[0], os.path.basename(path), pin, actual))

    os.remove(path)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in files_under(work):
            archive.write(os.path.join(work, name), name)
    # What went in is what comes out. A repack that lost a file would be the
    # quietest defect this script could have, so it is counted, not trusted.
    with zipfile.ZipFile(path) as archive:
        repacked = sorted(n for n in archive.namelist() if not n.endswith("/"))
    if repacked != inside:
        raise SystemExit("sign_release: %s was repacked with %d file(s) and held %d\n"
                         "Nothing has been uploaded." % (os.path.basename(path), len(repacked), len(inside)))
    shutil.rmtree(work)
    print("    %s: certdoctor.exe signed and repacked, %d file(s)" % (os.path.basename(path), len(repacked)))


def macos_archive(directory):
    """The macOS archive, refusing a surprise in the count."""
    found = [n for n in files_in(directory) if n.endswith(MACOS_ARCHIVE)]
    if len(found) != 1:
        raise SystemExit("sign_release: expected one macOS archive and found %d: %s"
                         % (len(found), ", ".join(found) or "none"))
    return found[0]


def sign_macos(tag, directory, host, profile, dry_run):
    """Hand the macOS archive to the Mac, and take back a signed one.

    -t because the script over there asks for the keychain password on the
    terminal. A password given that way is not in argv, so it is not in ps,
    and it is nowhere in this repository.

    The address of the Mac is an argument rather than a constant. A machine
    address is not something a public repository should carry.
    """
    name = macos_archive(directory)
    if dry_run:
        print("  DRY RUN, would sign %s on %s" % (name, host))
        return
    remote = "certdoctor-signing-%s" % tag
    run(["ssh", host, "rm -rf %s && mkdir -p %s/dist" % (remote, remote)])
    run(["scp", os.path.join(".github", "scripts", "sign_macos.sh"), "%s:%s/" % (host, remote)])
    run(["scp", os.path.join(directory, name), "%s:%s/dist/" % (host, remote)])
    run(["ssh", "-t", host, "bash %s/sign_macos.sh %s/dist %s %s"
         % (remote, remote, pinned(APPLE_PIN), profile)])
    run(["scp", "%s:%s/dist/%s" % (host, remote, name), directory])
    run(["ssh", host, "rm -rf %s" % remote])
    print("  %s signed, notarised and stapled" % name)


def name_for_publication(directory, tag):
    """Give the build's own files the names a person will see, or drop them.

    build.sha256 was the subject list of the statement the runner made. It
    describes archives that no longer exist in that form, so publishing it
    beside the real checksums would put two lists on one page, one of them
    wrong about three files. The provenance bundle stays, under a name a person
    can use: it still describes the Linux archives byte for byte.
    """
    build_sums = os.path.join(directory, "build.sha256")
    if os.path.isfile(build_sums):
        os.remove(build_sums)
    made = os.path.join(directory, "build.provenance.sigstore.json")
    if os.path.isfile(made):
        os.rename(made, os.path.join(
            directory, "%scertdoctor_%s.provenance.sigstore.json" % (AUX_PREFIX, tag[1:])))


def write_checksums(directory):
    """The checksum file over what is about to be published, and its own digest."""
    published = files_in(directory)
    sums = os.path.join(directory, AUX_PREFIX + "SHA256SUMS.txt")
    with open(sums, "w", encoding="utf-8", newline="\n") as handle:
        for name in published:
            handle.write("%s  %s\n" % (sha256_of(os.path.join(directory, name)), name))
    print("  %d file(s) listed in %sSHA256SUMS.txt" % (len(published), AUX_PREFIX))
    return sha256_of(sums)


def upload_to_draft(tag, directory, dry_run):
    """Everything a person downloads, onto the draft."""
    files = [os.path.join(directory, n) for n in files_in(directory)]
    if dry_run:
        print("  DRY RUN, would upload %d file(s)" % len(files))
        return
    run(["gh", "release", "upload", tag, "--repo", REPO, "--clobber", *files])


def ask_for_the_statement(tag, digest, dry_run):
    """Hand the signed bytes back to a workflow, which can sign a statement."""
    if dry_run:
        print("  DRY RUN, would dispatch %s for %s" % (ATTEST_WORKFLOW, digest[:16]))
        return
    run(["gh", "workflow", "run", ATTEST_WORKFLOW, "--repo", REPO,
         "-f", "tag=%s" % tag, "-f", "digest=%s" % digest])


def confirm_draft(tag, wait_seconds, dry_run):
    """Wait for the statement and check the draft is actually complete."""
    if dry_run:
        print("  DRY RUN, not waiting")
        return
    version = tag[1:]
    statement = "%scertdoctor_%s.sbom.sigstore.json" % (AUX_PREFIX, version)
    deadline = time.time() + wait_seconds
    while True:
        release = gh_json("release", "view", tag, "--repo", REPO, "--json", "assets,isDraft")
        names = sorted(asset["name"] for asset in release.get("assets", []))
        if statement in names:
            break
        if time.time() > deadline:
            raise SystemExit(
                "sign_release: the statement about the signed bytes has not arrived after "
                "%d seconds.\nThe draft holds: %s\nLook at the run of %s before publishing "
                "anything." % (wait_seconds, ", ".join(names), ATTEST_WORKFLOW))
        print("    waiting for %s ..." % ATTEST_WORKFLOW)
        time.sleep(10)

    missing = []
    archives = [n for n in names if n.endswith((".zip", ".tar.gz"))]
    if len(archives) != ARCHIVES:
        missing.append("%d archives (it holds %d)" % (ARCHIVES, len(archives)))
    # Each asked for with its whole name. A suffix would be happy with a file
    # the prefix fell off, and the prefix is what keeps these at the end.
    for needed in (AUX_PREFIX + "SHA256SUMS.txt",
                   "%scertdoctor_%s.spdx.json" % (AUX_PREFIX, version),
                   "%scertdoctor_%s.provenance.sigstore.json" % (AUX_PREFIX, version),
                   statement):
        if needed not in names:
            missing.append(needed)
    if missing:
        raise SystemExit("sign_release: the draft is not complete - missing %s.\nIt holds: %s"
                         % (", ".join(missing), ", ".join(names)))
    if not release.get("isDraft"):
        raise SystemExit("sign_release: %s is no longer a draft. Nothing here publishes, so "
                         "somebody or something else did." % tag)
    print("  the draft holds %d file(s) and is still a draft" % len(names))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("tag", help="the release tag, for example v0.1.0")
    parser.add_argument("--dry-run", action="store_true",
                        help="everything except signing, uploading and dispatching")
    parser.add_argument("--wait", type=int, default=300,
                        help="seconds to wait for the statement (default 300)")
    parser.add_argument("--macos-host", default=os.environ.get("CERTDOCTOR_MACOS_HOST"),
                        help="user@host of the Mac that signs the macOS archive, "
                             "or set CERTDOCTOR_MACOS_HOST")
    parser.add_argument("--notary-profile",
                        default=os.environ.get("CERTDOCTOR_NOTARY_PROFILE", "certdoctor-notary"),
                        help="the notarytool keychain profile on the Mac "
                             "(default certdoctor-notary, or set CERTDOCTOR_NOTARY_PROFILE)")
    args = parser.parse_args(argv)

    if not os.path.isfile(PIN_FILE):
        raise SystemExit("sign_release: run this from the root of the repository")
    if not TAG_SHAPE.match(args.tag):
        raise SystemExit("sign_release: %r is not the tag of a release, which looks like v0.1.0"
                         % args.tag)
    if not args.macos_host:
        raise SystemExit(
            "sign_release: no Mac to sign the macOS archive on.\n"
            "Pass --macos-host user@host, or set CERTDOCTOR_MACOS_HOST.\n"
            "A bare macOS binary cannot carry a notarisation ticket, so that archive\n"
            "is refused by Gatekeeper unless this step runs.")
    windows_pin = pinned(WINDOWS_PIN)
    pinned(APPLE_PIN)
    work = os.path.join("dist", "signing", args.tag)

    print("\nbefore anything: can the Mac be reached")
    reach_the_mac(args.macos_host)

    print("\n[1/8] fetching the build for %s" % args.tag)
    fetch_build(args.tag, work)

    print("\n[2/8] checking it before touching it")
    verify_before_touching(work)

    print("\n[3/8] the card")
    thumbprint = signing_thumbprint(windows_pin)
    signtool = find_signtool()

    print("\n[4/8] signing the Windows programs")
    for name in windows_archives(work):
        sign_archive(os.path.join(work, name), thumbprint, windows_pin, signtool, args.dry_run)

    print("\n[5/8] signing the macOS bundle on %s" % args.macos_host)
    sign_macos(args.tag, work, args.macos_host, args.notary_profile, args.dry_run)

    print("\n[6/8] checksums over what will be published")
    name_for_publication(work, args.tag)
    digest = write_checksums(work)
    print("  %sSHA256SUMS.txt: %s" % (AUX_PREFIX, digest))

    print("\n[7/8] uploading to the draft")
    upload_to_draft(args.tag, work, args.dry_run)
    ask_for_the_statement(args.tag, digest, args.dry_run)

    print("\n[8/8] waiting for the statement and checking the draft")
    confirm_draft(args.tag, args.wait, args.dry_run)

    print("\nDone. %s is a complete DRAFT." % args.tag)
    print("Read it, then publish it from the Releases page.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
