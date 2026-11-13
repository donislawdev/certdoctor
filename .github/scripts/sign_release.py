#!/usr/bin/env python3
"""Sign a release on the two machines that hold its keys, then hand it back.

    python .github/scripts/sign_release.py v0.1.0 --macos-host user@mac
    python .github/scripts/sign_release.py v0.1.0 --macos-host user@mac --dry-run
    python .github/scripts/sign_release.py --rehearsal <run id> --macos-host user@mac

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
maintainer's Mac. So five of the eight archives are signed here, in two places -
the three for Windows at the card, the two for macOS on the Mac - and the
checksums are written once at the end over everything.

What it does, in order, and what it refuses
-------------------------------------------
 1. downloads the unsigned build release.yml produced for this tag;
 2. **verifies that build's provenance** before touching it. Signing something
    you did not check is how a supply chain gets a signature on it;
 3. exports the tree of the tag with git archive and asks build_msi.py from it
    whether this machine can build the Windows installer - template, icon, WiX
    at the pinned version;
 4. finds the pinned certificate among those the card offers;
 5. signs every program and every library in the three Windows archives with
    the card, each with an RFC 3161 timestamp - **without a timestamp a
    signature dies when the certificate expires** - and each distinct file
    ONCE: the window's archive carries the very certdoctor.exe the command
    line's does. It reads the certificate back OUT of each signed file, refusing
    to go on unless it hashes to the pin in .github/signing-certificates.txt;
 6. hands the two macOS archives to the Mac, which signs each program in the
    .app bundle inside each one and then the bundle, notarises it with Apple and
    staples the ticket on;
 7. builds the Windows installer from the window's SIGNED archive with the
    tagged tree's build_msi.py, signs it with the product's name as the
    signature's description and reads the certificate back out of it (ADR148).
    A release candidate gets no installer;
 8. writes verify-SHA256SUMS.txt over everything it is about to publish, signed
    and unsigned alike;
 9. uploads the lot to the DRAFT release and asks attest-release.yml for the
    statement about the signed bytes;
10. waits for that statement and confirms the draft is complete, because a
    draft missing one file looks almost exactly like a finished one.

It refuses without a Mac, and asks the Mac and WiX before the card signs
anything: a build with three signed archives and two unsigned macOS archives,
or with no installer, is a release page that cannot say so.

Nothing here publishes. The release stays a draft until a person reads it and
presses the button.

The rehearsal
-------------
--rehearsal <run id> takes the build of a run of release.yml started by hand on
main, instead of the build of a tag, and does steps 3 to 8 on it for real - the
card signs, the Mac signs, Apple notarises and the installer is built from the
tree of the commit the run built and signed - and uploads nothing, dispatches
nothing and opens no draft. The road from a tag to a published page had not
been walked once when it was written, releases are immutable once published,
and a bundle with a second program inside it is a shape Apple had not seen from
this project. A run by hand has no provenance statement (the job that makes one
is fenced behind a tag), so what stands in for step 2 is GitHub's own account
of the run and of its artefact: the workflow file, how it was started, that it
succeeded, that its commit is on main, and the artefact's digest against the
bytes downloaded. What it leaves is signed and is not a release.

The mechanics and the refusals come from the release script of the maintainer's
other Go project, where each of them was paid for on a real release - the notes
beside them say where.
"""
import argparse
import contextlib
import datetime
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile

REPO = "donislawdev/certdoctor"
RELEASE_WORKFLOW = ".github/workflows/release.yml"
ATTEST_WORKFLOW = "attest-release.yml"
TIMESTAMP_URL = "http://time.certum.pl/"

# Every archive a release is made of: the five builds of the command line and
# the three of the window, ADR125 (a). Each is <program>_<version> and the end
# written here, the way build_release.sh names it. The last field is where it
# is signed - "card" here, every program and library inside it; "mac" on the
# Mac, the bundle inside it, then notarised - or None for an archive that is the
# finished article, so the statement the build made about it stays true because
# its bytes do not move. internal/guard holds this table to the targets the
# release builds, and each archive to the place its system is signed.
RELEASE = (
    ("certdoctor", "_windows_amd64.zip", "card"),
    ("certdoctor", "_windows_arm64.zip", "card"),
    ("certdoctor", "_linux_amd64.tar.gz", None),
    ("certdoctor", "_linux_arm64.tar.gz", None),
    ("certdoctor", "_macos_arm64.tar.gz", "mac"),
    ("certdoctor-gui", "_windows_amd64.zip", "card"),
    ("certdoctor-gui", "_linux_amd64.tar.gz", None),
    ("certdoctor-gui", "_macos_arm64.tar.gz", "mac"),
)

# What the card signs inside a Windows archive of each program: every program
# and every library, and the archive may hold no other. A program this table
# does not name would go out unsigned beside signed ones, so it is refused
# rather than signed unread. The window starts the command line from its own
# folder, and on a machine whose driver offers no OpenGL 2.1 it loads the
# software renderer from opengl\ beside it - a library beside a signed program
# is the one file a tamperer would swap. RENDERER stands for the renderer's
# files, which are read from the pin they were fetched by, not written here.
RENDERER = "<the files .github/mesa-dist-win pins>"
SIGNED_INSIDE = {
    "certdoctor": ("certdoctor.exe",),
    "certdoctor-gui": ("certdoctor-gui.exe", "certdoctor.exe", RENDERER),
}
RENDERER_PIN = os.path.join(".github", "mesa-dist-win")

# The Windows installer, one for a release and none for a release candidate
# (ADR148). It is built here, from the window's archive once the card has
# signed the programs in it - an installer made before would carry unsigned
# copies - by .github/scripts/build_msi.py taken from the tree of the tag
# rather than from this checkout, so it is built from what was tagged. It is
# signed with the product's name as the signature's description, the name
# Windows shows when it asks an administrator to let the installer run: without
# it the prompt showed the digits of a temporary copy's name (measured in the
# maintainer's other Go project on 2026-09-29).
INSTALLER = "certdoctor-setup_%s_windows_amd64.msi"
BUILD_MSI = os.path.join(".github", "scripts", "build_msi.py")

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
# so it is held to the shape of a version before anything uses it. The version
# a rehearsal reads out of the archive names is held to the same shape.
TAG_SHAPE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$")


def is_candidate(version):
    """Whether a version is a release candidate: it has a hyphen. The same rule
    release.yml marks a pre-release by and build_msi.py refuses an installer by,
    because Windows Installer reads only the three numbers of a version - a
    candidate's installer would take the release's own version."""
    return "-" in version


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


def renderer_files():
    """Where the software renderer's files sit in the window's archive.

    Read from the pin they were fetched by - the file= lines of
    .github/mesa-dist-win, each a path in the renderer's own archive - and
    placed in opengl/, where build_release.sh packs them.
    """
    found = []
    with open(RENDERER_PIN, encoding="utf-8") as handle:
        for line in handle:
            if line.startswith("file="):
                inside = line[len("file="):].split()[0]
                found.append("opengl/" + inside.rsplit("/", 1)[-1])
    if not found:
        raise SystemExit("sign_release: %s pins no file of the software renderer" % RENDERER_PIN)
    return found


def signed_inside(program):
    """The programs and libraries the card signs in a Windows archive of program."""
    files = []
    for name in SIGNED_INSIDE[program]:
        files.extend(renderer_files() if name == RENDERER else [name])
    return sorted(files)


def archive_names(version):
    """Every archive of the release by its file name, with its program, its
    end and where it is signed."""
    return {"%s_%s%s" % (program, version, end): (program, end, where)
            for program, end, where in RELEASE}


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
    error and a valid archive. The window's archive carries opengl/.
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
            "sign_release: %s does not answer over ssh, so the macOS archives cannot be "
            "signed and nothing has been.\n%s\n"
            "On Windows, run this from Git Bash: Windows' own ssh.exe refuses a private "
            "key whose file permissions it does not like. A Mac with its screen locked "
            "stops answering ssh as well." % (host, out.stderr.strip()))
    print("  %s answers" % host)


def fresh(directory):
    """An empty directory at this path, whatever was there before."""
    if os.path.isdir(directory):
        shutil.rmtree(directory)
    os.makedirs(directory)


def fetch_build(tag, into):
    """The build release.yml made for this tag.

    A missing artefact is the ordinary case rather than a crash: the tag has not
    been pushed, the build is still running, or it failed.
    """
    fresh(into)
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


def rehearsal_run(run_id):
    """GitHub's account of a run, refused unless it is one a rehearsal may sign.

    A run of release.yml, started by hand, finished and green, on a commit main
    already holds. A run on another branch is code nobody merged, and a run
    that failed is a build the release workflow itself refused - a signature
    on either would be the certificate vouching for something nobody did.
    Asked of the API by the run's number in this repository, so the answer
    cannot come from a fork.
    """
    meta = gh_json("api", "repos/%s/actions/runs/%d" % (REPO, run_id))
    said = {
        "the workflow": (meta.get("path"), RELEASE_WORKFLOW),
        "how it was started": (meta.get("event"), "workflow_dispatch"),
        "its state": (meta.get("status"), "completed"),
        "how it ended": (meta.get("conclusion"), "success"),
        "its branch": (meta.get("head_branch"), "main"),
        "its repository": ((meta.get("head_repository") or {}).get("full_name"), REPO),
    }
    wrong = ["%s is %r, not %r" % (what, got, want) for what, (got, want) in said.items() if got != want]
    if wrong:
        raise SystemExit("sign_release: run %d is not a build a rehearsal signs:\n  %s\n"
                         "A rehearsal takes the build of release.yml run by hand on main, "
                         "after it went green." % (run_id, "\n  ".join(wrong)))
    sha = meta.get("head_sha") or ""
    # compare/<sha>...main is "ahead" when main holds the commit and has moved
    # on since, "identical" when it stands on it - anything else is a commit
    # main does not hold, whatever branch name the run carries.
    status = gh_json("api", "repos/%s/compare/%s...main" % (REPO, sha), "--jq", "{status: .status}")
    if (status or {}).get("status") not in ("ahead", "identical"):
        raise SystemExit("sign_release: run %d built %s, and main does not hold that commit (%s)"
                         % (run_id, sha, (status or {}).get("status")))
    print("  run %d: %s, started by hand on main at %s, %s" % (
        run_id, RELEASE_WORKFLOW, sha[:12], meta.get("conclusion")))
    return sha


def fetch_rehearsal(run_id, into):
    """The build of a run by hand, checked against the digest GitHub keeps for
    it, as its version and the commit the run built.

    A run by hand has no provenance statement, so the artefact is downloaded as
    the zip GitHub stored and its sha256 compared with the digest the API gives
    for it - measured on 2026-11-11: equal - before anything is unpacked. The
    zip goes beside the folder rather than into it, because everything in the
    folder gets a checksum, and it is gone once unpacked.
    """
    sha = rehearsal_run(run_id)
    found = gh_json("api", "repos/%s/actions/runs/%d/artifacts" % (REPO, run_id))
    builds = [a for a in (found or {}).get("artifacts", []) if a.get("name") == "build"]
    if len(builds) != 1 or builds[0].get("expired"):
        raise SystemExit("sign_release: run %d keeps no build to sign - it %s" % (
            run_id, "expired" if builds and builds[0].get("expired") else "has no artefact called build"))
    artefact = builds[0]
    want = artefact.get("digest") or ""
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", want):
        raise SystemExit("sign_release: GitHub gives no sha256 for the build of run %d (%r), so there "
                         "is nothing to check the download against" % (run_id, want))

    fresh(into)
    stored = into.rstrip("/\\") + ".artefact.zip"
    print("    $ gh api repos/%s/actions/artifacts/%d/zip > %s" % (REPO, artefact["id"], stored))
    with open(stored, "wb") as handle:
        got = subprocess.run(["gh", "api", "repos/%s/actions/artifacts/%d/zip" % (REPO, artefact["id"])],
                             stdout=handle, stderr=subprocess.PIPE)
    if got.returncode != 0:
        raise SystemExit("sign_release: the build of run %d did not download:\n%s"
                         % (run_id, got.stderr.decode(errors="replace").strip()))
    actual = "sha256:" + sha256_of(stored)
    if actual != want:
        raise SystemExit("sign_release: the build of run %d downloaded as %s, and GitHub keeps %s for it"
                         % (run_id, actual, want))
    print("  the download is the artefact GitHub keeps: %s" % want)

    # The artefact is the build's dist/ as it was: files and no folders. A
    # name with a slash in it is not something the build makes.
    with zipfile.ZipFile(stored) as archive:
        names = archive.namelist()
        odd = [n for n in names if "/" in n or "\\" in n or n in ("", ".", "..")]
        if odd:
            raise SystemExit("sign_release: the build of run %d holds what the release build never "
                             "makes: %s" % (run_id, ", ".join(odd)))
        for name in names:
            with archive.open(name) as source, open(os.path.join(into, name), "wb") as target:
                shutil.copyfileobj(source, target)
    os.remove(stored)

    sboms = [n for n in names if re.fullmatch(r"%scertdoctor_.+\.spdx\.json" % AUX_PREFIX, n)]
    if len(sboms) != 1:
        raise SystemExit("sign_release: the build of run %d carries %d bill(s) of materials, and a "
                         "release one" % (run_id, len(sboms)))
    version = sboms[0][len(AUX_PREFIX + "certdoctor_"):-len(".spdx.json")]
    if not TAG_SHAPE.match("v" + version):
        raise SystemExit("sign_release: the build of run %d names version %r" % (run_id, version))
    print("  %d file(s) of version %s: %s" % (len(names), version, ", ".join(sorted(names))))
    return version, sha


def check_archives(directory, version):
    """Refuse a build that is not exactly the eight archives of a release."""
    found = {n for n in files_in(directory) if n.endswith((".zip", ".tar.gz"))}
    expected = set(archive_names(version))
    missing, extra = sorted(expected - found), sorted(found - expected)
    if missing or extra:
        raise SystemExit("sign_release: the build is not the %d archives of %s%s%s"
                         % (len(expected), version,
                            "\n  missing: " + ", ".join(missing) if missing else "",
                            "\n  not part of a release: " + ", ".join(extra) if extra else ""))
    print("  the %d archives of %s, and no other" % (len(expected), version))


def verify_before_touching(directory, version):
    """Refuse to sign a build whose own statement does not check out.

    The step that makes the rest worth anything: the whole attack on a person
    with a key is to hand them something that is not what they think it is.
    """
    bundle = os.path.join(directory, "build.provenance.sigstore.json")
    if not os.path.isfile(bundle):
        raise SystemExit(
            "sign_release: the build carries no provenance bundle, so there is "
            "nothing to check it against. Do not sign it.")
    check_archives(directory, version)
    for name in sorted(archive_names(version)):
        run(["gh", "attestation", "verify", os.path.join(directory, name),
             "-R", REPO, "--bundle", bundle])
    print("  %d archive(s) verified against the build's own statement" % len(archive_names(version)))


@contextlib.contextmanager
def tagged_tree(ref):
    """The tree of ref - the tag, or the commit a rehearsal's run built -
    exported with git archive into a temporary folder, removed afterwards.

    The installer is built from what was tagged, whatever this checkout stands
    on: the template, the names and the script that fills them all come from
    ref. filter="data" refuses a link or a name that leads out of the folder,
    which an archive of this tree never holds.
    """
    where = tempfile.mkdtemp(prefix="certdoctor-tree-")
    try:
        out = subprocess.run(["git", "archive", "--format=tar", ref], capture_output=True)
        if out.returncode != 0:
            raise SystemExit(
                "sign_release: git archive %s failed, so there is no tree to build the installer "
                "from. Fetch it first (git fetch --tags origin) and run this again.\n%s"
                % (ref, out.stderr.decode(errors="replace").strip()))
        with tarfile.open(fileobj=io.BytesIO(out.stdout)) as archive:
            archive.extractall(where, filter="data")
        print("  the tree of %s, exported for the installer" % ref)
        yield where
    finally:
        shutil.rmtree(where, ignore_errors=True)


def build_msi(tree, *args):
    """build_msi.py from the tagged tree, with these arguments, and what it
    printed. Its refusals are sentences that name the input, so a failure is
    said in its words and nothing goes on."""
    print("    $ build_msi.py %s" % " ".join(args))
    out = subprocess.run([sys.executable, os.path.join(tree, BUILD_MSI), *args],
                         capture_output=True, text=True)
    for line in out.stdout.strip().splitlines():
        print("      %s" % line)
    if out.returncode != 0:
        # build_msi.py refuses on stderr in one sentence. It ends this message
        # rather than standing above WiX's output, where nobody reads it.
        raise SystemExit("sign_release: the installer cannot be built.\n%s\nNothing has been uploaded."
                         % (out.stderr.strip() or "build_msi.py exited %d" % out.returncode))
    for line in out.stderr.strip().splitlines():
        print("      %s" % line)
    return out.stdout


def check_installer(tree, version):
    """Before the card signs anything: whether this machine can build the
    installer of version from the tagged tree - its template, its icon, WiX."""
    if is_candidate(version):
        print("  %s is a release candidate, which gets no installer" % version)
        return
    build_msi(tree, "--tag", "v" + version, "--check")


def build_installer(tree, directory, version, thumbprint, pin, signtool, dry_run):
    """The installer, built from the signed window archive, signed with the
    product's name, and the certificate read back out of it."""
    if is_candidate(version):
        print("  %s is a release candidate, which gets no installer" % version)
        return
    tag = "v" + version
    name = build_msi(tree, "--tag", tag, "--product-name").strip()
    if not name:
        raise SystemExit("sign_release: build_msi.py --product-name said nothing, and the "
                         "installer is signed with that name. Nothing has been uploaded.")
    build_msi(tree, "--tag", tag, "--archives", directory, "--out-dir", directory)
    path = os.path.join(directory, INSTALLER % version)
    if not os.path.isfile(path):
        raise SystemExit("sign_release: build_msi.py wrote no %s. Nothing has been uploaded."
                         % os.path.basename(path))
    command = [signtool, "sign", "/sha1", thumbprint, "/fd", "sha256",
               "/tr", TIMESTAMP_URL, "/td", "sha256", "/d", name, "/v", path]
    if dry_run:
        print("    DRY RUN, would run: %s" % " ".join(command))
        print("  %s built, not signed" % os.path.basename(path))
        return
    run(command)
    run([signtool, "verify", "/pa", "/v", path])
    actual = certificate_of(path)
    if actual != pin:
        raise SystemExit(
            "sign_release: %s was signed by a DIFFERENT certificate\n"
            "  expected %s\n  got      %s\nNothing has been uploaded."
            % (os.path.basename(path), pin, actual))
    print("  %s built, and signed as %s" % (os.path.basename(path), name))


def unpack_windows(directory, version):
    """Each Windows archive unpacked beside itself, refused unless it holds
    exactly the programs and libraries its program ships."""
    unpacked = {}
    for name, (program, end, where) in sorted(archive_names(version).items()):
        if where != "card":
            continue
        path = os.path.join(directory, name)
        work = path + ".unpacked"
        fresh(work)
        with zipfile.ZipFile(path) as archive:
            archive.extractall(work)
        inside = files_under(work)
        signable = sorted(n for n in inside if n.lower().endswith((".exe", ".dll")))
        wanted = signed_inside(program)
        if signable != wanted:
            raise SystemExit("sign_release: %s holds the programs and libraries\n  %s\nand a Windows "
                             "archive of %s holds\n  %s\nNothing has been signed."
                             % (name, ", ".join(signable) or "none", program, ", ".join(wanted)))
        unpacked[name] = (work, inside, signable, end)
    return unpacked


def distinct_files(unpacked):
    """The files to sign, each distinct one once: digest -> its places.

    The window's archive carries the very certdoctor.exe the command line's
    archive does - build_release.sh packs one build into both - and signing it
    twice would ask the card twice and publish two certdoctor.exe for one
    release that differ in their timestamps. So a file is signed once and its
    signed bytes copied to every other place it is. The same name in two
    archives for one system has to be the same file, or the release packed two
    builds of one program.
    """
    by_digest, by_place = {}, {}
    for name, (work, _inside, signable, end) in sorted(unpacked.items()):
        for rel in signable:
            digest = sha256_of(os.path.join(work, rel))
            by_digest.setdefault(digest, []).append((name, rel))
            by_place.setdefault((end, rel), set()).add(digest)
    split = ["%s in the archives ending %s" % (rel, end) for (end, rel), digests
             in sorted(by_place.items()) if len(digests) > 1]
    if split:
        raise SystemExit("sign_release: one name, two files - %s differ between the archives that "
                         "carry them, and a release packs one build of each program.\n"
                         "Nothing has been signed." % ", ".join(split))
    return by_digest


def sign_windows(directory, version, thumbprint, pin, signtool, dry_run):
    """Sign every program and library of the Windows archives, each distinct
    file once, and put each archive back together whole."""
    unpacked = unpack_windows(directory, version)
    places = distinct_files(unpacked)
    for digest, where in sorted(places.items(), key=lambda item: item[1][0]):
        first = os.path.join(unpacked[where[0][0]][0], where[0][1])
        command = [signtool, "sign", "/sha1", thumbprint, "/fd", "sha256",
                   "/tr", TIMESTAMP_URL, "/td", "sha256", "/v", first]
        if dry_run:
            print("    DRY RUN, would run: %s" % " ".join(command))
        else:
            run(command)
            run([signtool, "verify", "/pa", "/v", first])
            actual = certificate_of(first)
            if actual != pin:
                raise SystemExit(
                    "sign_release: %s in %s was signed by a DIFFERENT certificate\n"
                    "  expected %s\n  got      %s\nNothing has been uploaded."
                    % (where[0][1], where[0][0], pin, actual))
        signed = sha256_of(first)
        for name, rel in where[1:]:
            copy = os.path.join(unpacked[name][0], rel)
            shutil.copyfile(first, copy)
            if sha256_of(copy) != signed:
                raise SystemExit("sign_release: %s in %s is not the signed %s after copying it"
                                 % (rel, name, where[0][1]))
        print("    %s: %s%s" % (where[0][1], "would be signed" if dry_run else "signed",
                                 "".join(", and copied into %s" % name for name, _rel in where[1:])))

    for name, (work, inside, _signable, _end) in sorted(unpacked.items()):
        path = os.path.join(directory, name)
        if dry_run:
            shutil.rmtree(work)
            continue
        os.remove(path)
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            for rel in files_under(work):
                archive.write(os.path.join(work, rel), rel)
        # What went in is what comes out. A repack that lost a file would be the
        # quietest defect this script could have, so it is counted, not trusted.
        with zipfile.ZipFile(path) as archive:
            repacked = sorted(n for n in archive.namelist() if not n.endswith("/"))
        if repacked != inside:
            raise SystemExit("sign_release: %s was repacked with %d file(s) and held %d\n"
                             "Nothing has been uploaded." % (name, len(repacked), len(inside)))
        shutil.rmtree(work)
        print("    %s: repacked, %d file(s)" % (name, len(repacked)))
    print("  %d distinct file(s) %s across %d archive(s)"
          % (len(places), "would be signed" if dry_run else "signed", len(unpacked)))


def macos_archives(directory, version):
    """The archives the Mac signs, by the table."""
    names = sorted(n for n, (_p, _e, where) in archive_names(version).items() if where == "mac")
    for name in names:
        if not os.path.isfile(os.path.join(directory, name)):
            raise SystemExit("sign_release: %s is not in the build" % name)
    return names


def sign_macos(label, directory, version, host, profile, dry_run):
    """Hand the macOS archives to the Mac, and take back signed ones.

    -t because the script over there asks for the keychain password on the
    terminal. A password given that way is not in argv, so it is not in ps,
    and it is nowhere in this repository.

    The address of the Mac is an argument rather than a constant. A machine
    address is not something a public repository should carry.
    """
    names = macos_archives(directory, version)
    if dry_run:
        print("  DRY RUN, would sign %s on %s" % (", ".join(names), host))
        return
    before = {name: sha256_of(os.path.join(directory, name)) for name in names}
    remote = "certdoctor-signing-%s" % label
    run(["ssh", host, "rm -rf %s && mkdir -p %s/dist" % (remote, remote)])
    run(["scp", os.path.join(".github", "scripts", "sign_macos.sh"), "%s:%s/" % (host, remote)])
    for name in names:
        run(["scp", os.path.join(directory, name), "%s:%s/dist/" % (host, remote)])
    run(["ssh", "-t", host, "bash %s/sign_macos.sh %s/dist %s %s"
         % (remote, remote, pinned(APPLE_PIN), profile)])
    for name in names:
        run(["scp", "%s:%s/dist/%s" % (host, remote, name), directory])
    run(["ssh", host, "rm -rf %s" % remote])
    # An archive handed back with the bytes it went with was not signed, and
    # the script over there says so itself - this is the same question asked
    # of what came back rather than of what was said.
    unchanged = [name for name in names if sha256_of(os.path.join(directory, name)) == before[name]]
    if unchanged:
        raise SystemExit("sign_release: %s came back from the Mac unchanged, so it was not signed"
                         % ", ".join(unchanged))
    print("  %s signed, notarised and stapled" % ", ".join(names))


def name_for_publication(directory, tag):
    """Give the build's own files the names a person will see, or drop them.

    build.sha256 was the subject list of the statement the runner made. It
    describes archives that no longer exist in that form, so publishing it
    beside the real checksums would put two lists on one page, one of them
    wrong about five files. The provenance bundle stays, under a name a person
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

    # Each asked for with its whole name. A suffix would be happy with a file
    # the prefix fell off, and the prefix is what keeps these at the end.
    missing = [n for n in sorted(archive_names(version)) if n not in names]
    extra = [n for n in names if n.endswith((".zip", ".tar.gz")) and n not in archive_names(version)]
    # One installer for a release, none for a candidate - the rule build_msi.py
    # refuses a candidate's installer by.
    installer = INSTALLER % version
    if not is_candidate(version) and installer not in names:
        missing.append(installer)
    extra += [n for n in names if n.endswith(".msi") and (is_candidate(version) or n != installer)]
    for needed in (AUX_PREFIX + "SHA256SUMS.txt",
                   "%scertdoctor_%s.spdx.json" % (AUX_PREFIX, version),
                   "%scertdoctor_%s.provenance.sigstore.json" % (AUX_PREFIX, version),
                   statement):
        if needed not in names:
            missing.append(needed)
    if missing or extra:
        raise SystemExit("sign_release: the draft is not complete -%s%s\nIt holds: %s"
                         % (" missing " + ", ".join(missing) if missing else "",
                            " and it carries files no release has: " + ", ".join(extra) if extra else "",
                            ", ".join(names)))
    if not release.get("isDraft"):
        raise SystemExit("sign_release: %s is no longer a draft. Nothing here publishes, so "
                         "somebody or something else did." % tag)
    print("  the draft holds %d file(s) and is still a draft" % len(names))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("tag", nargs="?", help="the release tag, for example v0.1.0")
    parser.add_argument("--rehearsal", type=int, metavar="RUN",
                        help="sign the build of this run of release.yml by hand, upload nothing")
    parser.add_argument("--dry-run", action="store_true",
                        help="everything except signing, uploading and dispatching")
    parser.add_argument("--wait", type=int, default=300,
                        help="seconds to wait for the statement (default 300)")
    parser.add_argument("--macos-host", default=os.environ.get("CERTDOCTOR_MACOS_HOST"),
                        help="user@host of the Mac that signs the macOS archives, "
                             "or set CERTDOCTOR_MACOS_HOST")
    parser.add_argument("--notary-profile",
                        default=os.environ.get("CERTDOCTOR_NOTARY_PROFILE", "certdoctor-notary"),
                        help="the notarytool keychain profile on the Mac "
                             "(default certdoctor-notary, or set CERTDOCTOR_NOTARY_PROFILE)")
    args = parser.parse_args(argv)

    if not os.path.isfile(PIN_FILE):
        raise SystemExit("sign_release: run this from the root of the repository")
    rehearsal = args.rehearsal is not None
    if rehearsal == (args.tag is not None):
        raise SystemExit("sign_release: give a tag to sign a release, or --rehearsal <run> to "
                         "rehearse on a run by hand - one of the two")
    if rehearsal and args.rehearsal <= 0:
        raise SystemExit("sign_release: %d is not the number of a run" % args.rehearsal)
    if not rehearsal and not TAG_SHAPE.match(args.tag):
        raise SystemExit("sign_release: %r is not the tag of a release, which looks like v0.1.0"
                         % args.tag)
    if not args.macos_host:
        raise SystemExit(
            "sign_release: no Mac to sign the macOS archives on.\n"
            "Pass --macos-host user@host, or set CERTDOCTOR_MACOS_HOST.\n"
            "A bare macOS binary cannot carry a notarisation ticket, so those\n"
            "archives are refused by Gatekeeper unless this step runs.")
    windows_pin = pinned(WINDOWS_PIN)
    pinned(APPLE_PIN)
    renderer_files()
    label = "rehearsal-%d" % args.rehearsal if rehearsal else args.tag
    work = os.path.join("dist", "signing", label)

    print("\nbefore anything: can the Mac be reached")
    reach_the_mac(args.macos_host)

    steps = 8 if rehearsal else 10
    if rehearsal:
        print("\n[1/%d] fetching the build of run %d - a REHEARSAL, nothing will be uploaded"
              % (steps, args.rehearsal))
        version, ref = fetch_rehearsal(args.rehearsal, work)
        print("\n[2/%d] checking it before touching it" % steps)
        check_archives(work, version)
    else:
        version, ref = args.tag[1:], args.tag
        print("\n[1/%d] fetching the build for %s" % (steps, args.tag))
        fetch_build(args.tag, work)
        print("\n[2/%d] checking it before touching it" % steps)
        verify_before_touching(work, version)

    with tagged_tree(ref) as tree:
        print("\n[3/%d] whether the installer can be built, before the card signs anything" % steps)
        check_installer(tree, version)

        print("\n[4/%d] the card" % steps)
        thumbprint = signing_thumbprint(windows_pin)
        signtool = find_signtool()

        print("\n[5/%d] signing the Windows programs and libraries" % steps)
        sign_windows(work, version, thumbprint, windows_pin, signtool, args.dry_run)

        print("\n[6/%d] signing the macOS bundles on %s" % (steps, args.macos_host))
        sign_macos(label, work, version, args.macos_host, args.notary_profile, args.dry_run)

        print("\n[7/%d] building and signing the Windows installer" % steps)
        build_installer(tree, work, version, thumbprint, windows_pin, signtool, args.dry_run)

    print("\n[8/%d] checksums over what will be published" % steps)
    if not rehearsal:
        name_for_publication(work, args.tag)
    digest = write_checksums(work)
    print("  %sSHA256SUMS.txt: %s" % (AUX_PREFIX, digest))

    if rehearsal:
        print("\nDone. The rehearsal %s %s in %s." % (
            "would have signed" if args.dry_run else "signed", version, work))
        print("Nothing was uploaded and no draft was touched. These files are signed and are")
        print("NOT a release: look at them, then delete the folder.")
        return 0

    print("\n[9/%d] uploading to the draft" % steps)
    upload_to_draft(args.tag, work, args.dry_run)
    ask_for_the_statement(args.tag, digest, args.dry_run)

    print("\n[10/%d] waiting for the statement and checking the draft" % steps)
    confirm_draft(args.tag, args.wait, args.dry_run)

    print("\nDone. %s is a complete DRAFT." % args.tag)
    print("Read it, then publish it from the Releases page.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except subprocess.CalledProcessError as failed:
        # The command that failed has printed its own reason just above -
        # sign_macos.sh, signtool and wix each say why - and a Python traceback
        # under that sentence only pushes it off the screen.
        sys.exit("sign_release: %s stopped with exit code %d, and the lines above say why."
                 % (os.path.basename(str(failed.cmd[0])), failed.returncode))
