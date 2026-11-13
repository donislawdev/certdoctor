#!/usr/bin/env python3
"""Build the Windows installer of one release from the window's signed archive.

    python .github/scripts/build_msi.py --tag v0.1.0 --archives <dir> --out-dir <dir>
    python .github/scripts/build_msi.py --tag v0.1.0 --check
    python .github/scripts/build_msi.py --tag v0.1.0 --source-only
    python .github/scripts/build_msi.py --tag v0.1.0 --product-name

One installer carries both programs, the window and the command line, for every
account on the machine, with the folder on the machine's PATH and the window in
the Start menu (ADR148, decided by the owner on 2026-11-13). The window's amd64
archive holds all of it - both programs, the software renderer and the
documents - so it is built from that archive alone. It is built from the SIGNED
archive, because the signature is on the programs inside it: an installer made
before the card signed them would carry unsigned copies. So a release builds it
in sign_release.py, on the machine with the card, and never in release.yml. The
same script builds an unsigned one in release.yml on a Windows runner, from the
unsigned archive of that run, so that what the installer DOES is asked on a
clean machine before anything is signed.

Every value comes from the tree this script sits in: the template in
packaging/msi/, the names below, the site's address in web/static/CNAME, the
icon. sign_release.py runs it from the tree of the TAG, exported with git
archive, so the installer is built from what was tagged, whatever the checkout
happens to stand on.

--check asks only whether this machine can build it (the tag, the template, the
icon, WiX), so sign_release.py can refuse before the card signs anything.
--source-only prints the rendered installer source and builds nothing, which is
what the guards read. --product-name prints the name the installer carries and
nothing else, which is what sign_release.py signs it with - Windows shows that
name when it asks an administrator to let the installer run.

Exit codes:
    0  the installer was written to --out-dir, or --check found nothing missing
    1  refused, and the message says which input and why

Nothing here signs or publishes anything.
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
TEMPLATE = os.path.join(ROOT, "packaging", "msi", "certdoctor-setup.wxs.in")
ICON = os.path.join(ROOT, "assets", "icon", "certdoctor.ico")
CNAME = os.path.join(ROOT, "web", "static", "CNAME")

# The file a person downloads, public for good (ADR148 decision 2). Not
# certdoctor_*, because that is the command line alone and this carries the
# window too. It sorts between the window's archives and the command line's on
# the release page, never among the verify- files.
NAME = "certdoctor-setup_{version}_windows_amd64.msi"

# The product, not a build, and it never changes - see the comment on it in the
# template. Generated once on 2026-11-13 and pinned by a guard.
UPGRADE_CODE = "8078E22A-32AA-4080-B031-CA470D5D3EB7"

# The WiX this project builds with. Another version builds another package from
# the same source, so a different one is refused rather than used. 5.0.2 because
# the Open Source Maintenance Fee starts with WiX 6, and WiX 3 is out of support.
WIX_VERSION = "5.0.2"

# What Windows calls the program once it is installed (ADR148 decision 1), and
# who made it. The window shows the same name from its catalogue, and both
# programs carry both in their Windows resources - a guard holds the copies
# equal: words.AppName, and ProductName and CompanyName in cmd/*/winres.json.
APP_NAME = "Cert Doctor"
PUBLISHER = "DonislawDev"

# Where Programs and Features sends a person. The repository is the window's
# words.RepositoryURL, held equal by the same guard. The site is read from the
# file that publishes it.
REPOSITORY = "https://github.com/donislawdev/certdoctor"
SHORTCUT_DESCRIPTION = "Finds why this machine cannot connect to a URL"

# The archive the installer is made of, and the two programs that have to be at
# its top: the window, which the shortcut starts, and the command line, which
# PATH finds.
ARCHIVE = "certdoctor-gui_{version}_windows_amd64.zip"
WINDOW_EXE = "certdoctor-gui.exe"
COMMAND_EXE = "certdoctor.exe"

PLACEHOLDER = re.compile(r"\{\{([A-Z_]+)\}\}")

# A value lands in an XML attribute, and some of them in a Windows Installer
# Formatted column, where square brackets name a property. None of the values
# needs any of these, so a value holding one is refused rather than escaped.
BREAKS = set('<>&"\'[]{}$')


def refuse(message):
    raise SystemExit("build_msi: %s" % message)


def parse_version(tag):
    """The version a tag names, or a refusal saying why it gets no installer.

    A tag with a hyphen is a release candidate, the same rule release.yml uses
    to mark one as a pre-release. Windows Installer reads only the three
    numbers, so a candidate's installer would take the release's own version
    and the release could not replace it.
    """
    if "-" in tag:
        refuse("%s is a release candidate, and candidates get no installer. Windows "
               "Installer reads only the three numbers, so it would take %s for the "
               "release itself and the release would not replace it"
               % (tag, tag.split("-")[0]))
    found = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", tag)
    if not found:
        refuse("%r is not a release tag. Pass it the way the release is tagged, for "
               "example v0.1.0" % tag)
    major, minor, patch = (int(n) for n in found.groups())
    if major > 255 or minor > 255 or patch > 65535:
        refuse("%s does not fit an installer version, which holds at most 255 for the "
               "first two numbers and 65535 for the third" % tag)
    return "%d.%d.%d" % (major, minor, patch)


def read_text(path):
    try:
        with open(path, "rb") as handle:
            return handle.read().decode("utf-8")
    except (OSError, UnicodeDecodeError) as err:
        refuse("cannot read %s: %s" % (path, err))


def site():
    """The product site's address, from the file that publishes it."""
    lines = [line.strip() for line in read_text(CNAME).splitlines() if line.strip()]
    if len(lines) != 1 or not re.fullmatch(r"[a-z0-9.-]+", lines[0]):
        refuse("%s does not hold one host name, which is what the site is published "
               "under" % CNAME)
    return "https://%s/" % lines[0]


def values(version, tag):
    """Every placeholder the template may use."""
    return {
        "APP_NAME": APP_NAME,
        "PUBLISHER": PUBLISHER,
        "VERSION": version,
        "UPGRADE_CODE": UPGRADE_CODE,
        "PROJECT_URL": site(),
        "ISSUES_URL": REPOSITORY + "/issues",
        "RELEASE_NOTES_URL": "%s/releases/tag/%s" % (REPOSITORY, tag),
        "SHORTCUT_DESCRIPTION": SHORTCUT_DESCRIPTION,
        "WINDOW_EXE": WINDOW_EXE,
    }


def render(text, table):
    """The template with every placeholder filled, or a refusal naming the one
    that cannot be."""
    used = set(PLACEHOLDER.findall(text))
    unknown = used - set(table)
    if unknown:
        refuse("the template asks for %s, and build_msi.py has no value for it"
               % ", ".join(sorted(unknown)))
    unused = set(table) - used
    if unused:
        refuse("the template uses no %s any more - take it out of build_msi.py"
               % ", ".join(sorted(unused)))
    for key, value in sorted(table.items()):
        bad = sorted(set(value) & BREAKS)
        if bad:
            refuse("the value of %s, %r, holds %s, which would break the installer "
                   "source it lands in" % (key, value, " ".join(bad)))
    return PLACEHOLDER.sub(lambda m: table[m.group(1)], text)


def source(version, tag):
    """The installer source for one release, every placeholder filled."""
    if not os.path.isfile(TEMPLATE):
        refuse("there is no template at %s. Run this from a tree that has one - a tag "
               "from before the installer existed has none" % TEMPLATE)
    return render(read_text(TEMPLATE), values(version, tag))


def find_wix():
    """The wix command, at the version this project builds with, or a refusal."""
    found = shutil.which("wix") or shutil.which(
        "wix", path=os.path.join(os.path.expanduser("~"), ".dotnet", "tools"))
    install = ("    dotnet tool install --global wix --version %s\n"
               "It runs on .NET - install the .NET SDK first if there is no dotnet command."
               % WIX_VERSION)
    if not found:
        refuse("WiX is not installed, and the installer is built with it. Install the "
               "version this project builds with:\n" + install)
    said = subprocess.run([found, "--version"], capture_output=True, text=True)
    version = said.stdout.strip().split("+")[0]
    if said.returncode != 0 or version != WIX_VERSION:
        refuse("%s says it is version %r, and the installer is built with %s - another "
               "version builds another package from the same source. Replace it:\n"
               "    dotnet tool uninstall --global wix\n%s"
               % (found, version, WIX_VERSION, install))
    return found


def safe_name(name):
    """Whether a name inside an archive stays inside the folder it is unpacked into."""
    parts = name.split("/")
    return (bool(name) and not name.startswith("/") and "\\" not in name and ":" not in name
            and all(part not in ("", ".", "..") for part in parts))


def unpack(archives, version, into):
    """The window's amd64 archive, unpacked into one folder, refused unless both
    programs stand at its top.

    One file means one name to Windows, where the installer puts it: LICENSE and
    License are the same file there, so the names are compared folded to one
    case, and an archive holding both is refused rather than unpacked with the
    second over the first.
    """
    name = ARCHIVE.format(version=version)
    path = os.path.join(archives, name)
    if not os.path.isfile(path):
        refuse("%s holds no %s. Pass the folder that holds the archives of this release"
               % (archives, name))
    seen = {}
    try:
        with zipfile.ZipFile(path) as archive:
            for entry in archive.infolist():
                if entry.is_dir():
                    continue
                if not safe_name(entry.filename):
                    refuse("%s holds %r, a name that leads out of the folder it is unpacked "
                           "into. That is not an archive the release built" % (name, entry.filename))
                key = entry.filename.casefold()
                if key in seen:
                    refuse("%s holds %s and %s, one file on Windows. That is not an archive "
                           "the release built" % (name, seen[key], entry.filename))
                seen[key] = entry.filename
                target = os.path.join(into, *entry.filename.split("/"))
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with archive.open(entry) as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst)
    except zipfile.BadZipFile as err:
        refuse("%s is not a zip archive it can read (%s). Download it again" % (path, err))
    for program in (WINDOW_EXE, COMMAND_EXE):
        if program.casefold() not in seen:
            refuse("%s holds no %s at its top, and the installer needs it there. That is "
                   "not the shape the release builds" % (name, program))
    return sorted(seen.values())


def build(tag, archives, out_dir):
    """Write the installer into out_dir, all or nothing, and return its path."""
    version = parse_version(tag)
    text = source(version, tag)
    if not os.path.isdir(out_dir):
        refuse("--out-dir %s is not a folder. Pass one that exists" % out_dir)
    target = os.path.join(out_dir, NAME.format(version=version))
    if os.path.exists(target):
        refuse("%s is already there. Nothing is overwritten - remove it or pass another "
               "--out-dir" % target)
    if not os.path.isfile(ICON):
        refuse("the icon %s is not in the tree" % ICON)

    # Beside nothing of the caller's: sign_release.py hands its own folder of
    # files to publish as --out-dir, and a folder left inside it would be
    # published, or would break the checksums written over it.
    staging = tempfile.mkdtemp(prefix="certdoctor-msi-")
    try:
        payload = os.path.join(staging, "payload")
        os.makedirs(payload)
        unpack(archives, version, payload)
        wix = find_wix()
        wxs = os.path.join(staging, "certdoctor-setup.wxs")
        with open(wxs, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        built = os.path.join(staging, os.path.basename(target))
        command = [wix, "build", wxs, "-arch", "x64", "-pdbtype", "none",
                   "-d", "PayloadDir=" + payload, "-d", "IconFile=" + ICON, "-o", built]
        print("    $ %s" % " ".join(command))
        result = subprocess.run(command)
        if result.returncode != 0 or not os.path.isfile(built):
            refuse("wix build exited %d, and nothing was written to %s. What it said is above"
                   % (result.returncode, out_dir))
        # Moved in only once it is whole, so a run that fails or is stopped
        # leaves no half written installer where the caller would find it.
        shutil.move(built, target)
    except OSError as err:
        refuse("cannot build the installer: %s. Nothing was written to %s" % (err, out_dir))
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return target


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--tag", required=True, help="the release, for example v0.1.0")
    parser.add_argument("--archives", help="the folder holding the window's signed amd64 archive")
    parser.add_argument("--out-dir", help="the folder the installer is written into")
    parser.add_argument("--check", action="store_true",
                        help="only say whether this machine can build it")
    parser.add_argument("--source-only", action="store_true",
                        help="print the installer source and build nothing")
    parser.add_argument("--product-name", action="store_true",
                        help="print the name the installer carries and build nothing")
    args = parser.parse_args(argv)

    if args.source_only:
        sys.stdout.write(source(parse_version(args.tag), args.tag))
        return 0
    if args.product_name:
        print(values(parse_version(args.tag), args.tag)["APP_NAME"])
        return 0
    if args.check:
        version = parse_version(args.tag)
        source(version, args.tag)
        if not os.path.isfile(ICON):
            refuse("the icon %s is not in the tree" % ICON)
        print("ready to build %s with %s" % (NAME.format(version=version), find_wix()))
        return 0
    if not args.archives or not args.out_dir:
        parser.error("--archives and --out-dir are needed to build")
    print(build(args.tag, args.archives, args.out_dir))
    return 0


if __name__ == "__main__":
    sys.exit(main())
