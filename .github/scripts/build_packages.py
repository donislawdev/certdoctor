#!/usr/bin/env python3
"""Render the WinGet and Chocolatey packages of one published release.

    python .github/scripts/build_packages.py --tag vX.Y.Z \\
        --sums verify-SHA256SUMS.txt --out <a directory outside the repository>

Two packages in each feed, decided by the owner on 2026-11-16 (ADR149): the
whole product - the window and the command line - and the command line alone,
for a build agent or a server without a desktop.

    WinGet      DonislawDev.CertDoctor       the Windows installer first, the
                                             window's archive second
                DonislawDev.CertDoctor.CLI   the command line's archive, x64 and arm64
    Chocolatey  cert-doctor                  the Windows installer
                cert-doctor-cli              the command line's archive

The templates in packaging/ hold the shape. This fills them from the one place
each value lives: the version from the tag, the checksums from the release's own
checksum file, the date from CHANGELOG.md, and the installer's file name, its
UpgradeCode, the product's name, the publisher, the repository and the site from
build_msi.py, which built the installer the packages point at. Two values are
copied here, the licence and the copyright line, and a guard holds each to the
Go constant the program's own documents are made from.

Every package downloads the published files by address and checksum and carries
none of them. A published release is never changed, so neither stops matching.

Exit codes:
    0  every package was rendered into --out
    1  refused, and the message says which input and why

Nothing here submits anything. A package is published under the project's name
to a feed somebody else moderates, and that is a person's step.
"""
import argparse
import importlib.util
import os
import re
import shutil
import stat
import sys
import tempfile
from collections import namedtuple

# realpath, not abspath: the check that keeps --out outside the repository
# compares resolved paths, so a link or a junction pointing into the tree cannot
# walk the packages into it.
HERE = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
TEMPLATES = os.path.join(ROOT, "packaging")
TEMPLATE_SUFFIX = ".in"
PLACEHOLDER = re.compile(r"\{\{([A-Z0-9_]+)\}\}")
FEEDS = ("winget", "chocolatey")


def load_installer_script():
    """build_msi.py, the sibling script, loaded from its path.

    By path and not by import name: python -I leaves the script's own folder
    off sys.path, and the release scripts are run that way. Without writing
    bytecode: a loaded module leaves a __pycache__ folder beside its file, and
    that folder would land in the checkout, where a commit would pick it up.
    """
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("build_msi", os.path.join(HERE, "build_msi.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MSI = load_installer_script()

# The manifest schema the WinGet submission pipeline accepts TODAY, and it
# moves. The answer is in what merged manifests carry, not in what the
# winget-pkgs tree documents: in August 2026 the documented 1.28.0 was refused
# within minutes, and on 2026-10-30 the bot marked 1.12.0 deprecated and asked
# for 1.28.0. On 2026-11-16, 14 of the 19 installer manifests read from the last
# 25 commits of winget-pkgs carried 1.28.0 and 5 carried 1.12.0. Read it again
# before every submission.
WINGET_SCHEMA = "1.28.0"

# Held by a guard to ourLicence in cmd/sbom/licences.go and ourCopyright in
# cmd/sbom/spdx.go. Chocolatey's moderation asks for a copyright of at least four
# characters (rule CPMR0001), and the nuspec cannot hold a copyright sign
# unescaped, hence (C).
LICENCE = "GPL-3.0-only"
COPYRIGHT = "Copyright (C) 2026 DonislawDev"

ICON = "assets/icon/certdoctor.png"

# WinGet's name for an architecture, keyed by the one the archive names use.
WINGET_ARCH = {"amd64": "x64", "arm64": "arm64"}

# kind: "full" is the whole product, "cli" the command line alone.
# archive: what WinGet unpacks for the package - the full package's second
# installer, and the command line package's only one. Chocolatey's full package
# installs the Windows installer and no archive.
# command: the program WinGet points the package at, and the moniker.
Package = namedtuple("Package", "kind winget_id choco_id title archive arches command")

PACKAGES = (
    Package("full", "DonislawDev.CertDoctor", "cert-doctor", MSI.APP_NAME,
            MSI.ARCHIVE.replace("amd64", "{arch}"), ("amd64",), MSI.WINDOW_EXE),
    Package("cli", "DonislawDev.CertDoctor.CLI", "cert-doctor-cli", MSI.APP_NAME + " CLI",
            "certdoctor_{version}_windows_{arch}.zip", ("amd64", "arm64"), MSI.COMMAND_EXE),
)

DESCRIPTION = (
    "Cert Doctor finds out why this machine or this container cannot connect to a URL, and "
    "what to run to fix it. One run walks the whole path - DNS, the proxy and its PAC script, "
    "TCP, TLS - and then asks each trust store on the machine whether it trusts what the "
    "server presented: the Windows store, every Java installation, every git, curl and node, "
    "every Python and its pip. It prints the command that fixes each store that does not, "
    "and runs none of them. It connects only where you point it, and the only file it writes "
    "is the report, at the path you name."
)

SHORT = {
    "full": "Finds out why this machine cannot connect to a URL, and what to run to fix it. "
            "The window and the command line.",
    "cli": "Finds out why this machine cannot connect to a URL, and what to run to fix it. "
           "The command line alone, for scripts and build agents.",
}

TAGS = ("tls", "ssl", "certificates", "proxy", "pac", "dns", "diagnostics", "trust-store")
KIND_TAG = {"full": "gui", "cli": "cli"}


def how_to_start(package, feed):
    """The paragraph that differs by package and feed: what it gives and how to start it."""
    other = next(p for p in PACKAGES if p is not package)
    other_id = other.winget_id if feed == "winget" else other.choco_id
    if package.kind == "cli":
        return ("This package is the command line alone, for scripts and build agents. The "
                "package %s has the window as well. Open a new terminal and type certdoctor "
                "followed by the address that fails, or certdoctor --help." % other_id)
    if feed == "winget":
        return ("This package is the window and the command line. WinGet installs it with the "
                "Windows installer, for every account on the machine, and asks for administrator "
                "rights. That puts Cert Doctor in the Start menu and certdoctor-gui and certdoctor "
                "on PATH, so the package %s is not needed beside it. With --scope user it needs "
                "no administrator rights, but WinGet installs the window's archive instead, which "
                "has no Start menu entry - open a new terminal and type certdoctor-gui." % other_id)
    return ("This package installs Cert Doctor with its Windows installer, for every account on "
            "the machine: the window in the Start menu, and certdoctor-gui and certdoctor on "
            "PATH. The package %s is the command line alone and is not needed beside this "
            "one." % other_id)


def refuse(message):
    raise SystemExit("build_packages: %s" % message)


def read_text(path):
    """A file of this repository - the templates and the changelog.

    These are not inputs a person chooses, so a failure here is a broken
    checkout and a traceback says so. What a person DOES choose - the checksum
    file - is read by read_sums, which refuses with a sentence instead.
    """
    with open(path, encoding="utf-8-sig") as handle:
        return handle.read().replace("\r\n", "\n")


def parse_tag(tag):
    """The version a tag names, by the installer's own rule.

    The full package in both feeds IS the Windows installer, and a release
    candidate gets none, so build_msi.py's refusal is the answer here too - one
    rule for a candidate, held by a guard.
    """
    try:
        return MSI.parse_version(tag)
    except SystemExit as err:
        refuse("%s. Both feeds get published releases only" % str(err).replace("build_msi: ", "", 1))


def release_date(version):
    """The date the changelog gives the version - one reader, not a second answer."""
    found = re.search(r"^## \[%s\] - (\d{4}-\d{2}-\d{2})\s*$" % re.escape(version),
                      read_text(os.path.join(ROOT, "CHANGELOG.md")), re.M)
    if not found:
        refuse("CHANGELOG.md has no dated section for %s. Package a version that has "
               "been released" % version)
    return found.group(1)


# A release's checksum file is about a kilobyte - 1147 bytes for v0.2.0.
# Anything near this is another file passed by mistake, an archive for
# instance, and reading stops one byte past it.
SUMS_LIMIT = 1024 * 1024


def read_sums(path):
    """{file name: lowercase sha256} from a checksum file, in any of its spellings.

    sha256sum writes '<hash>  <name>' in text mode and '<hash> *<name>' in binary
    mode, and that star is not part of the name. A file saved on Windows may
    carry a byte order mark and CRLF. None of that may reach an address.
    """
    # Opened once and read at most one byte past the limit, from a regular file
    # only: a size asked for first and a read made after could see two different
    # files, and a pipe or a device has no size to ask.
    hint = "Download verify-SHA256SUMS.txt from the release you are packaging and pass that"
    try:
        with open(path, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                refuse("%s is not a file. %s" % (path, hint))
            data = handle.read(SUMS_LIMIT + 1)
    except OSError as err:
        refuse("cannot read the checksum file %s: %s. %s" % (path, err.strerror or err, hint))
    if len(data) > SUMS_LIMIT:
        refuse("%s is larger than %d bytes, so it is not a release's checksum file. %s"
               % (path, SUMS_LIMIT, hint))
    try:
        text = data.decode("utf-8-sig").replace("\r\n", "\n")
    except UnicodeDecodeError:
        refuse("%s is not UTF-8 text, so it is not a release's checksum file. %s" % (path, hint))
    sums = {}
    for number, line in enumerate(text.split("\n"), 1):
        if not line.strip():
            continue
        found = re.fullmatch(r"([0-9A-Fa-f]{64}) [ *](\S.*)", line.strip())
        if not found:
            refuse("%s line %d is not '<sha256>  <file>': %r" % (path, number, line))
        sums[found.group(2).strip()] = found.group(1).lower()
    return sums


def archives(package, version):
    return {arch: package.archive.format(version=version, arch=arch) for arch in package.arches}


def another_release(sums, pattern):
    """The hint for a missing line: a name that fits the pattern with another version."""
    other = sorted(n for n in sums if re.fullmatch(
        re.escape(pattern).replace(r"\{version\}", r"[^_]+"), n))
    return (" It lists %s - that is the checksum file of another release." % other[0]
            if other else "")


def checked_files(sums, version, path):
    """Every file the packages download, with its checksum, or a refusal naming what is missing."""
    wanted = [(MSI.NAME, MSI.NAME.format(version=version))]
    for package in PACKAGES:
        for arch, name in archives(package, version).items():
            wanted.append((package.archive.replace("{arch}", arch), name))
    found = {}
    for pattern, name in wanted:
        if name not in sums:
            refuse("%s has no line for %s.%s Download the checksum file of the release you are "
                   "packaging." % (path, name, another_release(sums, pattern)))
        found[name] = sums[name]
    return found


def values(package, version, tag, sums):
    """Every placeholder a template may use, for one package."""
    repo_url = MSI.REPOSITORY
    repo = repo_url.split("github.com/", 1)[1]
    download = "%s/releases/download/%s/" % (repo_url, tag)
    names = archives(package, version)
    msi = MSI.NAME.format(version=version)
    installers = []
    for arch, name in names.items():
        installers += ["- Architecture: %s" % WINGET_ARCH[arch],
                       "  InstallerUrl: %s%s" % (download, name),
                       "  InstallerSha256: %s" % sums[name].upper()]
    return {
        "VERSION": version,
        "WINGET_SCHEMA": WINGET_SCHEMA,
        "WINGET_ID": package.winget_id,
        "CHOCO_ID": package.choco_id,
        "TITLE": package.title,
        "PUBLISHER": MSI.PUBLISHER,
        "EXE": package.command,
        "PROGRAM": package.command[:-len(".exe")],
        "MONIKER": package.command[:-len(".exe")],
        "LICENSE": LICENCE,
        "COPYRIGHT": COPYRIGHT,
        "REPO_URL": repo_url,
        "PROJECT_URL": MSI.site(),
        "DOCS_URL": MSI.site() + "docs/",
        "LICENSE_URL": "%s/blob/%s/LICENSE" % (repo_url, tag),
        "RELEASE_NOTES_URL": "%s/releases/tag/%s" % (repo_url, tag),
        "PACKAGE_SOURCE_URL": "%s/tree/main/packaging/chocolatey" % repo_url,
        # A CDN pinned to the tag, both halves load-bearing: Chocolatey's
        # moderation refuses raw.githubusercontent.com and github.com/.../raw
        # alike, and an icon on a branch keeps changing under an approved package.
        "ICON_URL": "https://cdn.jsdelivr.net/gh/%s@%s/%s" % (repo, tag, ICON),
        "RELEASE_DATE": release_date(version),
        "MSI_URL": download + msi,
        "MSI_SHA256": sums[msi],
        "WINGET_MSI_SHA256": sums[msi].upper(),
        # In braces, as Windows Installer spells a code and as merged manifests
        # in winget-pkgs carry it - WinGet compares it exactly.
        "UPGRADE_CODE": "{%s}" % MSI.UPGRADE_CODE,
        "URL_AMD64": download + names["amd64"],
        "SHA256_AMD64": sums[names["amd64"]],
        "WINGET_SHA256_AMD64": sums[names["amd64"]].upper(),
        "SHORT_DESCRIPTION": SHORT[package.kind],
        "DESCRIPTION": DESCRIPTION,
        "WINGET_HOW_TO_START": how_to_start(package, "winget"),
        "CHOCO_HOW_TO_START": how_to_start(package, "chocolatey"),
        "WINGET_TAGS": "\n".join("- " + t for t in TAGS + (KIND_TAG[package.kind],)),
        "CHOCO_TAGS": " ".join(TAGS + (KIND_TAG[package.kind],)),
        "WINGET_INSTALLERS": "\n".join(installers),
    }


# What a value substituted inside a line must not hold, by the file it lands in.
# Each would still render, and each would hand the feed a file that means
# something else: a quote ends a PowerShell string early, a bracket or an
# ampersand is markup in the nuspec, and a colon followed by a space or a space
# followed by a hash turns the rest of a plain YAML value into a key or a
# comment.
BREAKS = (
    (".ps1", "'", "a single quote ends the PowerShell string it sits in"),
    (".nuspec", "<", "the nuspec reads it as markup"),
    (".nuspec", ">", "the nuspec reads it as markup"),
    (".nuspec", "&", "the nuspec reads it as markup"),
    (".yaml", ": ", "YAML reads the rest as a key"),
    (".yaml", " #", "YAML reads the rest as a comment"),
)


def breaking(name, value):
    for suffix, text, why in BREAKS:
        if name.endswith(suffix) and text in value:
            return why
    return ""


def render(text, table, name):
    """Fill every placeholder, or refuse. An unknown one is an error, never an empty string.

    A placeholder alone on its line may hold several lines, and each takes the
    indentation the placeholder had - that is how a YAML block stays a block. A
    placeholder inside a line takes one line only.
    """
    out = []
    for line in text.split("\n"):
        for key in PLACEHOLDER.findall(line):
            if key not in table:
                refuse("%s uses {{%s}}, which the renderer does not know" % (name, key))
        alone = re.fullmatch(r"( *)\{\{([A-Z0-9_]+)\}\}", line)
        if alone:
            out += [alone.group(1) + part if part else "" for part in table[alone.group(2)].split("\n")]
            continue
        for key in PLACEHOLDER.findall(line):
            if "\n" in table[key]:
                refuse("%s puts the several lines of {{%s}} inside a line" % (name, key))
            breaks = breaking(name, table[key])
            if breaks:
                refuse("{{%s}} holds %r, which breaks %s: %s" % (key, table[key], name, breaks))
        out.append(PLACEHOLDER.sub(lambda m: table[m.group(1)], line))
    return "\n".join(out)


def check_script(text, name):
    """A package script is read by Windows PowerShell 5.1, which takes a file without a
    byte order mark as the machine's ANSI code page - so a script that is not ASCII
    reaches it changed."""
    for number, line in enumerate(text.split("\n"), 1):
        if any(ord(c) > 127 for c in line):
            refuse("%s line %d is not ASCII: %r" % (name, number, line))


def templates(kind):
    """(template path, output path relative to the package) for one kind of package.

    A template named name.<kind>.ext.in belongs to that kind only, and renders to
    name.ext. One named name.ext.in belongs to every package.
    """
    kinds = {p.kind for p in PACKAGES}
    for feed in FEEDS:
        for base, _, files in os.walk(os.path.join(TEMPLATES, feed)):
            for file in sorted(files):
                if not file.endswith(TEMPLATE_SUFFIX):
                    continue
                parts = file[:-len(TEMPLATE_SUFFIX)].split(".")
                owner = parts[1] if len(parts) > 2 and parts[1] in kinds else None
                if owner not in (None, kind):
                    continue
                target = ".".join(p for i, p in enumerate(parts) if not (i == 1 and owner))
                relative = os.path.relpath(os.path.join(base, target), TEMPLATES)
                yield os.path.join(base, file), relative.replace(os.sep, "/")


def destination(package, relative, version):
    """Where a rendered file goes: WinGet's in the folder layout winget-pkgs uses, so
    the three files can be copied across as they are."""
    feed, _, rest = relative.partition("/")
    if feed == "winget":
        kind = rest[:-len(".yaml")]
        name = package.winget_id + ("" if kind == "version" else "." + kind) + ".yaml"
        parts = package.winget_id.split(".")
        return "/".join(["winget", "manifests", parts[0][0].lower()] + parts + [version, name])
    if rest == "package.nuspec":
        rest = package.choco_id + ".nuspec"
    return "/".join(["chocolatey", package.choco_id, rest])


def check_out(out):
    """--out is outside the repository and empty or absent, or a refusal."""
    out = os.path.realpath(out)
    root = os.path.normcase(ROOT)
    if os.path.normcase(out) == root or os.path.normcase(out).startswith(root + os.sep):
        refuse("--out %s is inside the repository. Rendered packages are not source - put "
               "them somewhere outside it" % out)
    if os.path.exists(out):
        try:
            holds = not os.path.isdir(out) or bool(os.listdir(out))
        except OSError as err:
            refuse("cannot look inside --out %s: %s. Pass a new directory, or one you can "
                   "read and write" % (out, err.strerror or err))
        if holds:
            refuse("--out %s already holds something. Nothing is overwritten - pass an empty "
                   "or new directory" % out)
    return out


def missing_folders(path):
    """The folders of path that do not exist yet, deepest first - what this run
    will have made, and the most a failed run may take away again."""
    made = []
    while not os.path.exists(path):
        made.append(path)
        up = os.path.dirname(path)
        if up == path:
            break
        path = up
    return made


def remove_empty(folders):
    """Remove the folders this run made, deepest first, stopping at the first one
    that is not empty - it then holds something that is not ours."""
    for folder in folders:
        try:
            os.rmdir(folder)
        except OSError:
            return


def build(tag, sums_path, out):
    """Render every package into out, all or nothing."""
    version = parse_tag(tag)
    out = check_out(out)
    sums = checked_files(read_sums(sums_path), version, sums_path)
    if not os.path.isfile(os.path.join(ROOT, ICON)):
        refuse("the icon %s is not in the repository" % ICON)

    parent = os.path.dirname(out)
    made = missing_folders(parent)
    try:
        os.makedirs(parent, exist_ok=True)
        work = tempfile.mkdtemp(prefix=".packages-", dir=parent)
    except OSError as err:
        remove_empty(made)
        refuse("cannot create a working folder in %s: %s. Check that you can write there, "
               "or pass another --out" % (parent, err.strerror or err))
    finished = False
    try:
        used = {key for package in PACKAGES for source, _ in templates(package.kind)
                for key in PLACEHOLDER.findall(read_text(source))}
        known = set()
        for package in PACKAGES:
            table = values(package, version, tag, sums)
            known |= set(table)
            for source, relative in templates(package.kind):
                rendered = render(read_text(source), table, relative)
                if relative.endswith(".ps1"):
                    check_script(rendered, relative)
                target = os.path.join(work, *destination(package, relative, version).split("/"))
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, "w", encoding="utf-8", newline="\n") as handle:
                    handle.write(rendered)
        if known - used:
            refuse("no template uses %s any more - take it out of the renderer"
                   % ", ".join(sorted(known - used)))
        if os.path.isdir(out):
            os.rmdir(out)
        os.rename(work, out)
        finished = True
    except OSError as err:
        refuse("cannot write the packages to %s: %s. Check that you can write there, or "
               "pass another --out. Nothing was left behind" % (out, err.strerror or err))
    finally:
        # A refusal is a SystemExit, so it reaches here too: nothing half
        # rendered, and no folder this run made, outlives a run that failed.
        if os.path.isdir(work):
            shutil.rmtree(work)
        if not finished:
            remove_empty(made)
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--tag", required=True, help="the published release, for example v0.2.0")
    parser.add_argument("--sums", required=True, help="that release's verify-SHA256SUMS.txt")
    parser.add_argument("--out", required=True, help="an empty or new directory outside the repository")
    args = parser.parse_args(argv)
    out = build(args.tag, args.sums, args.out)
    for base, _, files in sorted(os.walk(out)):
        for file in sorted(files):
            print(os.path.join(base, file))
    return 0


if __name__ == "__main__":
    sys.exit(main())
