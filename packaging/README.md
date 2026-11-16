# Package sources: WinGet, Chocolatey and the Windows installer

These are **templates**, not packages. Every `{{PLACEHOLDER}}` is filled by
`.github/scripts/build_packages.py` from the one place that owns the value: the
version from the release tag, the checksums from that release's
`verify-SHA256SUMS.txt`, the release date from `CHANGELOG.md`, and the
installer's file name, its `UpgradeCode`, the product's name, the publisher, the
repository and the site from `.github/scripts/build_msi.py`, which builds the
installer the packages point at. The two values the renderer keeps a copy of,
the licence and the copyright line, are held to their Go originals by a guard.

    python .github/scripts/build_packages.py --tag vX.Y.Z \
        --sums verify-SHA256SUMS.txt --out <a directory outside the repository>

The renderer refuses, with a sentence that names the input and says what to do,
and never a traceback: a release candidate or a version that is not a tag, a
checksum file of another release or one missing a file the packages download, a
checksum file that is missing, unreadable, not a regular file, not UTF-8 or over
a megabyte, a destination inside the repository - compared as a resolved path,
so a link or a junction does not get round it - or one that already holds
something, and a value that would break the file it lands in. It renders into a
working folder beside the destination and renames it at the end, so a run that
fails leaves nothing behind.

## Four packages, two in each feed

| | the whole product | the command line alone |
|---|---|---|
| WinGet | `DonislawDev.CertDoctor` | `DonislawDev.CertDoctor.CLI` |
| Chocolatey | `cert-doctor` | `cert-doctor-cli` |
| what it installs | the Windows installer `certdoctor-setup_<version>_windows_amd64.msi`, and in WinGet the window's archive `certdoctor-gui_<version>_windows_amd64.zip` as a second installer | the archive `certdoctor_<version>_windows_amd64.zip`, and `arm64` as well in WinGet |
| commands | `certdoctor-gui` and `certdoctor` | `certdoctor` |

The whole product carries the command line as well, so a machine needs one of
the two. The command line alone is for a build agent or a server without a
desktop, which would otherwise download the window and its software renderer -
56 MB instead of 13. Each package stands alone, so one waiting in moderation
does not hold the other.

A template named `name.<kind>.ext.in` belongs to one kind of package only
(`full` or `cli`). One named `name.ext.in` belongs to every package.

## What each package has to get right

**Every package downloads the release's own files** by address and checksum and
carries none of them, so what a feed installs is the file the release page
publishes, checksum and all. A published release is never changed, so neither
the address nor the checksum stops matching.

**WinGet, the whole product: the installer first, the archive second.** Only the
Windows installer puts Cert Doctor in the Start menu - a portable package cannot
have a Start menu entry at all, the manifest schema has no field for one
([microsoft/winget-cli#2299](https://github.com/microsoft/winget-cli/issues/2299)).
The installer comes first because that decides a fresh install: recent clients
prefer it over a portable package, and older ones take the first installer that
applies. It installs for every account on the machine and asks for
administrator rights, and WinGet knows it again by its `UpgradeCode`. The
archive comes second, for `--scope user`, which needs no administrator rights.

**WinGet, both archives: `ArchiveBinariesDependOnPath: true`.** The window looks
for the command line it runs and for its software renderer beside the path it
was started from. Through the symbolic link WinGet would otherwise make, it
would find neither. With the field, WinGet makes no link and puts the package's
own folder on `PATH`, which puts both programs there. The command line would
work either way, but without the field its shape depends on the machine.

**Chocolatey, the whole product: the Windows installer.** The same installer a
person downloads, run silently, so the Start menu entry and `PATH` come from it
and nothing in the package makes or removes them. The uninstall finds the
program by its `UpgradeCode`, never by the name in Programs and Features, and a
program already removed from Settings is not a failure. A running Cert Doctor is
not closed: 3010, a restart that removes the old copy, counts as success.

**Chocolatey, the command line alone: the archive**, unpacked into a folder of
its own under `tools`, and Chocolatey's shim puts `certdoctor` on `PATH`.

**No package ends a running program** - a diagnosis in progress is cut off by
nothing.

The CI job `the Chocolatey packages install and leave` renders the packages of
the latest release, asks the renderer to refuse what looks fine and is wrong,
and installs and removes both Chocolatey packages with
`.github/scripts/check_chocolatey_packages.ps1`. WinGet is not on the runner, so
both manifests are validated and installed by hand before every submission.

## Submitting

Submitting is a person's step and stays one. Nothing here is wired into a
release: a package is published under the project's name to a feed somebody
else moderates.

1. The release is published, and its `verify-SHA256SUMS.txt` is the file you
   render from.
2. Render, then `winget validate` both WinGet folders and `choco pack` both
   nuspecs. The WinGet `ManifestVersion` is the one manifests merged into
   `microsoft/winget-pkgs` carry today, not the newest one documented.
3. Install, run and remove every package on a machine you can break.
4. Chocolatey: `choco push` with the maintainer's key - the package that was
   tested, because `choco pack` makes a new file every time. WinGet: one pull
   request per package against `microsoft/winget-pkgs`, with the three files
   under `manifests/d/DonislawDev/CertDoctor/<version>/` and
   `manifests/d/DonislawDev/CertDoctor/CLI/<version>/`.

A published release asset is never replaced. Every package version names its
file by address and checksum, so a replaced file would break every install of
it.
