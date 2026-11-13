Why this machine, or this container, cannot reach that URL - DNS, proxy and PAC, TCP, TLS, and the trust store of every runtime on the machine, with the commands that fix each one.

## What to download

Two programs. **certdoctor** is the command line, in five builds:

- `certdoctor_<version>_windows_amd64.zip` and `certdoctor_<version>_windows_arm64.zip`
- `certdoctor_<version>_linux_amd64.tar.gz` and `certdoctor_<version>_linux_arm64.tar.gz`
- `certdoctor_<version>_macos_arm64.tar.gz`, for Apple silicon

**certdoctor-gui** is a window for the same diagnosis: type the address, press Diagnose, read the report, and save it as HTML, Markdown or JSON. It runs the command line that sits next to it, so its archive carries both programs:

- `certdoctor-gui_<version>_windows_amd64.zip`
- `certdoctor-gui_<version>_linux_amd64.tar.gz`
- `certdoctor-gui_<version>_macos_arm64.tar.gz`, for Apple silicon

**On Windows on x64 you can install Cert Doctor instead** with `certdoctor-setup_<version>_windows_amd64.msi`. It puts both programs in `C:\Program Files\Cert Doctor` for every account, adds that folder to the system `PATH` and puts Cert Doctor in the Start menu. It installs the same files as the window's archive for Windows, a newer version installs over it, and it closes nothing that is running. A pre-release has no installer.

Take the archive for your system and architecture. Every archive carries `LICENSE`, `README.md` and `THIRD-PARTY-NOTICES.md`, and the window's archives also `THIRD-PARTY-NOTICES-GUI.md`.

The command line's Linux builds are static and run in a container with no C library at all, so the binary can be copied into an image on its own - `certdoctor --license` prints the notices that travel with it.

Keep the files of the window's archive together: the window starts `certdoctor` from its own folder. On Windows the `opengl` folder holds a software renderer, which the window uses when the graphics driver offers no OpenGL 2.1 - in a virtual machine without 3D acceleration, or over Remote Desktop. On Linux the window needs a desktop session with OpenGL: it loads `libGL.so.1` and `libwayland-client.so.0`, which a desktop installation has.

Check what you downloaded against `verify-SHA256SUMS.txt`, at the bottom of this list.

## Signing

**The Windows programs are signed** - `certdoctor.exe`, `certdoctor-gui.exe`, the two libraries of the software renderer in the window's `opengl` folder, and the installer. Each signature carries a timestamp and is issued by Certum. Windows checks it when you run the program, and shows whose it is when the installer asks for administrator rights. The `certdoctor.exe` in the window's archive is the same file as the one in the command line's archive.

**The macOS programs are signed and notarised by Apple.** The command line lives inside `certdoctor.app`, and the window inside `certdoctor-gui.app` together with the `certdoctor` it runs. Next to each bundle is a link for each program in it, so you still type `./certdoctor`. macOS runs them without asking the network, because the notarisation ticket travels inside the bundle.

> Keep the bundle and its links together. A copy of a program taken out of the bundle on its own is refused, because the signature covers the bundle.

**The Linux programs are not signed.** They come out of the archive ready to run.

## What you can check without trusting this page

What is inside any of these files, signed when the release was made:

```
gh attestation verify <the file you downloaded> -R donislawdev/certdoctor \
   --predicate-type https://spdx.dev/Document/v2.3
```

The predicate type has to be given. `gh` asks for build provenance unless told otherwise, and that is a different statement - see below.

Where a **Linux** archive came from. These are exactly the bytes the build produced, so the build's own statement still describes them:

```
gh attestation verify <the file you downloaded> -R donislawdev/certdoctor
```

That one does not answer for a **Windows or macOS** archive or the installer, and on purpose: those were signed after the build, so their bytes are no longer the bytes the build made. What answers for them is the signature itself - Authenticode on Windows, and on macOS:

```
spctl -a -vv certdoctor.app            # what Gatekeeper thinks of it
xcrun stapler validate certdoctor.app  # that the ticket is really in the file
```

The same two commands answer for `certdoctor-gui.app` from the window's archive.

The four files whose names start with `verify-` are the ones you check a download against. The `.spdx.json` file lists every module compiled into either program, the Go toolchain included, with its licence and version, and the software renderer for the window on Windows. The `.sigstore.json` files are the statements themselves, so both commands also work offline with `--bundle <file>`.

## Everything that changed

See [CHANGELOG.md](https://github.com/donislawdev/certdoctor/blob/main/CHANGELOG.md).
