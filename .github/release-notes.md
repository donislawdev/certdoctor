Why this machine, or this container, cannot reach that URL - DNS, proxy and PAC, TCP, TLS, and the trust store of every runtime on the machine, with the commands that fix each one.

## What to download

One program, five builds. Take the archive for your system and architecture:

- `certdoctor_<version>_windows_amd64.zip` and `certdoctor_<version>_windows_arm64.zip`
- `certdoctor_<version>_linux_amd64.tar.gz` and `certdoctor_<version>_linux_arm64.tar.gz`
- `certdoctor_<version>_macos_arm64.tar.gz`, for Apple silicon

Every archive carries the program, `LICENSE`, `README.md` and `THIRD-PARTY-NOTICES.md`. The Linux builds are static and run in a container with no C library at all, so the binary can be copied into an image on its own - `certdoctor --license` prints the notices that travel with it.

Check what you downloaded against `verify-SHA256SUMS.txt`, at the bottom of this list.

## Signing

**The Windows programs are signed.** The signature is on `certdoctor.exe` inside the zip, carries a timestamp, and is issued by Certum. Windows checks it when you run the program.

**The macOS program is signed and notarised by Apple.** It lives inside `certdoctor.app`, with a link called `certdoctor` next to it, so you still type `./certdoctor`. macOS runs it without asking the network, because the notarisation ticket travels inside the bundle.

> Keep `certdoctor.app` and the link together. A copy of the program taken out of the bundle on its own is refused, because the signature covers the bundle.

**The Linux programs are not signed.** You may need `chmod +x`.

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

That one does not answer for a **Windows or macOS** archive, and on purpose: those were signed after the build, so their bytes are no longer the bytes the build made. What answers for them is the signature itself - Authenticode on Windows, and on macOS:

```
spctl -a -vv certdoctor.app            # what Gatekeeper thinks of it
xcrun stapler validate certdoctor.app  # that the ticket is really in the file
```

The four files whose names start with `verify-` are the ones you check a download against. The `.spdx.json` file lists every module compiled into the program, the Go toolchain included, with its licence and version. The `.sigstore.json` files are the statements themselves, so both commands also work offline with `--bundle <file>`.

## Everything that changed

See [CHANGELOG.md](https://github.com/donislawdev/certdoctor/blob/main/CHANGELOG.md).
