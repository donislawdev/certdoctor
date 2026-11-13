---
title: Download Cert Doctor
linkTitle: Download
seoTitle: Download Cert Doctor for Windows, Linux and macOS
description: "Download Cert Doctor for Windows, Linux and macOS: the command line as one file with nothing to install, and the window for Windows, Linux and macOS."
lead: "Take the archive for your system from the [releases page](https://github.com/donislawdev/certdoctor/releases/latest) and unpack it. There is nothing to install."
---

## The command line

{{< downloads "certdoctor" >}}

On Linux the command line needs no C library, so the same file runs in Alpine, in Ubuntu and in an image with nothing else in it. `certdoctor --license` prints the licence and the notices of the code by others that travels with it.

## The window

`certdoctor-gui` has archives of its own, for three systems. Each carries the command line as well, because the window runs it:

{{< downloads "certdoctor-gui" >}}

Keep the files of the window's archive together. [The window](/docs/window/) says why.

Every archive also carries `LICENSE`, `THIRD-PARTY-NOTICES.md` and the README, and the window's archives `THIRD-PARTY-NOTICES-GUI.md` too.

## Check what you downloaded

Each release lists the SHA-256 of every file in `verify-SHA256SUMS.txt`, and GitHub signs a statement of what went into each one. [Check what you downloaded](/docs/verify-a-download/) shows the commands.

## From source

With Go {{< go-version >}} or newer:

```
git clone https://github.com/donislawdev/certdoctor
cd certdoctor
CGO_ENABLED=0 go build ./cmd/certdoctor
```

In PowerShell, set the variable on its own line first: `$env:CGO_ENABLED = "0"`, then `go build ./cmd/certdoctor`. `CGO_ENABLED=0` gives the same static binary the releases carry, the one that runs in an Alpine image as it is.

## Next

[Getting started](/docs/getting-started/) takes you from the download to the first report.
