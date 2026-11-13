---
title: Check what you downloaded
linkTitle: Verify a download
seoTitle: Verify a Cert Doctor download - checksums and attestation
description: "Check a Cert Doctor archive against the release's SHA-256 list, and prove where it came from with the signed bill of materials GitHub attests."
lead: "Two questions: is this the file the release published, and was the release made from this repository?"
---

## Is it the file the release published

Each release lists the SHA-256 of every file it publishes in `verify-SHA256SUMS.txt`. Download it next to the archive, then on Linux or macOS:

{{< readme-check 1 >}}

On Windows, in PowerShell, `True` beside the archive means it is the file the release published:

{{< readme-check 2 >}}

## Was it made from this repository

A digest file from the same page only proves that the two agree. What proves where they came from is a statement GitHub signed when the release was made, and the [GitHub CLI](https://cli.github.com/) checks it:

{{< readme-check 3 >}}

That statement is the bill of materials - every module compiled into the program, the Go toolchain included, with its licence and version - and it covers every file of the release. The predicate type has to be given, because without it `gh` asks for build provenance, which is a different statement.

A Linux archive is exactly the bytes the build produced, so the build's own provenance answers for it too:

{{< readme-check 4 >}}

## The signature

The Windows and macOS programs are signed after the build, so their bytes are no longer the build's, and the second command finds nothing for them by design. The signature answers for them instead: Windows checks it when the program starts, and on macOS `spctl -a -vv certdoctor.app` - or `certdoctor-gui.app` - asks Gatekeeper.
