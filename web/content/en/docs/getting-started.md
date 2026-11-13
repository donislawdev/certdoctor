---
title: Getting started
seoTitle: Getting started - your first Cert Doctor report
description: "Download Cert Doctor, run it against the URL that fails, and read the sentence that names the cause. Then try it on a deliberately broken site."
lead: "From the download to the sentence that names the cause in about two minutes."
---

## What you need

A computer with Windows, Linux or macOS on Apple silicon, and the URL that fails. Nothing has to be installed: the command line's [download](/download/) is an archive with one program in it, and on Linux that program is one static file that also runs inside a container. No administrator rights are needed. On Windows you can install it instead, and then the command works in any new terminal.

## Run it against the URL

Open a terminal where the archive was unpacked, or any new terminal once it is installed, and give Cert Doctor the address exactly as the failing program uses it, with `https://` or `http://` in front:

```
certdoctor https://api.example.com/
```

The scheme is required. Without it there is no way to tell a host name from a port number. A run takes a few seconds, and longer when a resolver or a proxy does not answer - no run takes more than 60 seconds unless you give it more with `--timeout`.

## Read the first sentence

The report opens with one sentence naming the cause, in the words of the layer that decided it. Below it is the exit code, then every layer with its evidence, then the notes saying what was not looked at. When a trust store refuses the server's chain, its row carries a `run:` line with the command that would add the certificate there. [Reading a report](/docs/read-the-report/) goes through every part.

Cert Doctor prints the commands. It never runs them. Read a command before you run it, and replace what it asks you to replace first, such as `<certificate.pem>`.

## Try it on a broken site

[badssl.com](https://badssl.com/) keeps deliberately broken HTTPS sites. Three of them show three different causes:

```
certdoctor https://untrusted-root.badssl.com/
certdoctor https://incomplete-chain.badssl.com/
certdoctor https://expired.badssl.com/
```

The first names an authority no store on your machine holds, the second names the server for not sending its intermediate certificate, and the third names a certificate past its validity.

> Do not run the fix commands for badssl.com. Its root is untrusted on purpose, and trusting it would make your stores accept a certificate nobody vouches for. The commands are there for the day the refused root is your own company's.

## Keep the report

A report can go to a file, in Markdown for a ticket, as one HTML page, or as JSON:

```
certdoctor https://api.example.com/ --redact --format md --out report.md
```

`--redact` masks host names, paths and user names. [Reports](/docs/reports/) says what each format holds.

## Or use the window

`certdoctor-gui` shows the same report without a terminal: type the address, press Diagnose, read the report and save it. [The window](/docs/window/) says more.
