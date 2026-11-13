---
title: Security and privacy
seoTitle: Security and privacy - what Cert Doctor never does
description: "Cert Doctor changes nothing on the machine, runs no fix, connects only where you point it, masks credentials always and needs no administrator rights."
lead: "A tool you run where connections fail sees internal names, paths and proxies. These are the promises it keeps."
---

## It changes nothing

Cert Doctor never writes to a trust store, never edits a configuration file and never runs the commands it prints. The only file it writes is the report, at the path you give with `--out`. A diagnostic tool that quietly modified trust stores would be a tool nobody should grant administrator rights to.

The window keeps one setting of its own, the folder you last saved a report to. [The window](/docs/window/) says where.

## It runs no fix

Every command in a report is there for you to read, adjust and run yourself. A row says when its command needs administrator or root rights, and why, before you run it.

## It connects only where you point it

A run connects to the URL you gave, the addresses it resolves to, your configured resolvers, your proxies and the PAC script your machine names. Nothing else: no telemetry, no update check, no reporting of any kind. On Windows, the trust store is asked with every network retrieval switched off, so even Windows does not go and fetch anything on Cert Doctor's behalf.

## Credentials never reach a report

Proxy user names and passwords in proxy addresses, authorization headers and cookies are masked always, with or without `--redact`. `--redact` additionally masks host names, file system paths and user names, for a report that leaves the company.

## It needs no administrator rights

It runs as whoever started it, and the report records which rights it ran with, because what a store looks like can depend on them.

## What it runs

To learn what some runtimes trust, Cert Doctor starts their own programs and reads the answer: `node` and `python` with a fixed script of its own, and `curl --version` to see how that curl was built. Those programs start without the environment variables that would make them load other code or write files.

## Reporting a vulnerability

Report a security problem privately, as [SECURITY.md](https://github.com/donislawdev/certdoctor/blob/main/SECURITY.md) in the repository says, not in a public issue. For anything else, the [issue tracker](https://github.com/donislawdev/certdoctor/issues) is open.
