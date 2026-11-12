---
title: The trust matrix
seoTitle: Trust matrix - which trust stores on this machine refuse
description: "certdoctor asks every trust store on the machine - Windows store, Linux bundle, each JDK, git, curl, node, Python and pip - and prints the fix for each."
lead: "The browser works, curl works, the application does not. That is several trust stores disagreeing, and the trust matrix shows which."
---

## Why there is more than one answer

Every runtime keeps its own idea of whom to trust. Java keeps a `cacerts` file in every installation, and a developer machine often has several JDKs, of which somebody fixed one. Git for Windows carries its own bundle. Node.js is built with its own list. Python and pip each read the list they were set up with. A certificate your company added to the Windows store reaches some of these and not others, which is why one program connects and the next one does not.

The trust matrix asks each of them the same question about the same chain: does this store trust what the server presented?

## The stores it asks

One row per store, not per runtime:

| Row | Which store |
|---|---|
| `system-store` on Windows | the Windows certificate store, twice: as your account sees it (`CurrentUser`) and as services see it (`LocalMachine`) |
| `system-store` on Linux | the CA bundle of the distribution |
| `java` | the `cacerts` of every JDK and JRE it finds, each as its own row |
| `git` | every `git` it finds, and the bundle each one reads |
| `curl` | every `curl` it finds, and which store each one reads |
| `node` | every `node` on PATH, by the list that binary trusts |
| `python` | every Python on PATH, by the list its `ssl` module trusts |
| `pip` | the `pip` of each Python, by its own rule |

The report lists the families it asked, so a missing row always means nobody looked, never that a store agreed. On the machine certdoctor was built on, one run in November 2026 read seventeen stores, eight of them Java runtimes.

## The command each store gets

A store that refuses because it does not know the authority gets the command that adds the certificate to it. The commands only ever add: none of them removes or replaces what a store already holds.

| Store | The command, in the form a row prints it |
|---|---|
| Windows, `LocalMachine` | `certutil -addstore Root "<certificate.pem>"`, which needs administrator rights |
| Windows, `CurrentUser` | `certutil -user -addstore Root "<certificate.pem>"`, after which Windows asks you to confirm |
| a JDK or JRE | that installation's own `keytool -importcert` into its own `cacerts`, with the real paths |
| git, curl, a Linux bundle, a CA file Python or pip reads | an append of the certificate to that exact file: `cat` on Linux and macOS, `cmd /c copy /b` on Windows |
| node | `NODE_USE_SYSTEM_CA=1` when the system's own list would close the chain, otherwise an append to the file `NODE_EXTRA_CA_CERTS` names, or setting that variable |
| Python on Windows | this account's Windows store, because that is where its list comes from |

A row says when its command needs administrator or root rights, and why. It also says what to watch: a package manager or a runtime update can rewrite a bundle and drop an appended certificate, and a newer JDK brings its own `cacerts`.

certdoctor prints these commands. It never runs them. Each one has placeholders you replace first, named on the row's `replace first:` line.

## When a row points at another

A program that judges by another store says so instead of repeating it. curl built on Schannel, the Windows TLS library, trusts what this account's Windows store trusts, so its row points at that store's row and command. On Linux, a `curl` or `git` from the distribution's own packages that reads the distribution's bundle points at that bundle's row.

## How the Windows store is asked

The Windows store is asked with every network retrieval switched off. Windows would otherwise fetch a missing certificate from an address written into the certificate by the server you are diagnosing, and certdoctor connects only where you point it. A public root that Windows simply has not downloaded yet is told apart from an authority nobody installed by reading this machine's own copy of Microsoft's root program list.

## Who signed the certificate

Above the rows, the matrix says who signed the server's certificate and how many stores on this machine hold that authority. When the signer is an authority some stores hold and others do not, that is usually a company root or a TLS inspection product that reached only part of the machine. [TLS inspection](/guides/tls-inspection-corporate-proxy/) says how to read that.
