---
title: The Windows certificate store
seoTitle: Add a root certificate to the Windows store with certutil
description: "Add a root certificate to the Windows certificate store with certutil: CurrentUser or LocalMachine, which programs read each, and which programs ignore both."
lead: "Your account's store and the machine's store are two different lists. Services read one, your programs read both, and Java and Git read neither."
---

## Two stores

Windows keeps trusted roots in two places that matter here:

- **`CurrentUser`** - your account's own store. Programs you run read it, together with the machine's. Services running as other accounts do not.
- **`LocalMachine`** - the machine's store. Every account and every service reads it, and changing it needs administrator rights.

A company root that IT deploys usually lands in `LocalMachine`. A root you add yourself without administrator rights lands in `CurrentUser`.

## Who reads them

Edge, Chrome, .NET programs, PowerShell, Go programs, the `curl.exe` that ships with Windows and Python's `ssl` module trust what these stores trust. Java, Git for Windows' own bundle and Node.js do not: they carry lists of their own, and need [their own commands](/guides/).

## See what each store says

```
certdoctor https://the-url-that-fails/
```

The trust matrix has a `system-store` row for each of the two stores, asked with every network retrieval switched off, so Windows does not fetch anything from addresses written into the server's certificate. A public root that Windows simply has not downloaded yet is told apart from an authority nobody installed, using this machine's own copy of Microsoft's root program list.

## Add the root

The rows carry the command for their store ([certutil documentation](https://learn.microsoft.com/windows-server/administration/windows-commands/certutil)):

```
certutil -user -addstore Root "<certificate.pem>"
certutil -addstore Root "<certificate.pem>"
```

- The first adds to your account's store. Windows asks you to confirm in a dialog before it adds a root there.
- The second adds to the machine's store, needs a terminal run as administrator, and reaches services too.

`-addstore` adds one certificate and leaves the rest of the store alone. Replace `<certificate.pem>` with the full path of the root certificate.

## When it is the wrong store

A root in either store does nothing for Java, Git for Windows or Node.js. The trust matrix's note under the `LocalMachine` row says so, and their own rows carry their own commands.
