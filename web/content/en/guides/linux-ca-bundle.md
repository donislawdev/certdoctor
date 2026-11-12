---
title: The Linux CA bundle
seoTitle: Add a CA certificate on Linux - the system CA bundle
description: "Add a root certificate to the Linux CA bundle on Debian, Ubuntu, Alpine and RHEL: which file programs read, update-ca-certificates, and what survives a rebuild."
lead: "Most programs on Linux read one file the distribution maintains. Adding to it is quick, and a rebuild of that file drops what was added by hand."
---

## Which file programs read

A Linux distribution keeps its trusted roots in one bundle file - `/etc/ssl/certs/ca-certificates.crt` on Debian, Ubuntu and Alpine, `/etc/pki/tls/certs/ca-bundle.crt` on Red Hat and its family. Go programs, curl and git from the distribution's packages, and Python's `ssl` module usually read it.

## See what the bundle says

```
certdoctor https://the-url-that-fails/
```

The `system-store` row names the bundle it read - the first that exists, in the order Go looks for them - and whether it trusts the chain. A `curl` or `git` from the distribution's own packages that reads the same file points at this row rather than repeating it. Inside a container, [run it in the container](/docs/containers/): the image has a bundle of its own.

## Add the root, quickly

The row's command appends the root to the bundle:

```
cat "<certificate.pem>" >> /etc/ssl/certs/ca-certificates.crt
```

It adds and removes nothing, and it works at once. It needs root rights, and the row says so.

## Add the root, to last

The distribution's own tool rebuilds the bundle from a directory of certificates, and the rebuild drops anything appended by hand - the row's note says that too. To make the root survive the next update, put a copy where the tool collects from, then rebuild:

- Debian, Ubuntu, Alpine: a file named `*.crt` in `/usr/local/share/ca-certificates`, then `update-ca-certificates` ([manual page](https://manpages.debian.org/stable/ca-certificates/update-ca-certificates.8.en.html))
- Red Hat, Fedora, Rocky, Alma: a file in `/etc/pki/ca-trust/source/anchors`, then `update-ca-trust`

The Debian tool ignores a file whose name does not end in `.crt`.

## Programs with a list of their own

Java and Node.js do not read this file, and a Python or pip pointed at another file does not either. Their rows in the trust matrix carry their own commands.
