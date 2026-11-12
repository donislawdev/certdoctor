---
title: certificate has expired
codeTitle: true
seoTitle: "SSL certificate has expired: find which one and why"
description: "certificate has expired, CERT_HAS_EXPIRED and x509 certificate has expired or is not yet valid: which certificate in the chain expired, and whose fix it is."
lead: "A certificate in the chain is past its validity, or the clock of this machine says it is. The report shows which certificate, its dates, and the time of the run."
messages:
  - from: curl, git
    text: "SSL certificate problem: certificate has expired"
  - from: Node.js
    text: "Error: certificate has expired (CERT_HAS_EXPIRED)"
  - from: Python
    text: "certificate verify failed: certificate has expired"
  - from: Go
    text: "x509: certificate has expired or is not yet valid"
  - from: Java
    text: "PKIX path validation failed: java.security.cert.CertPathValidatorException: validity check failed"
---

## What it means

Every certificate is valid between two dates. A client refuses a chain in which any certificate, the server's own or one above it, is outside those dates at the moment of the connection.

## Common causes

- **The server's certificate expired** and nobody renewed it. Every client fails, and the fix is on the server.
- **An intermediate or a root in the chain expired**, while a newer one exists. A server still sending an old intermediate fails in some clients and not others.
- **This machine's clock is wrong.** A virtual machine restored from a snapshot, or a machine without time synchronisation, can be days or years off.

## Find which one is yours

```
certdoctor https://the-url-that-fails/
```

For a chain with an expired certificate, the verdict says so directly:

```
x 16 of 17 store(s) do not trust the presented chain, and 1 could not be assessed - a certificate in
  the path is past its validity.
```

`L4` lists every certificate the server presented with its `valid ... to ...` dates and its fingerprint, so you can see which one expired. The first line of the report holds the time of the run, as this machine's clock gave it: when the dates look right and the time does not, the clock is the problem.

## Fix it

An expired server certificate or intermediate is fixed on the server: renew it, and send the current chain. Attach the report, made with `--redact --format md`, to the ticket for whoever runs the server.

A wrong clock is fixed on this machine, by synchronising its time.

## What not to do

Do not add the expired certificate to a trust store, and do not turn verification off. Neither makes an expired certificate valid.
