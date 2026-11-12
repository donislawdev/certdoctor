---
title: Missing intermediate certificate
seoTitle: "Incomplete certificate chain: server misses intermediate"
description: "Works in the browser, fails in curl, Java and Python? The server does not send its intermediate certificate. How to prove it is the server's fault, and fix it."
lead: "The browser connects and everything else fails, because the server sends its own certificate without the one that issued it."
messages:
  - from: curl, git, Python
    text: "unable to get local issuer certificate"
  - from: Java
    text: "PKIX path building failed: unable to find valid certification path to requested target"
  - from: Node.js
    text: "unable to verify the first certificate (UNABLE_TO_VERIFY_LEAF_SIGNATURE)"
---

## What it means

A server is supposed to send its own certificate and every intermediate certificate between it and a root. The client already has the root. When the server leaves out the intermediate, the client has no way to connect the server's certificate to the root it trusts.

Browsers often hide this, because they remember intermediates they met on other sites and some fetch missing ones. curl, Java, Python and Node.js do not, so they fail on the same URL. That is why the problem looks like it is on your machine when it is not.

## Find out whether it is yours

```
certdoctor https://incomplete-chain.badssl.com/
```

`L4` counts the certificates the server presented and checks whether each one's issuer is among them. When the server left one out and no store on the machine could build a path without it, certdoctor names the server:

```
x The server presented 1 certificate(s) and did not send the issuer of the first one, so only a
  client that already holds it can build a path, and none of the 10 store(s) assessed here built one
  - this is a fact about the server rather than about this machine.
```

A report made with `--redact --format md` is the evidence to attach to a ticket for whoever runs the server.

## Fix it

On the server: configure it to send the full chain - its certificate followed by the intermediates, in order. Most servers take one file with the chain in it rather than the certificate alone.

On the client, as a stopgap while the server is fixed: adding the intermediate to the client's trust store lets that one client build the path. The trust matrix shows which stores need it.

## What not to do

Do not turn verification off to get past it. The server's certificate may be perfectly valid, and the fix is one file on the server.
