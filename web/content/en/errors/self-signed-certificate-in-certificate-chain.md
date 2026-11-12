---
title: self-signed certificate in certificate chain
codeTitle: true
seoTitle: "SELF_SIGNED_CERT_IN_CHAIN: npm, Node and git fix"
description: "npm ERR! SELF_SIGNED_CERT_IN_CHAIN and self-signed certificate in certificate chain in Node.js, git and Python: why it happens behind a proxy, and the fix."
lead: "The chain ends in a root this program does not trust. Behind a company network that root is almost always the company's own, or its inspection proxy's."
messages:
  - from: npm
    text: "npm ERR! code SELF_SIGNED_CERT_IN_CHAIN"
  - from: Node.js
    text: "Error: self-signed certificate in certificate chain"
  - from: git, curl
    text: "SSL certificate problem: self-signed certificate in certificate chain"
  - from: Python, pip
    text: "certificate verify failed: self-signed certificate in certificate chain"
---

## What it means

Every chain ends in a root certificate, which signs itself. That is normal. This message says the chain the program received included a root, and that root is not on the program's list of trusted authorities. Older versions write "self signed" without the hyphen.

It does not mean the server is misconfigured with a home-made certificate, although it can. On a company network it usually means something between you and the server re-signs the connection with a root of its own.

## Common causes

- **TLS inspection.** A company proxy decrypts and re-signs HTTPS traffic with its own root. IT installed that root in the system store, and Node.js, npm, Git for Windows and Python read their own lists instead.
- **A private authority.** An internal server with a certificate from the company's own authority, trusted by machines that were given its root.
- **A server that really uses a self-signed root**, such as a test environment.

## Find which one is yours

```
certdoctor https://the-url-that-fails/
```

The trust matrix says who signed the certificate and how many stores on this machine hold that authority. A root the Windows store holds while node and git do not is a root that reached part of the machine. When the signer is an inspection product certdoctor recognises, the report names it.

Each node row is judged by the list that `node` binary trusts, and its command depends on what would close the chain: turning on the system's own list where that has the root, or adding the root to the file `NODE_EXTRA_CA_CERTS` names.

## Fix it

- Node.js and npm - [NODE_EXTRA_CA_CERTS and NODE_USE_SYSTEM_CA](/guides/node-extra-ca-certs/)
- git - [Git and SSL certificates](/guides/git-ssl-certificate/)
- Python and pip - [Python and pip certificates](/guides/python-pip-certificates/)
- Getting the company root - [TLS inspection](/guides/tls-inspection-corporate-proxy/)

## What not to do

`npm config set strict-ssl false` and `NODE_TLS_REJECT_UNAUTHORIZED=0` switch off verification for everything that process connects to. certdoctor reads `NODE_TLS_REJECT_UNAUTHORIZED` in `L0`, so a report shows when somebody already did.
