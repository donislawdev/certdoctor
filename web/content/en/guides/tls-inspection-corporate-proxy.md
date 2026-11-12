---
title: TLS inspection and company certificates
linkTitle: TLS inspection
seoTitle: Corporate proxy SSL errors - TLS inspection explained
description: "Behind a corporate proxy with TLS inspection, Java, git, npm and pip fail while the browser works. See who signed the certificate and where it is missing."
lead: "A company network can decrypt and re-sign HTTPS. The browser trusts the company's root, and every program with a list of its own does not."
---

## What TLS inspection does

A TLS inspection proxy - many company security products do this - sits between your machine and the internet. It answers your connection with a certificate it made for that site on the spot, signed by its own root, and opens its own connection to the real server. Your machine trusts it because IT installed that root, usually in the system store.

Programs that read the system store connect. Java, Git for Windows, Node.js and pip on certifi read lists of their own and fail with [PKIX path building failed](/errors/pkix-path-building-failed/), [unable to get local issuer certificate](/errors/unable-to-get-local-issuer-certificate/) or [SELF_SIGNED_CERT_IN_CHAIN](/errors/self-signed-certificate-in-certificate-chain/).

## See who signed the certificate

```
certdoctor https://api.example.com/
```

The trust matrix says who signed the certificate the server presented, with its fingerprint, and how many stores on this machine hold that authority. An authority the Windows store holds and the JDKs and Node.js do not is a root that reached only part of the machine - the usual picture of a company root or an inspection product.

When the certificate names an inspection product in the way its vendor publishes, the report names the product. Otherwise it says who signed and how many stores know them, and nothing more, because from one connection an inspecting proxy and your company's own authority look the same. Telling someone they are being intercepted when they are not is harm, not a detail.

## Get the root certificate

The certificate to add is the root at the top of the chain, not the site's own:

- **Ask IT** for the company's root certificate, in PEM (Base-64) form. This is the certificate you can be sure of.
- **Export it from the Windows store** where IT already installed it: open `certmgr.msc`, find the root under Trusted Root Certification Authorities, and export it as Base-64 encoded X.509.
- **Compare fingerprints.** The fingerprint in certdoctor's report is what to compare the file you got with, before you trust it.

Then use the commands the trust matrix printed for each store that refuses.

## Where it needs to go

| Program | Guide |
|---|---|
| Java, Maven, Gradle | [Java cacerts and keytool](/guides/java-cacerts-keytool/) |
| git | [Git and SSL certificates](/guides/git-ssl-certificate/) |
| Node.js, npm | [NODE_EXTRA_CA_CERTS](/guides/node-extra-ca-certs/) |
| Python, pip | [Python and pip certificates](/guides/python-pip-certificates/) |
| Docker images, Linux | [The Linux CA bundle](/guides/linux-ca-bundle/) |
