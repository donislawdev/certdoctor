---
title: Certificate and connection errors
linkTitle: All errors
seoTitle: SSL and certificate errors explained, with fixes
description: "PKIX path building failed, unable to get local issuer certificate, SELF_SIGNED_CERT_IN_CHAIN, x509 unknown authority: what each means and the fix."
lead: "The same missing certificate reads differently in every runtime. Start from the message you saw."
cards:
  - /errors/pkix-path-building-failed
  - /errors/unable-to-get-local-issuer-certificate
  - /errors/self-signed-certificate-in-certificate-chain
  - /errors/x509-certificate-signed-by-unknown-authority
  - /errors/certificate-has-expired
  - /errors/hostname-does-not-match-certificate
  - /errors/missing-intermediate-certificate
  - /errors/python-3-13-strict-certificate-checks
  - /errors/407-proxy-authentication-required
---

Most of these messages are the same complaint in the words of different runtimes: the program could not build a chain from the server's certificate to an authority it trusts. They have a handful of causes, and the fix depends on which one is yours:

- **the authority is missing from this program's trust store** - most often a company root or a TLS inspection product, added to the system and never to Java, Git or Python,
- **the server does not send its intermediate certificate** - a fault of the server, which a browser hides by remembering the intermediate from another site,
- **the certificate is wrong for this connection** - expired, or issued for another name,
- **something in between answers instead of the server** - a proxy that wants credentials, or one that re-signs every connection.

Each page below says what the message means, which causes it has, and what to run. Running `certdoctor` against the URL tells you which cause is yours, on the machine where it fails.
