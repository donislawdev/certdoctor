---
title: Tools
linkTitle: All tools
seoTitle: "Offline JWT, certificate and CSR decoder, NO_PROXY tester"
description: "Decode a JWT, a certificate chain or a CSR and test a NO_PROXY list on your own machine. Nothing is uploaded and nothing connects. Command line and window."
lead: "Small tools for what stands around a connection. Each reads only what you give it, connects to nothing and changes nothing."
cards:
  - /tools/jwt-decoder
  - /tools/certificate-decoder
  - /tools/csr-decoder
  - /tools/no-proxy
  - /tools/ksef-certificate-fingerprint
---

A token, a certificate or a signing request is often something you would rather not paste into a website. These tools come with Cert Doctor, in the same [download](/download/), and read what you give them on your own machine: from the terminal, a file or a pipe.

In a terminal, `certdoctor tool` lists them and `certdoctor tool <name> --help` says what each one takes. In the window, they are under **Tools** on its bar.

Every tool ends with exit code `0` when it could read its input, whatever it found there, and writes a JSON document with `--json`, so a script can run one and read its checks.
