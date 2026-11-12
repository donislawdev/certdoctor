---
title: Fix guides
linkTitle: All fix guides
seoTitle: Add a CA certificate to Java, git, Node, Python and Windows
description: "Where Java, Git, curl, Node.js, Python, pip, Windows and Linux keep their trusted certificates, and the command that adds a company root to each one."
lead: "Every runtime keeps its own list of trusted authorities. Each guide says where one of them keeps it and how to add a certificate to it."
cards:
  - /guides/java-cacerts-keytool
  - /guides/git-ssl-certificate
  - /guides/curl-ca-bundle
  - /guides/node-extra-ca-certs
  - /guides/python-pip-certificates
  - /guides/windows-certificate-store
  - /guides/linux-ca-bundle
  - /guides/tls-inspection-corporate-proxy
  - /guides/test-a-pac-file
---

A company root added to the Windows store reaches the browser and the programs that read that store. It does not reach a JDK's `cacerts`, Git for Windows' bundle, Node.js' built-in list or the file Python reads. Each of those needs the certificate added where it looks.

`certdoctor` tells you which of them refuse, on the machine where it fails, and prints the command for each one with that machine's paths in it. These guides explain what those commands do, so you can run them knowing what changes.
