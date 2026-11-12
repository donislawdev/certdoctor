---
title: "x509: certificate signed by unknown authority"
codeTitle: true
seoTitle: "x509: certificate signed by unknown authority: fix"
description: "x509: certificate signed by unknown authority in Go programs, Docker, kubectl, Terraform and Helm: why the system's trust store decides, and how to fix it."
lead: "Programs written in Go trust what the operating system trusts. When they print this, the system's own store - or the bundle inside a container - lacks the authority."
messages:
  - from: Go programs
    text: "tls: failed to verify certificate: x509: certificate signed by unknown authority"
  - from: Docker, kubectl, Terraform, Helm
    text: "x509: certificate signed by unknown authority"
---

## What it means

Go's TLS library verifies the server's chain against the platform's trust store: the Windows certificate store on Windows, and the CA bundle of the distribution on Linux. This message says the chain does not lead to any authority in that store. Docker, kubectl, Terraform, Helm and many other tools are written in Go, so they all print it.

## Common causes

- **A container without the company root.** The host trusts your company's authority, and the image's own CA bundle, often minimal, does not.
- **TLS inspection on the network.** A proxy re-signs connections with a root that was never added to this machine's or this image's store.
- **An internal server with a private authority**, whose root this machine never received.
- **The server does not send its intermediate certificate.** [Missing intermediate certificate](/errors/missing-intermediate-certificate/) covers it.

## Find which one is yours

Run certdoctor where the program fails - on the host, or inside the container:

```
certdoctor https://registry.example.com/
```

The `system-store` row is the platform store a Go program reads. It shows whether that store trusts the chain, who signed the certificate, and the command that adds the root: `certutil` on Windows, an append to the distribution's bundle on Linux. Inside a container, [copy the static binary in](/docs/containers/) and the report describes the container's bundle, not the host's.

## Fix it

- Windows - [the Windows certificate store](/guides/windows-certificate-store/)
- Linux and containers - [the Linux CA bundle](/guides/linux-ca-bundle/)
- A company root - [TLS inspection](/guides/tls-inspection-corporate-proxy/)

`docker pull` is a special case: the pull is made by the Docker daemon, not inside a container, so the root belongs in the store the daemon reads on its host.

## What not to do

Flags such as `--insecure-skip-tls-verify` and `insecure-registries` stop checking certificates for that destination altogether. Add the root instead.
