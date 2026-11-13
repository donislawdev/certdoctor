---
title: Cert Doctor
seoTitle: "Cert Doctor - why this machine cannot connect to that URL"
description: "Fix PKIX path building failed, unable to get local issuer certificate and SELF_SIGNED_CERT_IN_CHAIN: one command checks every trust store and prints the fix."
hero:
  eyebrow: Command line and window
  title: The browser connects.
  turn: Your program does not.
  lead: "**Cert Doctor** walks the whole path to the URL that fails - DNS, proxy and PAC script, TCP, TLS - then asks every trust store on this machine whether it trusts what the server sent, and prints the command that fixes each one that does not."
  facts:
    - Free and open source, GPL-3.0
    - Changes nothing, no telemetry
    - Windows, macOS and Linux
  panel_title: One missing certificate, said four ways
  panel_rows:
    - text: PKIX path building failed
      from: Java
      page: /errors/pkix-path-building-failed
    - text: unable to get local issuer certificate
      from: curl, git, Python
      page: /errors/unable-to-get-local-issuer-certificate
    - text: SELF_SIGNED_CERT_IN_CHAIN
      from: Node.js
      page: /errors/self-signed-certificate-in-certificate-chain
    - text: "x509: certificate signed by unknown authority"
      from: Go
      page: /errors/x509-certificate-signed-by-unknown-authority
  panel_foot: asks every one of them the same question, and names the ones that refuse
run:
  eyebrow: A real run
  title: The cause first, then a command for every store
  text: "A site whose root no store trusts, checked on a Windows machine with Git and eight Java runtimes. The first sentence names the cause. Below it every store has its own row, and every row that refuses carries the command that would add the root there, with this machine's paths in it. Cert Doctor prints the commands. It never runs them."
  caption: Windows, an excerpt
  command: certdoctor https://untrusted-root.badssl.com/
  # An excerpt of a real run on 2026-11-12, cut line for line from what it printed.
  output: runs/untrusted-root-windows.txt
  link:
    text: How to read a report
    page: /docs/read-the-report
steps:
  eyebrow: How it works
  title: One command, the whole path
  items:
    - title: Point it at the URL that fails
      text: "`certdoctor https://api.example.com/` - on the laptop, the build agent or inside the container where it fails."
    - title: It walks the path
      text: "Every resolver asked directly, the proxy your programs really use, a TCP connection to every address and the full certificate chain from each one."
    - title: Every trust store answers
      text: "The Windows store, the Linux CA bundle, every JDK and JRE, every git, curl, node, Python and pip it finds, each with the command that would fix it."
layers:
  eyebrow: Six layers
  title: What it checks
  text: "Each layer answers one question. The sentence at the top of the report comes from the layer that decided it, which is not always the first red one."
  link:
    text: Every layer in detail
    page: /docs/layers
errors:
  eyebrow: Error messages
  title: Find the message you saw
  text: "Each runtime words the same problem in its own way. Every page says what the message means, which causes it has, and how Cert Doctor tells you which one is yours."
  pages:
    - /errors/pkix-path-building-failed
    - /errors/unable-to-get-local-issuer-certificate
    - /errors/self-signed-certificate-in-certificate-chain
    - /errors/x509-certificate-signed-by-unknown-authority
    - /errors/missing-intermediate-certificate
    - /errors/407-proxy-authentication-required
  link:
    text: All error messages
    page: /errors
guides:
  eyebrow: Fix guides
  title: Fix it in the store that needs it
  text: "A browser, a JDK, Git for Windows and Python can each trust a different list. These guides say where each one keeps its list and which command adds a certificate to it."
  pages:
    - /guides/java-cacerts-keytool
    - /guides/git-ssl-certificate
    - /guides/node-extra-ca-certs
    - /guides/python-pip-certificates
    - /guides/windows-certificate-store
    - /guides/tls-inspection-corporate-proxy
  link:
    text: All fix guides
    page: /guides
pipeline:
  eyebrow: Tickets and pipelines
  title: A report for the ticket, an exit code for CI
  text: "Markdown, one self-contained HTML page, or JSON checked against its schema before it is printed. `--redact` masks host names, paths and user names, and credentials are masked always. Every ending has its own exit code, and a warning alone does not fail a build."
  caption: four ways to keep a report
  output: |-
    # a report to attach to a ticket
    certdoctor https://api.example.com/ --redact --format md --out report.md

    # one HTML page with no script in it
    certdoctor https://api.example.com/ --format html --out report.html

    # JSON for a pipeline, checked against its schema
    certdoctor https://api.example.com/ --json --out report.json

    # the same report as a page later, without running again
    certdoctor --from report.json --format html --out report.html
  link:
    text: Using it in CI
    page: /docs/ci
promises:
  eyebrow: What it never does
  title: Safe to run on a locked-down machine
  text: "A tool you run where connections fail is a tool that sees internal names, paths and proxies. These are the promises it keeps."
  items:
    - title: Changes nothing
      text: "It never writes to a trust store or a configuration file. The only file it writes is the report, at the path you name."
    - title: Runs no fix
      text: "It prints every command for you to read and run. It never runs one, and says when one needs administrator rights."
    - title: Connects only where you point it
      text: "The URL, its addresses, your resolvers, your proxies and your PAC script. No telemetry, no update check."
    - title: Credentials always masked
      text: "Proxy passwords, authorization headers and cookies never reach a report, with or without `--redact`."
    - title: No administrator rights needed
      text: "It runs as whoever started it, and the report says which rights it ran with."
    - title: One file, nothing to install
      text: "The Linux build is one static binary that runs as it is in Alpine and Ubuntu images."
  link:
    text: Security and privacy
    page: /security
cta:
  title: Find out why it fails, in one run
  text: "Free and open source. Download, unpack, and point it at the URL that fails."
---
