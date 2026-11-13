---
title: Questions
seoTitle: Cert Doctor FAQ - certificate errors, proxies, trust stores
description: "Answers about Cert Doctor: what it does, how it differs from openssl s_client and curl -v, whether it changes anything, whether it needs admin rights, and more."
lead: "The questions people ask first, answered in the first sentence."
layout: faq
faq:
  - question: What is Cert Doctor?
    answer: "A GUI/CLI tool that finds out why this machine cannot connect to a URL and what to run to fix it. It walks DNS, the proxy and PAC script, TCP and TLS, then asks every trust store on the machine whether it trusts the server's certificate chain, and prints the command that fixes each store that does not."
  - question: Why does the browser connect when Java, git or Python does not?
    answer: "Because each of them trusts a different list. A browser on Windows reads the Windows store, Java reads the `cacerts` of its own installation, Git for Windows reads its own bundle and Python reads the list it was set up with. A company root added to one of them does not reach the others. [The trust matrix](/docs/trust-matrix/) shows which list refuses."
  - question: Why not just openssl s_client or curl -v?
    answer: "Both answer for themselves. `openssl s_client` tells you what OpenSSL's store thinks, and the Java service that fails does not use that store. Cert Doctor asks every store it finds the same question about the same chain, and the answer is usually that they disagree."
  - question: Does it change anything on my machine?
    answer: "No. It reads, connects where you pointed it, and writes one report if you ask for one with `--out`. The commands it prints are for you to run, after reading them. [Security and privacy](/security/) has the details."
  - question: Does it need administrator rights?
    answer: "No. It runs as whoever started it, and the report records which rights it ran with. A printed fix says when running it needs administrator or root rights. Only the Windows installer asks for them, because it installs for every account on the machine."
  - question: Will it tell me my company is intercepting my traffic?
    answer: "It tells you who signed the certificate and how many stores on your machine trust that authority, and it names the inspection product when the certificate says so in a way the vendor publishes. From one connection, an inspecting proxy and your own company's certificate authority look the same, so it never accuses anyone on a guess. [TLS inspection](/guides/tls-inspection-corporate-proxy/) says how to read it."
  - question: Can it tell whether the server is at fault?
    answer: "Yes. A server that does not send its intermediate certificate, a certificate that does not cover the name, and a certificate past its validity are named as facts about the server, with the evidence to paste into a ticket."
  - question: Does it work inside a Docker container?
    answer: "Yes. Copy the static Linux binary into the container and run it there, and the report describes the container rather than the host. [Inside a container](/docs/containers/) shows how."
  - question: Can I use it in CI?
    answer: "Yes. Every ending has its own exit code, and `--json` writes a report checked against its schema. [Using it in CI](/docs/ci/) shows a step."
  - question: Is it safe to share a report?
    answer: "Read it first. A report holds internal host names, paths and user names, and `--redact` masks them. Credentials are masked always. Masking is a filter, not a guarantee."
  - question: Is it free? Can I use it at work?
    answer: "Yes to both. It is GPL-3.0 and costs nothing. The reports you generate belong to you."
  - question: Which systems does it run on?
    answer: "The command line runs on Windows and Linux on x64 and Arm, and on macOS on Apple silicon. The window runs on Windows and Linux on x64 and on macOS on Apple silicon. [Download](/download/) has every archive."
  - question: It got my case wrong. What now?
    answer: "That is the most useful issue you can open. Attach the report made with `--redact --json`, say what the right answer was, and name the runtime that disagreed, on the [issue tracker](https://github.com/donislawdev/certdoctor/issues)."
---
