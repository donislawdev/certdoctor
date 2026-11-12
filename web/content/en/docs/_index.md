---
title: Documentation
seoTitle: certdoctor documentation - layers, trust matrix, CLI
description: "How certdoctor finds why a URL fails on this machine: the six layers, the trust matrix, reports, CI, containers, the window and every switch."
lead: "Everything the command line and the window do, and how to read what they tell you."
cards:
  - /docs/getting-started
  - /docs/read-the-report
  - /docs/layers
  - /docs/trust-matrix
  - /docs/proxy-and-pac
  - /docs/reports
  - /docs/ci
  - /docs/containers
  - /docs/window
  - /docs/cli
  - /docs/exit-codes
  - /docs/verify-a-download
---

certdoctor is two programs over one diagnosis. `certdoctor` is the command line: you give it the URL that fails, and it prints a report in the terminal or writes one for a ticket or a pipeline. `certdoctor-gui` is a window that runs the same command line and shows the same report, for anyone who would rather type an address into a box.

A run walks the path a connection takes - the environment, name resolution, the proxy, TCP, TLS - and then asks every trust store it finds on the machine whether it trusts the chain the server presented. The report opens with one sentence naming the cause, and every store that refuses carries the command that would fix it.

If you came here with an error message, the [error pages](/errors/) start from the message. If you know which program refuses, the [fix guides](/guides/) start from the program.
