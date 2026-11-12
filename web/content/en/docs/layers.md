---
title: What it checks, layer by layer
linkTitle: The six layers
seoTitle: What certdoctor checks - DNS, proxy, TCP, TLS, trust
description: "The six layers of a certdoctor run: environment variables, DNS from every resolver, proxy and PAC, TCP to every address, the TLS chain and the trust matrix."
lead: "A connection can fail at six places. A run looks at every one of them, in the order a connection meets them."
---

{{< layers >}}

## L0 Context

The machine itself: which system, whether it runs inside a container, and which environment variables that decide trust and proxying are set. A variable set in one spelling and not the other - `HTTPS_PROXY` without `https_proxy` - is worth knowing, because programs disagree about which one counts. L0 reads these, in this order:

{{< variables >}}

They are read as things to diagnose. None of them changes what certdoctor itself does: the only variable it obeys is `NO_COLOR`, and that only changes how the report looks.

## L1 Name resolution

The name is looked up twice: every configured resolver is asked directly, and the system resolver is asked the way programs on this machine ask it. When the two views differ, the difference is classified - a split horizon, where an internal and a public resolver answer differently, an answer that leaks past a VPN, or a name that resolves nowhere. A name that does not resolve is the cause, whatever happens after it.

## L2 Proxy

Which proxy this URL really goes through, and who decided that: the environment variables, the Windows Internet Settings that Edge, Chrome and .NET follow, the WinHTTP settings that Windows services follow, and the PAC script your machine names. The PAC script is run in a sandbox to see where it sends this URL, and the proxy is asked whether it wants credentials. [Proxy and PAC](/docs/proxy-and-pac/) has the details.

## L3 TCP

A connection to every address the name resolved to, in parallel and reported in the order of the addresses. A refused connection, an unreachable network and a timeout are told apart, per address, because they point at different culprits.

## L4 TLS

A TLS handshake with every address that accepted a connection, and the full certificate chain each one presented, with fingerprints and validity dates. The handshake is completed without verifying the chain, on purpose: a chain that fails verification would otherwise leave nothing to look at, and here the chain is the evidence.

L4 also checks that the certificate covers the name in the URL, that the chain is complete - a server that does not send its intermediate certificate is named here - and whether every address presented the same chain. A URL that starts with `http://` has no handshake to make, and the report says so.

## L5 Trust matrix

The chain from L4, put to every trust store on the machine: does this store trust it? One row per store, and every row that refuses carries the command that would fix it. [The trust matrix](/docs/trust-matrix/) says which stores are asked.

## Which layer decides

The sentence at the top of the report comes from the layer that decided the outcome, and that is not always the first red one. A name that resolves nowhere is the cause even though every later layer fails too. A certificate that does not cover the name is the cause even when some stores trust its authority. A server that does not send its intermediate certificate is named as the server's fault, even though every store then refuses the chain.
