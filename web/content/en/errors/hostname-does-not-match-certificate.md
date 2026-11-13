---
title: Hostname does not match the certificate
seoTitle: "SSL hostname mismatch: certificate not valid for name"
description: "no alternative certificate subject name matches target host name, ERR_TLS_CERT_ALTNAME_INVALID and Hostname mismatch: why the name and the certificate differ."
lead: "The certificate is valid, but not for the name in the URL. No trust store can fix that, and Cert Doctor says so before it asks any."
messages:
  - from: curl, git
    text: "SSL: no alternative certificate subject name matches target host name 'wrong.host.badssl.com'"
  - from: Node.js
    text: "Hostname/IP does not match certificate's altnames (ERR_TLS_CERT_ALTNAME_INVALID)"
  - from: Python
    text: "certificate verify failed: Hostname mismatch, certificate is not valid for 'wrong.host.badssl.com'"
  - from: Go
    text: "x509: certificate is valid for *.badssl.com, badssl.com, not wrong.host.badssl.com"
  - from: Java
    text: "No subject alternative DNS name matching wrong.host.badssl.com found."
---

## What it means

A certificate names the hosts it is for. A client compares the name in the URL with those names, and refuses the connection when none of them covers it, however trusted the certificate's authority is.

## Common causes

- **The URL uses another name for the server** - an IP address, a short internal name, an old alias - that the certificate does not list.
- **A wildcard that does not reach.** `*.example.com` covers `api.example.com` and not `v2.api.example.com` or `example.com` itself.
- **A shared address serving the wrong site**, or a load balancer presenting its default certificate.
- **Something in between answers instead of the server**, with a certificate of its own.

## Find which one is yours

```
certdoctor https://wrong.host.badssl.com/
```

`L4` checks the name from the URL against the certificate of every address, and the verdict names what the certificate covers:

```
x The server presented a certificate for *.badssl.com, badssl.com, and none of those names covers
  wrong.host.badssl.com - clients refuse that whatever they trust, so this is a fact about the
  server or about the name used to reach it.
```

The names covered and the issuer are in `L4` for every address, so a load balancer with one address that answers differently stands out.

## Fix it

Use a name the certificate covers, or have the certificate reissued with the name you need. Adding anything to a trust store does not help, because the authority was never the problem.

## What not to do

Turning off host name checks in a client accepts a valid certificate for any site, including one an attacker owns.
