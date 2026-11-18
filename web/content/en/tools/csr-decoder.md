---
title: CSR decoder and checker
linkTitle: CSR decoder
seoTitle: "CSR decoder and checker: SAN, key and what a CA refuses"
description: "Decode a certificate signing request from openssl, certreq or keytool: subject, SAN names, key and extensions, its signature, and what a public CA refuses."
lead: "See what a certificate signing request asks for before you send it to a certificate authority - and what in it a public one will not issue."
---

## Decode a CSR

```
certdoctor tool csr --file request.csr
```

The decoder reads a request as `openssl req`, `certreq` on Windows and `keytool -certreq` write it - PEM, base64 or DER. Pipe one in as it is made:

```
openssl req -new -key server.key -subj "/CN=www.example.com" | certdoctor tool csr
```

A private key pasted with the request is not read and not shown. A certificate given by mistake is refused with a sentence that sends you to the [certificate decoder](/tools/certificate-decoder/), and a CMS message, which `certreq` writes for `RequestType = CMC` or `PKCS7`, is refused with a sentence that says so.

## What it shows

A real run on 2026-11-18, a request made with `openssl req` without a subject alternative name:

```
certdoctor 0.3.0   tool csr - CSR decoder
judged at 2026-11-18T16:18:27Z

CHECKS
  ! WARN  The request asks for no subject alternative name, so unless the authority adds names
          itself the certificate has none a client matches: those names are the ones a client
          matches (RFC 6125 section 6.4.4), Go and Chrome since version 58 ignore the common name,
          and a public authority puts them in every certificate (CA/Browser Forum Baseline
          Requirements 7.1.2.7.12).
  + PASS  The request's own key verifies its signature, so the request is as the holder of that key
          signed it.
  + PASS  No RSA key is shorter than 2048 bits.
  + PASS  The key is RSA, a kind a public authority issues for (CA/Browser Forum Baseline
          Requirements 6.1.5).
  + PASS  The request carries no challenge password.
  + PASS  The request's version field is 0, as PKCS #10 defines (RFC 2986 section 4.1).

INPUT
  Read as  PEM

REQUEST
    Subject     CN=www.example.com
  ! Host names  none
    Key         RSA, 2048 bits
    SPKI pin    DBycrPcJ8QiqLcrZYlNlgD6Sj3mcRR3uxF43sb+Fox0=  SHA-256, the same in the certificate
                                                              issued
    Signature   SHA256-RSA                                verified with its own key
    Version     0
```

Every extension and attribute the request carries is listed too - key usage, extended key usage, and the attributes `certreq` adds, by their names.

## Subject alternative name and common name

A client matches the host name against the subject alternative name of the certificate, not the common name ([RFC 6125 section 6.4.4](https://www.rfc-editor.org/rfc/rfc6125#section-6.4.4)). The decoder lists the host names and addresses the request asks for, and warns when:

- it asks for no subject alternative name at all,
- its subject alternative name holds no host name and no address,
- the common name is not one of the names in the subject alternative name - a public authority's certificate carries a common name only when it is one of them,
- the subject has more than one common name.

To add the names with OpenSSL 1.1.1 or newer, give them with `-addext "subjectAltName=DNS:www.example.com,DNS:example.com"` ([openssl-req](https://docs.openssl.org/master/man1/openssl-req/)).

## What a public CA refuses

A public certificate authority follows the CA/Browser Forum Baseline Requirements, and the decoder warns about what they do not allow:

- a host name a public authority cannot issue for - a single label like `localhost`, an underscore or another character than a letter, a digit or a hyphen, an IP address written as a host name, a dot at the end, a wildcard anywhere but the whole first label,
- an e-mail address or a URI among the names of a server's certificate,
- a key it does not issue for - RSA with a size that is not a multiple of 8, ECDSA on a curve other than P-256, P-384 or P-521, or another kind of key - and an RSA key under 2048 bits.

A private authority, the one inside a company, may accept what a public one does not, and every warning says that it is a public authority's rule. The rules about names and kinds of key are asked only of a request a TLS server could use - one that names no purpose, or names serving TLS, and does not ask to be an authority - and the output says when they were not.

## The signature check

A request is signed with the key it carries, so it cannot be changed after it was made ([RFC 2986 section 3](https://www.rfc-editor.org/rfc/rfc2986#section-3)). The decoder checks that signature with the request's own key: `PASS` when it holds, `FAIL` when it does not - the request was changed or damaged. A request signed with SHA-1 gets a warning, and one signed with MD5 a `FAIL`, because Go does not check such a signature at all.

## Challenge password

A challenge password in a request is reported, and never read or shown. It travels in the request as it was typed, so whoever has the file can read it.

## Match the request to its certificate

The `SPKI pin` is SHA-256 of the request's public key. The [certificate decoder](/tools/certificate-decoder/) shows the same value for the certificate issued for it, so the two can be matched without comparing keys by hand.

## In the window

Open **Tools** on the window's bar, choose **CSR decoder**, paste the request in PEM and press **Decode**.

## Options

{{< tool-options "csr" >}}

`certdoctor tool csr --help` prints the same in the terminal.

## Exit codes

{{< tool-exit-codes >}}
