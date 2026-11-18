---
title: Certificate decoder
seoTitle: "Certificate decoder and viewer for PEM, CRT and DER files"
description: "Read a certificate or a whole chain from a .pem, .crt or .der file: names, expiry date, key, SHA-256 and SHA-1 fingerprints, SPKI pin and chain order."
lead: "Open a certificate file and see who it is for, who issued it, when it expires and its fingerprints - one certificate or a whole chain, offline."
---

## Open a PEM, CRT or DER file

```
certdoctor tool cert --file server.crt
```

The decoder reads:

- **PEM** - a `.pem`, `.crt` or `.cer` file with one or many `BEGIN CERTIFICATE` blocks, text around them included, which it skips and says so,
- **DER** - the binary form, often a `.cer` or `.der` file,
- **base64** of one certificate, without the PEM lines,
- an **`x5c`** array, as a JWT header or a JWK carries the chain.

A private key in the same file is not read and not shown. A `.pfx` or `.p12` file holds a key as well and is not a certificate file, so the decoder refuses it, with exit code `3`.

A chain has many lines and no single Enter that ends it, so it is named with `--file` or piped in, never pasted at a prompt:

```
certdoctor tool cert < chain.pem
```

## Read the chain a server sends

```
openssl s_client -showcerts -connect example.com:443 </dev/null | certdoctor tool cert
```

Here `openssl` connects to the server and the decoder reads what it printed. To find out whether each program on this machine trusts that chain - Java, git, curl, Node.js, Python, the system store - run the diagnosis instead, `certdoctor https://example.com/`, which asks every [trust store](/docs/trust-matrix/).

## What it shows

The checks for the whole input, then every certificate in the order it was given. An excerpt of a real run on 2026-11-18, the chain example.com sent:

```
certdoctor 0.3.0   tool cert - Certificate decoder
judged at 2026-11-18T16:18:26Z

NOTES
  Text outside the PEM blocks was not read.

CHECKS
  + PASS  All 4 are valid now. The first to end is certificate 1 (example.com), in 37 days, at
          2026-12-25 22:56:35 UTC.
  + PASS  No certificate is signed with MD5 or SHA-1, apart from any root's signature on itself,
          which a client does not check (RFC 5280 section 6.1.1).
  + PASS  No RSA key is shorter than 2048 bits.
  + PASS  Certificate 1 (example.com) is for example.com and *.example.com.
  ...
  + PASS  In order: each certificate is followed by the one that issued it.

INPUT
    Read as  PEM - 4 certificates
  + Chain    1, issued by 2, issued by 3, issued by 4, whose issuer is not in the input

CERTIFICATE 1
  Subject               CN=example.com
  Issuer                CN=Cloudflare TLS Issuing ECC CA 3,O=SSL Corporation,C=US
  Host names            example.com, *.example.com
  Valid from            2026-09-26 22:49:11 UTC                   52 days ago
  Valid until           2026-12-25 22:56:35 UTC                   in 37 days
  Key                   ECDSA, P-256
  Signature             ECDSA-SHA256
  Authority             no
  Serial number         01eee6aabb521d5e14fc315fd9985690
  Key usage             digitalSignature
  Extended key usage    serverAuth
  SHA-256               85ca6ab068e9bcce88b6c4aa3c47f7d17228134a457f870d3800e6223a0df07a
  SHA-1                 899cb259e7de8df10033a2af48c22c2f6580a21d  the thumbprint Windows shows
  SPKI pin              toyMGpiThuoVaTygu6QeCcnum2PKJknnGOsHalH7BzU=  SHA-256, for pinning
  ...
```

## Check the expiry date

`Valid until` is the last moment the certificate is valid, with how long is left. The first check names the certificate in the input that ends first, and it is:

- `FAIL` when a certificate has expired or is not valid yet - a client checks the dates of every certificate in the chain ([RFC 5280 section 6.1.3](https://www.rfc-editor.org/rfc/rfc5280#section-6.1.3)),
- `WARN` when one ends within 30 days,
- `PASS` otherwise.

If a program already refuses the server with [certificate has expired](/errors/certificate-has-expired/), the diagnosis says which certificate of the chain it was.

## Fingerprint, thumbprint and SPKI pin

- **SHA-256** - the fingerprint of the whole certificate, the one most tools show today,
- **SHA-1** - the same over SHA-1, which Windows shows as the **Thumbprint** of a certificate ([X509Certificate2.Thumbprint](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificate2.thumbprint)),
- **SPKI pin** - SHA-256 of the public key alone, in base64: the value `curl --pinnedpubkey sha256//...` takes ([curl manual](https://curl.se/docs/manpage.html#--pinnedpubkey)). It stays the same when a certificate is renewed with the same key, and the [CSR decoder](/tools/csr-decoder/) shows it for a request, so the two can be matched.

A fingerprint and a thumbprint are both hashes of the whole certificate - the names differ, and so may the hash. The decoder prints them in lower case without separators. OpenSSL prints the same digits in capitals with colons between the bytes, so compare the digits and ignore the rest.

## Chain order and completeness

With more than one certificate, the decoder says whether each one is issued by the next, and:

- whether the chain is in order - a server sends its own certificate first and each next one certifies the one before it ([RFC 8446 section 4.4.2](https://www.rfc-editor.org/rfc/rfc8446#section-4.4.2)),
- whether a certificate's issuer is missing from the input - fine when it is a root, which a server may leave out, and a broken chain when it is an intermediate (see [missing intermediate certificate](/errors/missing-intermediate-certificate/)),
- whether a certificate is in the input twice, or has nothing to do with the rest.

## What it warns about

- a certificate signed with MD5 or SHA-1, apart from a root's signature on itself,
- an RSA key under 2048 bits,
- a server certificate without a subject alternative name, or with one that holds no host name and no address - clients match the names there and ignore the common name ([RFC 6125 section 6.4.4](https://www.rfc-editor.org/rfc/rfc6125#section-6.4.4)),
- a certificate this program's X.509 library cannot read, which it names, and says nothing more about.

## It checks no trust

The decoder says what the certificates say. Whether a program trusts them depends on the trust store that program reads, and the decoder asks none. The diagnosis does, for a server: `certdoctor https://the-url-that-fails/`.

## In the window

Open **Tools** on the window's bar, choose **Certificate decoder**, paste the certificate or the chain in PEM and press **Decode**. The answer shows the same checks and certificates. A DER file, which is binary, is read with the command line and `--file`.

## For scripts

`--json` writes every check and every certificate, with its fingerprints, dates, names and key:

```
certdoctor tool cert --file chain.pem --json
```

## Options

{{< tool-options "cert" >}}

`certdoctor tool cert --help` prints the same in the terminal.

## Exit codes

{{< tool-exit-codes >}}
