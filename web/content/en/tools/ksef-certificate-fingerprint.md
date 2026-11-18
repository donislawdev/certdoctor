---
title: KSeF certificate fingerprint
seoTitle: "KSeF certificate fingerprint: read the SHA-256 offline"
description: "The fingerprint KSeF asks for is the SHA-256 of the certificate. Read it from the .cer or .crt file on your own machine, and write it in capitals as KSeF does."
lead: "KSeF, the Polish e-invoicing system, identifies a certificate without a NIP or PESEL by its fingerprint: the SHA-256 of the whole certificate, 64 hexadecimal digits."
---

## What KSeF calls a fingerprint

The Ministry of Finance's user manual of the Certificates and Permissions Module (MCU) defines the certificate fingerprint as a value computed from the certificate with SHA-256, shown as a string of 64 characters ([MCU user manual](https://ksef.podatki.gov.pl/media/0iafuqe5/podrecznik-uzytkownika-modulu-certyfikatow-i-uprawnien-mcu.pdf), November 2025, page 5). The Ministry's own Java client computes it over the encoded certificate and writes it in capital letters ([`getSha256Fingerprint`](https://github.com/CIRFMF/ksef-client-java/blob/main/ksef-client/src/main/java/pl/akmf/ksef/sdk/api/services/DefaultCertificateService.java)), and its C# client accepts exactly 64 capital hexadecimal digits ([`RegexPatterns`](https://github.com/CIRFMF/ksef-client-csharp/blob/main/KSeF.Client/Validation/RegexPatterns.cs)).

That is the certificate's SHA-256 fingerprint, the same value the [certificate decoder](/tools/certificate-decoder/) prints in its `SHA-256` row.

It is not the **Thumbprint** Windows shows for a certificate, which Microsoft's Polish documentation also calls *odcisk palca*: that one is SHA-1, 40 characters ([X509Certificate2.Thumbprint](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificate2.thumbprint)). KSeF wants the 64 characters of SHA-256.

## When you need it

A qualified certificate that holds neither a NIP nor a PESEL can be used in KSeF only after permissions are granted to its fingerprint (MCU manual, page 17). Permissions for a person or an EU entity can be granted to a fingerprint in the same way ([KSeF API documentation, permissions](https://github.com/CIRFMF/ksef-docs/blob/main/uprawnienia.md)).

## Read it from the certificate file

The file is the certificate itself, without its private key - usually a `.cer` or `.crt` file, in PEM or in DER:

```
certdoctor tool cert --file certificate.cer
```

The fingerprint is the `SHA-256` row:

```
  SHA-256           7767265b01d8e5c8c7eff9300a10706d8e3dad5ccb55f688acaabbc28cca3d34
```

The decoder writes it in lower case, and KSeF in capitals - the same 64 digits. To print it in capitals in PowerShell:

```
(certdoctor tool cert --file certificate.cer --json | ConvertFrom-Json).data.certificates[0].fingerprint_sha256.ToUpper()
```

On Linux and macOS, with `jq`:

```
certdoctor tool cert --file certificate.cer --json | jq -r '.data.certificates[0].fingerprint_sha256' | tr a-f A-F
```

The file is read on your machine and nothing is sent anywhere. A `.pfx` or `.p12` file holds the private key as well and is not a certificate file, so the decoder refuses it.

## The other way: MCU

MCU computes the fingerprint of a qualified certificate from a file you sign with it: download the file, sign it with the qualified certificate, hand the signed file back, and press **Pobierz odcisk palca** (MCU manual, pages 17-18). Both ways give the SHA-256 of the same certificate.

## KSeF certificates

The certificates MCU itself issues - KSeF certificates for authentication and for offline invoices - are downloaded in PEM with the `.crt` extension (MCU manual, page 85). The certificate decoder reads them as any other: who they are for, when they expire, the key and the fingerprints.

```
certdoctor tool cert --file Certyfikat_testowy.crt
```
