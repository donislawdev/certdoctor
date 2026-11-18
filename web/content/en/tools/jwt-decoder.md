---
title: Offline JWT decoder
linkTitle: JWT decoder
seoTitle: "JWT decoder offline: decode a token without uploading it"
description: "Decode a JWT on your own machine, in a terminal or a window: header, claims, iat, nbf and exp in UTC, alg none and stripped signatures. Nothing is uploaded."
lead: "See what a JSON Web Token says - its header, its claims and when it expires - without pasting it into a website."
---

## Why decode a token on your own machine

An access token or an ID token carries who it was issued to - a user ID, often a name or an email address - and what it allows. A bearer token can be used by anyone who holds it ([RFC 6750 section 1.2](https://www.rfc-editor.org/rfc/rfc6750#section-1.2)), until it expires. Decoding one on a website means handing it to that website.

`certdoctor tool jwt` reads the token on your machine and connects to nothing.

## Decode a JWT in the terminal

```
certdoctor tool jwt
```

Paste the token and press Enter. `Bearer` in front of it and quotes around it are taken off, and the output says so, so the value of an `Authorization` header can be pasted as it is. On Linux and macOS the token does not appear while you paste it, and after Enter the command says how many characters it read.

From a file, in any shell:

```
certdoctor tool jwt --file token.txt
```

From a pipe - in PowerShell, `Get-Content token.txt | certdoctor tool jwt`:

```
certdoctor tool jwt < token.txt
```

The token is never taken as an argument, because an argument stays in your shell's history and in the list of running programs.

## What it shows

The checks first, then the token's form, its times in UTC with how long ago or how soon, and the header and the claims in the order the token has them. A real run on 2026-11-18, with `Bearer` in front of the token:

```
certdoctor 0.3.0   tool jwt - JWT decoder
judged at 2026-11-18T16:40:49Z

NOTES
  Took off "Bearer" in front of the token.

CHECKS
  ? UNKNOWN  Not checked: checking the signature needs the issuer's key, which this tool does not
             take.
  + PASS     Valid for 49 minutes more, until 2026-11-18 17:30:00 UTC.
  + PASS     Valid since 2026-11-18 16:30:00 UTC.

TOKEN
  Form       Signed (JWS), 3 parts
  Algorithm  RS256
  Type       JWT
  Key ID     2026-11-signing
  Signature  256 bytes, not checked
  Length     614 characters

TIMES
    Issued (iat)      2026-11-18 16:30:00 UTC  10 minutes ago
  + Not before (nbf)  2026-11-18 16:30:00 UTC  10 minutes ago
  + Expires (exp)     2026-11-18 17:30:00 UTC  in 49 minutes

HEADER
  {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "2026-11-signing"
  }

PAYLOAD
  {
    "iss": "https://login.example.com/",
    "sub": "user-1842",
    "aud": "api.example.com",
    "iat": 1795019400,
    "nbf": 1795019400,
    "exp": 1795023000,
    "scope": "orders:read"
  }
```

## When it expires: exp, nbf and iat

A JWT keeps its times as seconds since 1970 ([RFC 7519 section 2](https://www.rfc-editor.org/rfc/rfc7519#section-2)). The decoder prints each one as a date in UTC, with how long ago or how soon it is, and checks them against this machine's clock:

- `exp` in the past is `FAIL`: from that moment on the token must not be accepted ([RFC 7519 section 4.1.4](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4)),
- `nbf` in the future is `FAIL`: the token is not valid yet ([section 4.1.5](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5)),
- `iat` in the future is `WARN`: the clock of whoever issued it, or of this machine, is wrong,
- no `exp` at all is `WARN`: nothing in the token stops it being accepted for ever,
- a token that expires before it becomes valid, or a time that is not a number of seconds, is `WARN`.

```
  x FAIL  Expired 60 minutes ago, at 2026-11-18 15:40:00 UTC - from that moment on it must not be
          accepted (RFC 7519 section 4.1.4).
```

## What it warns about

The decoder looks for what makes two libraries read the same token differently:

- `alg: none` - the token is not signed, so anyone can write one like it ([RFC 7518 section 3.6](https://www.rfc-editor.org/rfc/rfc7518#section-3.6)),
- an algorithm named and the signature empty - the token was cut short or stripped of its signature,
- a signature of the wrong length for its algorithm, an ECDSA signature written in ASN.1 DER where a JWT carries R and S side by side ([RFC 7518 section 3.4](https://www.rfc-editor.org/rfc/rfc7518#section-3.4)), or an RSA signature from a key under 2048 bits,
- a header without `alg`,
- a name given twice in the header or the claims - one library refuses such a token and another takes the last value,
- padding or standard base64 where a JWT has base64url without padding ([RFC 7515 section 2](https://www.rfc-editor.org/rfc/rfc7515#section-2)),
- `"b64": false` without `crit` naming it, and a payload that is not a JSON object.

```
  x FAIL  alg is "HS256" but the signature is empty, so the token was cut short or stripped of its
          signature.
```

An encrypted token (JWE, five parts) shows its header, and says that reading the rest needs the recipient's key.

## The signature is not checked

Checking a signature needs the issuer's key, and the decoder takes none. Every run says so with an `UNKNOWN` check, so a decoded token is never mistaken for a verified one.

## In the window

Open **Tools** on the window's bar and choose **JWT decoder**. Paste the token, with or without `Bearer` in front of it, and press **Decode**. The answer shows the same checks, times and claims.

## For scripts

`--json` writes a document with every check, its status and its id, and the header, claims and times:

```
certdoctor tool jwt --file token.txt --json
```

## Options

{{< tool-options "jwt" >}}

`certdoctor tool jwt --help` prints the same in the terminal.

## Exit codes

{{< tool-exit-codes >}}
