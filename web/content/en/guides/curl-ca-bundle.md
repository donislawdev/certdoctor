---
title: curl and its CA bundle
seoTitle: "curl: (60) SSL certificate problem - which CA bundle"
description: "Fix curl (60) SSL certificate problem. Which CA bundle or store each curl reads, Schannel on Windows, CURL_CA_BUNDLE, and the command that adds a root."
lead: "Two curls on one machine can trust two different lists, depending on the TLS library each was built with."
---

## Which list curl reads

curl trusts the CA bundle it was built or told to use: a file such as `/etc/ssl/certs/ca-certificates.crt`, given with `--cacert` or `CURL_CA_BUNDLE`. A curl built on Schannel, the Windows TLS library - like the `curl.exe` in `C:\Windows\System32` - reads the Windows store instead, and ignores `CURL_CA_BUNDLE` ([curl manual](https://curl.se/docs/manpage.html)).

So the `curl` in System32, the one inside Git for Windows and one from a package manager can each give a different answer for the same URL.

## See which store each curl reads

```
certdoctor https://the-url-that-fails/
```

The trust matrix has a row for every `curl` it finds. Cert Doctor asks each one how it was built, with `curl --version`, and judges it by the list that build reads. A curl on Schannel points at the Windows store's row rather than repeating it:

```
      curl C:\Windows\system32\curl.exe does NOT trust the presented chain (90 anchors) - it judges
        by system-store CurrentUser, which refuses it  detected
```

Its fix is that store's command. A curl reading a bundle gets an append to that bundle.

## Add the root

- **A curl on Schannel**: add the root to the Windows store - [the Windows certificate store](/guides/windows-certificate-store/).
- **A curl reading a bundle**: append the root to the bundle, as the row prints it. On Linux that bundle is usually the distribution's - [the Linux CA bundle](/guides/linux-ca-bundle/).

## What not to do

`curl -k` and `--insecure` skip verification for that request. They are fine for looking at a broken server on purpose, and wrong as a fix.
