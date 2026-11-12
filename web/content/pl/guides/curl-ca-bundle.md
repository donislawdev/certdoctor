---
title: curl i jego pakiet CA
seoTitle: "curl: (60) SSL certificate problem - który pakiet CA"
description: "Napraw curl (60) SSL certificate problem. Który pakiet CA albo magazyn czyta każdy curl, Schannel na Windowsie, CURL_CA_BUNDLE i polecenie naprawy."
lead: "Dwa curle na jednej maszynie mogą ufać dwóm różnym listom, zależnie od biblioteki TLS, z którą zbudowano każdy z nich."
---

## Którą listę czyta curl

curl ufa pakietowi CA, z którym go zbudowano albo który mu wskazano: plikowi takiemu jak `/etc/ssl/certs/ca-certificates.crt`, podanemu przez `--cacert` albo `CURL_CA_BUNDLE`. curl zbudowany na Schannel, bibliotece TLS Windows - jak `curl.exe` w `C:\Windows\System32` - czyta zamiast tego magazyn Windows i ignoruje `CURL_CA_BUNDLE` ([podręcznik curl](https://curl.se/docs/manpage.html)).

Dlatego `curl` z System32, ten wewnątrz Git for Windows i ten z menedżera pakietów mogą dać różne odpowiedzi dla tego samego adresu.

## Zobacz, który magazyn czyta każdy curl

```
certdoctor https://adres-ktory-nie-dziala/
```

Macierz zaufania ma wiersz dla każdego znalezionego `curl`. certdoctor pyta każdy z nich, jak go zbudowano, przez `curl --version`, i ocenia go według listy, którą czyta ta wersja. curl na Schannel wskazuje wiersz magazynu Windows, zamiast go powtarzać:

```
      curl C:\Windows\system32\curl.exe does NOT trust the presented chain (90 anchors) - it judges
        by system-store CurrentUser, which refuses it  detected
```

Jego naprawą jest polecenie tego magazynu. curl czytający pakiet dostaje dopisanie do tego pakietu.

## Dodaj certyfikat główny

- **curl na Schannel**: dodaj certyfikat główny do magazynu Windows - [magazyn certyfikatów Windows](/guides/windows-certificate-store/).
- **curl czytający pakiet**: dopisz certyfikat główny do pakietu, tak jak wypisuje to wiersz. Na Linuksie to zwykle pakiet dystrybucji - [pakiet CA Linuksa](/guides/linux-ca-bundle/).

## Czego nie robić

`curl -k` i `--insecure` pomijają weryfikację dla tego żądania. Nadają się do celowego oglądania zepsutego serwera, a jako naprawa są błędem.
