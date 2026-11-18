---
title: Dekoder certyfikatów
slug: dekoder-certyfikatow
seoTitle: "Dekoder certyfikatów: otwórz plik PEM, CRT lub DER offline"
description: "Odczytaj certyfikat albo cały łańcuch z pliku .pem, .crt lub .der: nazwy, data wygaśnięcia, klucz, odciski SHA-256 i SHA-1, pin SPKI i kolejność łańcucha."
lead: "Otwórz plik certyfikatu i zobacz, dla kogo jest, kto go wystawił, kiedy wygasa i jakie ma odciski palca - jeden certyfikat albo cały łańcuch, offline."
---

## Otwórz plik PEM, CRT albo DER

```
certdoctor tool cert --file server.crt
```

Dekoder czyta:

- **PEM** - plik `.pem`, `.crt` albo `.cer` z jednym albo wieloma blokami `BEGIN CERTIFICATE`, także z tekstem wokół nich, który pomija i o tym mówi,
- **DER** - postać binarną, często plik `.cer` albo `.der`,
- **base64** jednego certyfikatu, bez linii PEM,
- tablicę **`x5c`**, w której łańcuch niesie nagłówek JWT albo JWK.

Klucz prywatny w tym samym pliku nie jest czytany ani pokazywany. Plik `.pfx` albo `.p12` zawiera także klucz i nie jest plikiem certyfikatu, więc dekoder go odrzuca, z kodem wyjścia `3`.

Łańcuch ma wiele linii i nie ma jednego Entera, który by go kończył, więc podaje się go przez `--file` albo potokiem, nigdy wklejając w terminalu:

```
certdoctor tool cert < chain.pem
```

## Odczytaj łańcuch, który wysyła serwer

```
openssl s_client -showcerts -connect example.com:443 </dev/null | certdoctor tool cert
```

Tu z serwerem łączy się `openssl`, a dekoder czyta to, co ten wypisał. Żeby sprawdzić, czy każdy program na tym komputerze ufa temu łańcuchowi - Java, git, curl, Node.js, Python, magazyn systemowy - uruchom zamiast tego diagnozę, `certdoctor https://example.com/`, która pyta każdy [magazyn zaufania](/docs/trust-matrix/).

## Co pokazuje

Sprawdzenia dla całego wejścia, potem każdy certyfikat w kolejności, w jakiej go podano. Fragment prawdziwego przebiegu z 2026-11-18, łańcuch wysłany przez example.com:

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

## Sprawdź datę wygaśnięcia

`Valid until` to ostatnia chwila ważności certyfikatu, z tym, ile zostało. Pierwsze sprawdzenie wskazuje certyfikat z wejścia, który wygasa najwcześniej, i daje:

- `FAIL`, gdy któryś certyfikat wygasł albo jeszcze nie jest ważny - klient sprawdza daty każdego certyfikatu w łańcuchu ([RFC 5280, sekcja 6.1.3](https://www.rfc-editor.org/rfc/rfc5280#section-6.1.3)),
- `WARN`, gdy któryś wygasa w ciągu 30 dni,
- `PASS` w pozostałych przypadkach.

Jeśli program już odrzuca serwer z [certificate has expired](/errors/certificate-has-expired/), diagnoza mówi, który certyfikat łańcucha to był.

## Odcisk palca, thumbprint i pin SPKI

- **SHA-256** - odcisk palca całego certyfikatu, ten, który dziś pokazuje większość narzędzi,
- **SHA-1** - to samo liczone SHA-1, czyli to, co Windows nazywa **Thumbprint**, a polska dokumentacja Microsoftu odciskiem palca ([X509Certificate2.Thumbprint](https://learn.microsoft.com/pl-pl/dotnet/api/system.security.cryptography.x509certificates.x509certificate2.thumbprint)),
- **pin SPKI** - SHA-256 samego klucza publicznego, w base64: wartość, którą przyjmuje `curl --pinnedpubkey sha256//...` ([podręcznik curla](https://curl.se/docs/manpage.html#--pinnedpubkey)). Nie zmienia się, gdy certyfikat odnowiono z tym samym kluczem, a [dekoder CSR](/tools/csr-decoder/) pokazuje go dla żądania, więc oba da się dopasować.

Odcisk palca i thumbprint to skróty całego certyfikatu - różnią się nazwą i bywa, że funkcją skrótu. Dekoder wypisuje je małymi literami bez separatorów. OpenSSL wypisuje te same cyfry wielkimi literami, z dwukropkami między bajtami, więc porównuj cyfry, a resztę pomiń.

## Kolejność i kompletność łańcucha

Przy więcej niż jednym certyfikacie dekoder mówi, czy każdy jest wystawiony przez następny, oraz:

- czy łańcuch jest w kolejności - serwer wysyła najpierw własny certyfikat, a każdy następny poświadcza poprzedni ([RFC 8446, sekcja 4.4.2](https://www.rfc-editor.org/rfc/rfc8446#section-4.4.2)),
- czy w wejściu brakuje wystawcy któregoś certyfikatu - w porządku, gdy to certyfikat główny, który serwer może pominąć, i zerwany łańcuch, gdy to certyfikat pośredni (zobacz [brak certyfikatu pośredniego](/errors/missing-intermediate-certificate/)),
- czy któryś certyfikat jest w wejściu dwa razy albo nie ma związku z resztą.

## Przed czym ostrzega

- certyfikat podpisany MD5 albo SHA-1, poza podpisem certyfikatu głównego na samym sobie,
- klucz RSA krótszy niż 2048 bitów,
- certyfikat serwera bez rozszerzenia subject alternative name albo z takim, w którym nie ma nazwy hosta ani adresu - klienci dopasowują nazwy właśnie tam, a common name pomijają ([RFC 6125, sekcja 6.4.4](https://www.rfc-editor.org/rfc/rfc6125#section-6.4.4)),
- certyfikat, którego biblioteka X.509 tego programu nie umie odczytać - dekoder go wskazuje i nic więcej o nim nie mówi.

## Nie sprawdza zaufania

Dekoder mówi, co mówią certyfikaty. To, czy program im ufa, zależy od magazynu zaufania, który ten program czyta, a dekoder nie pyta żadnego. Dla serwera robi to diagnoza: `certdoctor https://adres-ktory-nie-dziala/`.

## W oknie

Otwórz **Tools** na pasku okna, wybierz **Certificate decoder**, wklej certyfikat albo łańcuch w PEM i naciśnij **Decode**. Odpowiedź pokazuje te same sprawdzenia i certyfikaty. Plik DER, który jest binarny, czyta się wierszem poleceń i `--file`.

## Dla skryptów

`--json` zapisuje każde sprawdzenie i każdy certyfikat, z odciskami palca, datami, nazwami i kluczem:

```
certdoctor tool cert --file chain.pem --json
```

## Przełączniki

{{< tool-options "cert" >}}

`certdoctor tool cert --help` wypisuje to samo w terminalu.

## Kody wyjścia

{{< tool-exit-codes >}}
