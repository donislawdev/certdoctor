---
title: Dekoder i walidator CSR
linkTitle: Dekoder CSR
slug: dekoder-csr
seoTitle: "Dekoder CSR: nazwy, klucz i to, czego odmówi publiczne CA"
description: "Zdekoduj żądanie podpisania certyfikatu z openssl, certreq albo keytool: podmiot, nazwy SAN, klucz, rozszerzenia, podpis i to, czego odmówi publiczne CA."
lead: "Zobacz, o co prosi żądanie podpisania certyfikatu (CSR), zanim wyślesz je do urzędu certyfikacji - i czego publiczny urząd w nim nie wystawi."
---

## Zdekoduj CSR

```
certdoctor tool csr --file request.csr
```

Dekoder czyta żądanie w postaci, w jakiej zapisują je `openssl req`, `certreq` na Windowsie i `keytool -certreq` - PEM, base64 albo DER. Można je podać potokiem od razu przy tworzeniu:

```
openssl req -new -key server.key -subj "/CN=www.example.com" | certdoctor tool csr
```

Klucz prywatny wklejony razem z żądaniem nie jest czytany ani pokazywany. Certyfikat podany przez pomyłkę jest odrzucany zdaniem, które odsyła do [dekodera certyfikatów](/tools/certificate-decoder/), a wiadomość CMS, którą `certreq` zapisuje przy `RequestType = CMC` albo `PKCS7`, jest odrzucana zdaniem, które to mówi.

## Co pokazuje

Prawdziwy przebieg z 2026-11-18, żądanie zrobione przez `openssl req` bez subject alternative name:

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

Wypisane są też wszystkie rozszerzenia i atrybuty, które niesie żądanie - użycie klucza, rozszerzone użycie klucza i atrybuty, które dodaje `certreq`, pod ich nazwami.

## Subject alternative name i common name

Klient dopasowuje nazwę hosta do subject alternative name certyfikatu, a nie do common name ([RFC 6125, sekcja 6.4.4](https://www.rfc-editor.org/rfc/rfc6125#section-6.4.4)). Dekoder wypisuje nazwy hostów i adresy, o które prosi żądanie, i ostrzega, gdy:

- nie prosi o żaden subject alternative name,
- jego subject alternative name nie zawiera nazwy hosta ani adresu,
- common name nie jest jedną z nazw z subject alternative name - certyfikat publicznego urzędu niesie common name tylko wtedy, gdy jest jedną z nich,
- podmiot ma więcej niż jedno common name.

Żeby dodać nazwy w OpenSSL 1.1.1 lub nowszym, podaj je przez `-addext "subjectAltName=DNS:www.example.com,DNS:example.com"` ([openssl-req](https://docs.openssl.org/master/man1/openssl-req/)).

## Czego odmówi publiczne CA

Publiczny urząd certyfikacji stosuje Baseline Requirements CA/Browser Forum, a dekoder ostrzega przed tym, na co one nie pozwalają:

- nazwa hosta, dla której publiczny urząd nie może wystawić certyfikatu - pojedyncza etykieta, jak `localhost`, podkreślnik albo inny znak niż litera, cyfra i łącznik, adres IP zapisany jako nazwa hosta, kropka na końcu, gwiazdka gdzie indziej niż jako cała pierwsza etykieta,
- adres e-mail albo URI wśród nazw certyfikatu serwera,
- klucz, dla którego nie wystawia certyfikatów - RSA o rozmiarze niebędącym wielokrotnością 8, ECDSA na innej krzywej niż P-256, P-384 i P-521 albo klucz innego rodzaju - oraz klucz RSA krótszy niż 2048 bitów.

Prywatny urząd, ten wewnątrz firmy, może przyjąć to, czego publiczny nie przyjmie, a każde ostrzeżenie mówi, że to reguła publicznego urzędu. Reguły dotyczące nazw i rodzaju klucza są stosowane tylko do żądania, którego mógłby użyć serwer TLS - takiego, które nie podaje przeznaczenia albo podaje obsługę TLS i nie prosi o bycie urzędem - a wynik mówi, kiedy ich nie zastosowano.

## Sprawdzenie podpisu

Żądanie jest podpisane kluczem, który niesie, żeby nie dało się go zmienić po utworzeniu ([RFC 2986, sekcja 3](https://www.rfc-editor.org/rfc/rfc2986#section-3)). Dekoder sprawdza ten podpis własnym kluczem żądania: `PASS`, gdy się zgadza, `FAIL`, gdy nie - żądanie zmieniono albo jest uszkodzone. Żądanie podpisane SHA-1 dostaje ostrzeżenie, a podpisane MD5 `FAIL`, bo Go takiego podpisu w ogóle nie sprawdza.

## Hasło wyzwania

Hasło wyzwania (challenge password) w żądaniu jest zgłaszane, ale nigdy czytane ani pokazywane. Podróżuje w żądaniu tak, jak je wpisano, więc może je przeczytać każdy, kto ma ten plik.

## Dopasuj żądanie do certyfikatu

`SPKI pin` to SHA-256 klucza publicznego żądania. [Dekoder certyfikatów](/tools/certificate-decoder/) pokazuje tę samą wartość dla certyfikatu wystawionego na to żądanie, więc oba da się dopasować bez porównywania kluczy ręcznie.

## W oknie

Otwórz **Tools** na pasku okna, wybierz **CSR decoder**, wklej żądanie w PEM i naciśnij **Decode**.

## Przełączniki

{{< tool-options "csr" >}}

`certdoctor tool csr --help` wypisuje to samo w terminalu.

## Kody wyjścia

{{< tool-exit-codes >}}
