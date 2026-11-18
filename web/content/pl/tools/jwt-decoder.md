---
title: Dekoder JWT offline
linkTitle: Dekoder JWT
slug: dekoder-jwt
seoTitle: "Dekoder JWT offline (JWT decoder) bez wysyłania tokena"
description: "Zdekoduj JWT na swoim komputerze, w terminalu albo w oknie: nagłówek, claims, iat, nbf i exp w UTC, alg none i obcięty podpis. Token nigdzie nie wychodzi."
lead: "Zobacz, co mówi JSON Web Token - jego nagłówek, claims i kiedy wygasa - bez wklejania go na stronę internetową."
---

## Dlaczego dekodować token u siebie

Token dostępu albo token ID niesie to, komu go wydano - identyfikator użytkownika, często imię i nazwisko albo adres e-mail - i na co pozwala. Tokenu typu bearer może użyć każdy, kto go ma ([RFC 6750, sekcja 1.2](https://www.rfc-editor.org/rfc/rfc6750#section-1.2)), aż do jego wygaśnięcia. Dekodowanie go na stronie internetowej to oddanie go tej stronie.

`certdoctor tool jwt` czyta token na twoim komputerze i z niczym się nie łączy.

## Zdekoduj JWT w terminalu

```
certdoctor tool jwt
```

Wklej token i naciśnij Enter. `Bearer` przed tokenem i cudzysłowy wokół niego są zdejmowane, a wynik o tym mówi, więc wartość nagłówka `Authorization` można wkleić tak, jak jest. Na Linuksie i macOS token nie pojawia się na ekranie podczas wklejania, a po Enterze polecenie mówi, ile znaków odczytało.

Z pliku, w każdej powłoce:

```
certdoctor tool jwt --file token.txt
```

Z potoku - w PowerShell `Get-Content token.txt | certdoctor tool jwt`:

```
certdoctor tool jwt < token.txt
```

Token nigdy nie jest przyjmowany jako argument, bo argument zostaje w historii powłoki i na liście uruchomionych programów.

## Co pokazuje

Najpierw sprawdzenia, potem postać tokena, jego czasy w UTC z tym, jak dawno albo jak niedługo, oraz nagłówek i claims w kolejności, w jakiej ma je token. Prawdziwy przebieg z 2026-11-18, z `Bearer` przed tokenem:

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

## Kiedy wygasa: exp, nbf i iat

JWT zapisuje czasy jako liczbę sekund od 1970 roku ([RFC 7519, sekcja 2](https://www.rfc-editor.org/rfc/rfc7519#section-2)). Dekoder pokazuje każdy z nich jako datę w UTC, z tym, jak dawno albo jak niedługo to jest, i porównuje je z zegarem tego komputera:

- `exp` w przeszłości to `FAIL`: od tej chwili tokenu nie wolno przyjąć ([RFC 7519, sekcja 4.1.4](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4)),
- `nbf` w przyszłości to `FAIL`: token jeszcze nie jest ważny ([sekcja 4.1.5](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5)),
- `iat` w przyszłości to `WARN`: zegar tego, kto go wydał, albo tego komputera jest zły,
- brak `exp` to `WARN`: nic w tokenie nie przeszkadza przyjmować go w nieskończoność,
- token, który wygasa, zanim stanie się ważny, albo czas, który nie jest liczbą sekund, to `WARN`.

```
  x FAIL  Expired 60 minutes ago, at 2026-11-18 15:40:00 UTC - from that moment on it must not be
          accepted (RFC 7519 section 4.1.4).
```

## Przed czym ostrzega

Dekoder szuka tego, przez co dwie biblioteki czytają ten sam token różnie:

- `alg: none` - token nie jest podpisany, więc każdy może napisać taki sam ([RFC 7518, sekcja 3.6](https://www.rfc-editor.org/rfc/rfc7518#section-3.6)),
- algorytm podany, a podpis pusty - token obcięto albo zdjęto z niego podpis,
- podpis o złej długości dla swojego algorytmu, podpis ECDSA zapisany w ASN.1 DER tam, gdzie JWT niesie R i S obok siebie ([RFC 7518, sekcja 3.4](https://www.rfc-editor.org/rfc/rfc7518#section-3.4)), albo podpis RSA z klucza krótszego niż 2048 bitów,
- nagłówek bez `alg`,
- nazwa podana dwa razy w nagłówku albo w claims - jedna biblioteka odrzuci taki token, a druga weźmie ostatnią wartość,
- dopełnienie albo zwykłe base64 tam, gdzie JWT ma base64url bez dopełnienia ([RFC 7515, sekcja 2](https://www.rfc-editor.org/rfc/rfc7515#section-2)),
- `"b64": false` bez `crit`, które go wymienia, oraz treść, która nie jest obiektem JSON.

```
  x FAIL  alg is "HS256" but the signature is empty, so the token was cut short or stripped of its
          signature.
```

Zaszyfrowany token (JWE, pięć części) pokazuje swój nagłówek i mówi, że odczytanie reszty wymaga klucza odbiorcy.

## Podpis nie jest sprawdzany

Sprawdzenie podpisu wymaga klucza wystawcy, a dekoder żadnego nie przyjmuje. Każdy przebieg mówi o tym sprawdzeniem `UNKNOWN`, więc zdekodowanego tokena nie da się pomylić ze zweryfikowanym.

## W oknie

Otwórz **Tools** na pasku okna i wybierz **JWT decoder**. Wklej token, z `Bearer` przed nim albo bez, i naciśnij **Decode**. Odpowiedź pokazuje te same sprawdzenia, czasy i claims.

## Dla skryptów

`--json` zapisuje dokument z każdym sprawdzeniem, jego statusem i identyfikatorem oraz z nagłówkiem, claims i czasami:

```
certdoctor tool jwt --file token.txt --json
```

## Przełączniki

{{< tool-options "jwt" >}}

`certdoctor tool jwt --help` wypisuje to samo w terminalu.

## Kody wyjścia

{{< tool-exit-codes >}}
