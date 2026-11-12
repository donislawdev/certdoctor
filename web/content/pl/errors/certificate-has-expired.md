---
title: certificate has expired
codeTitle: true
seoTitle: "Certyfikat SSL wygasł: który i dlaczego"
description: "certificate has expired, CERT_HAS_EXPIRED i x509 certificate has expired or is not yet valid: który certyfikat w łańcuchu wygasł i czyja to naprawa."
lead: "Certyfikat w łańcuchu jest po terminie ważności albo tak twierdzi zegar tej maszyny. Raport pokazuje który certyfikat, jego daty i czas przebiegu."
messages:
  - from: curl, git
    text: "SSL certificate problem: certificate has expired"
  - from: Node.js
    text: "Error: certificate has expired (CERT_HAS_EXPIRED)"
  - from: Python
    text: "certificate verify failed: certificate has expired"
  - from: Go
    text: "x509: certificate has expired or is not yet valid"
  - from: Java
    text: "PKIX path validation failed: java.security.cert.CertPathValidatorException: validity check failed"
---

## Co to znaczy

Każdy certyfikat jest ważny między dwiema datami. Klient odrzuca łańcuch, w którym którykolwiek certyfikat, serwera albo któryś nad nim, jest poza tymi datami w chwili połączenia.

## Częste przyczyny

- **Wygasł certyfikat serwera** i nikt go nie odnowił. Każdy klient pada, a naprawa jest na serwerze.
- **Wygasł certyfikat pośredni albo główny w łańcuchu**, choć istnieje nowszy. Serwer, który wciąż wysyła stary certyfikat pośredni, pada w części klientów, a w innych nie.
- **Zegar tej maszyny jest zły.** Maszyna wirtualna przywrócona z migawki albo maszyna bez synchronizacji czasu może się mylić o dni albo lata.

## Ustal, która dotyczy ciebie

```
certdoctor https://adres-ktory-nie-dziala/
```

Dla łańcucha z wygasłym certyfikatem werdykt mówi to wprost:

```
x 16 of 17 store(s) do not trust the presented chain, and 1 could not be assessed - a certificate in
  the path is past its validity.
```

`L4` wymienia każdy certyfikat, który pokazał serwer, z datami `valid ... to ...` i odciskiem palca, więc widać, który wygasł. Pierwsza linia raportu zawiera czas przebiegu według zegara tej maszyny: gdy daty wyglądają dobrze, a czas nie, winny jest zegar.

## Napraw to

Wygasły certyfikat serwera albo certyfikat pośredni naprawia się na serwerze: odnów go i wysyłaj aktualny łańcuch. Załącz raport, zrobiony z `--redact --format md`, do zgłoszenia dla tego, kto prowadzi serwer.

Zły zegar naprawia się na tej maszynie, synchronizując czas.

## Czego nie robić

Nie dodawaj wygasłego certyfikatu do magazynu zaufania i nie wyłączaj weryfikacji. Ani jedno, ani drugie nie sprawia, że wygasły certyfikat staje się ważny.
