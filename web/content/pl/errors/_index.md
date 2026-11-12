---
title: Błędy certyfikatów i połączeń
linkTitle: Wszystkie błędy
slug: bledy
seoTitle: Błędy SSL i certyfikatów - wyjaśnienie i naprawa
description: "PKIX path building failed, unable to get local issuer certificate, SELF_SIGNED_CERT_IN_CHAIN, x509 unknown authority: co znaczy każdy komunikat i naprawa."
lead: "Ten sam brakujący certyfikat w każdym środowisku brzmi inaczej. Zacznij od komunikatu, który widzisz."
cards:
  - /errors/pkix-path-building-failed
  - /errors/unable-to-get-local-issuer-certificate
  - /errors/self-signed-certificate-in-certificate-chain
  - /errors/x509-certificate-signed-by-unknown-authority
  - /errors/certificate-has-expired
  - /errors/hostname-does-not-match-certificate
  - /errors/missing-intermediate-certificate
  - /errors/python-3-13-strict-certificate-checks
  - /errors/407-proxy-authentication-required
---

Większość tych komunikatów to ta sama skarga słowami różnych środowisk: program nie zbudował łańcucha od certyfikatu serwera do urzędu, któremu ufa. Przyczyn jest kilka, a naprawa zależy od tego, która dotyczy ciebie:

- **urzędu brakuje w magazynie zaufania tego programu** - najczęściej firmowego certyfikatu głównego albo produktu do inspekcji TLS, dodanego do systemu, a nigdy do Javy, Gita czy Pythona,
- **serwer nie wysyła certyfikatu pośredniego** - wina serwera, którą przeglądarka ukrywa, bo pamięta certyfikat pośredni z innej strony,
- **certyfikat nie pasuje do tego połączenia** - wygasł albo wystawiono go dla innej nazwy,
- **coś pośrodku odpowiada zamiast serwera** - proxy, które chce poświadczeń, albo takie, które podpisuje każde połączenie na nowo.

Każda strona niżej mówi, co znaczy komunikat, jakie ma przyczyny i co uruchomić. Uruchomienie `certdoctor` na tym adresie mówi, która przyczyna dotyczy ciebie, na maszynie, na której połączenie pada.

Komunikaty są po angielsku, bo tak je wypisują programy, i właśnie tak warto je wyszukiwać.
