---
title: unable to get local issuer certificate
codeTitle: true
seoTitle: "unable to get local issuer certificate: naprawa"
description: "SSL certificate problem: unable to get local issuer certificate w curl, git, Pythonie, pip i Node: co to znaczy i jak naprawić właściwy magazyn zaufania."
lead: "Program nie znalazł urzędu, któremu ufa i który poręczyłby za certyfikat serwera. Naprawa jest we własnej liście tego programu, a każdy program ma inną."
messages:
  - from: curl
    text: "curl: (60) SSL certificate problem: unable to get local issuer certificate"
  - from: git
    text: "fatal: unable to access 'https://...': SSL certificate problem: unable to get local issuer certificate"
  - from: Python, pip
    text: "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate"
  - from: Node.js
    text: "Error: unable to get local issuer certificate (UNABLE_TO_GET_ISSUER_CERT_LOCALLY)"
---

## Co to znaczy

Program dostał certyfikat serwera i szukał certyfikatu tego, kto go wystawił - najpierw wśród tego, co przysłał serwer, potem w swoim lokalnym magazynie zaufania. Nie znalazł ani tu, ani tu. „Lokalny” znaczy tu: własna lista urzędów tego programu, niekoniecznie ta, której używa przeglądarka.

Komunikat pochodzi z OpenSSL i bibliotek zbudowanych podobnie, dlatego wypisują go curl, git, Python, pip i Node.js.

## Częste przyczyny

- **Firmowego certyfikatu głównego brakuje na liście tego programu.** Proxy z inspekcją TLS albo własny urząd firmy podpisuje połączenie, a dział IT dodał jego certyfikat główny do magazynu systemu. curl na Windowsie może mu ufać, a Git for Windows, Python i Node.js czytają własne listy, których to nie obejmuje.
- **Serwer nie wysyła certyfikatu pośredniego.** Przeglądarka to ukrywa, bo pamięta certyfikat pośredni z innej strony. Każdy inny klient pada. Opisuje to strona [brak certyfikatu pośredniego](/errors/missing-intermediate-certificate/).
- **Nieaktualny albo podmieniony pakiet CA.** Program skierowany na inny plik, przez `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE` albo `GIT_SSL_CAINFO`, ufa temu plikowi i niczemu więcej.

## Ustal, która dotyczy ciebie

```
certdoctor https://adres-ktory-nie-dziala/
```

`L0` pokazuje, które z tych zmiennych są ustawione. `L4` pokazuje, czy serwer wysłał cały łańcuch. Macierz zaufania pokazuje każdy git, curl, Python, pip i node na maszynie, którą listę czyta każdy z nich, które odmawiają i polecenie, które dodaje certyfikat główny do każdego.

Jeśli werdykt mówi, że serwer nie wysłał wystawcy swojego certyfikatu, naprawa należy do serwera, a certdoctor mówi to wprost: *„this is a fact about the server rather than about this machine.”*

## Napraw to

Dodaj certyfikat główny do listy, którą czyta program, który pada, poleceniem z jego wiersza:

- git - [Git i certyfikaty SSL](/guides/git-ssl-certificate/)
- curl - [curl i jego pakiet CA](/guides/curl-ca-bundle/)
- Python i pip - [certyfikaty Pythona i pipa](/guides/python-pip-certificates/)
- Node.js i npm - [NODE_EXTRA_CA_CERTS](/guides/node-extra-ca-certs/)

Jeśli to certyfikat główny twojej firmy, strona [inspekcja TLS](/guides/tls-inspection-corporate-proxy/) mówi, jak zdobyć właściwy certyfikat.

## Czego nie robić

`git config http.sslVerify false`, `curl -k`, `verify=False` i `NODE_TLS_REJECT_UNAUTHORIZED=0` usuwają błąd, przyjmując każdy certyfikat od każdego. Ukrywają problem, zamiast go naprawić, i zostają ustawione długo po tym, jak wszyscy zapomną dlaczego.
