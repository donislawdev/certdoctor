---
title: Pakiet CA Linuksa
slug: linux-pakiet-ca
seoTitle: Dodaj certyfikat CA w Linuksie - systemowy pakiet CA
description: "Dodaj certyfikat główny do pakietu CA Linuksa w Debianie, Ubuntu, Alpine i RHEL: który plik czytają programy, update-ca-certificates i co przetrwa przebudowę."
lead: "Większość programów na Linuksie czyta jeden plik, który utrzymuje dystrybucja. Dopisanie do niego jest szybkie, a przebudowa pliku gubi to, co dopisano ręcznie."
---

## Który plik czytają programy

Dystrybucja Linuksa trzyma zaufane certyfikaty główne w jednym pliku - `/etc/ssl/certs/ca-certificates.crt` w Debianie, Ubuntu i Alpine, `/etc/pki/tls/certs/ca-bundle.crt` w Red Hacie i jego rodzinie. Czytają go zwykle programy w Go, curl i git z pakietów dystrybucji oraz moduł `ssl` Pythona.

## Zobacz, co mówi pakiet

```
certdoctor https://adres-ktory-nie-dziala/
```

Wiersz `system-store` nazywa pakiet, który przeczytał - pierwszy istniejący, w kolejności, w jakiej szuka ich Go - i mówi, czy ufa łańcuchowi. `curl` albo `git` z pakietów dystrybucji, który czyta ten sam plik, wskazuje ten wiersz, zamiast go powtarzać. W kontenerze [uruchom go w kontenerze](/docs/containers/): obraz ma własny pakiet.

## Dodaj certyfikat główny, szybko

Polecenie z wiersza dopisuje certyfikat główny do pakietu:

```
cat "<certificate.pem>" >> /etc/ssl/certs/ca-certificates.crt
```

Niczego nie dodaje poza nim i niczego nie usuwa, i działa od razu. Wymaga uprawnień roota, a wiersz to mówi.

## Dodaj certyfikat główny, na stałe

Własne narzędzie dystrybucji przebudowuje pakiet z folderu certyfikatów, a przebudowa gubi wszystko, co dopisano ręcznie - mówi o tym też uwaga wiersza. Żeby certyfikat główny przetrwał następną aktualizację, umieść jego kopię tam, skąd zbiera narzędzie, i przebuduj:

- Debian, Ubuntu, Alpine: plik o nazwie `*.crt` w `/usr/local/share/ca-certificates`, potem `update-ca-certificates` ([strona podręcznika](https://manpages.debian.org/stable/ca-certificates/update-ca-certificates.8.en.html))
- Red Hat, Fedora, Rocky, Alma: plik w `/etc/pki/ca-trust/source/anchors`, potem `update-ca-trust`

Narzędzie Debiana ignoruje plik, którego nazwa nie kończy się na `.crt`.

## Programy z własną listą

Java i Node.js nie czytają tego pliku, a Python albo pip skierowany na inny plik też nie. Ich wiersze w macierzy zaufania niosą własne polecenia.
