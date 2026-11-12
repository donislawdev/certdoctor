---
title: Czytanie raportu
slug: czytanie-raportu
seoTitle: Jak czytać raport certdoctor - werdykt, warstwy, statusy
description: "Co znaczy każda część raportu certdoctor: zdanie z werdyktem, kod wyjścia, sześć warstw, wiersze macierzy zaufania i polecenia, które niosą."
lead: "Najpierw przyczyna, za nią liczby, niżej dowody, a na końcu uwagi."
---

## Pierwsze linie

```
certdoctor 0.1.0   https://untrusted-root.badssl.com/
2026-11-12T08:15:13Z   windows/amd64   privilege: elevated   took 20.46s
```

Wersja narzędzia i adres, potem kiedy wykonano przebieg, na jakim systemie, z jakimi uprawnieniami i jak długo trwał. Uprawnienia mają znaczenie, bo niektóre magazyny wyglądają inaczej dla administratora, a inaczej dla zwykłego konta.

## Werdykt

```
x CN=BadSSL Untrusted Root Certificate Authority,O=BadSSL,L=San Francisco,ST=California,C=US signed
  this certificate, and none of the 10 store(s) assessed here holds an anchor for it. 1 of 6
  diagnostic layers could not be assessed.
exit 4 DIAGNOSIS
```

Jedno zdanie, które nazywa przyczynę słowami warstwy, która o niej przesądziła. To nie zawsze pierwsza czerwona warstwa: nazwa, która się nie rozwiązuje, jest przyczyną, nawet gdy każda dalsza warstwa też pada, a serwer, który nie wysłał certyfikatu pośredniego, jest wskazany jako winny, chociaż każdy magazyn odrzuca łańcuch. Liczby są po zdaniu, a za nimi [kod wyjścia](/docs/exit-codes/) i jego nazwa.

Raport jest po angielsku, bo tak go wypisuje program, a ta strona tłumaczy, co znaczy każda część.

## Warstwy

Pod werdyktem każda warstwa ma jedną linię ze statusem i podsumowaniem, a pod nią dowody:

```
  + PASS     L0  Context          read 25 environment variables that decide trust and proxying
  + PASS     L3  TCP              1 of 1 address(es) accepted a connection
  x FAIL     L5  Trust matrix     15 of 17 store(s) do not trust the presented chain, and 2 could
                                  not be assessed
```

[Warstwy](/docs/layers/) mówią, co sprawdza każda z nich. Status jest jednym z czterech:

{{< statuses >}}

`UNKNOWN` zawsze ma podany powód. Magazyn, którego nie dało się odczytać, sonda, która nie zrozumiała tego, co zobaczyła, i warstwa, której skończył się czas, mówią o tym wprost i żadna z nich nie liczy się jako zaliczenie.

## Wiersz macierzy zaufania

```
      java C:\Program Files\OpenJDK\jdk-21.0.2 does NOT trust the presented chain (106
        anchors)  detected
        needs elevated rights: this store is outside this account's own files, so it belongs to
                               every account on the machine
        run: "C:\Program Files\OpenJDK\jdk-21.0.2\bin\keytool" -importcert -trustcacerts -keystore "C:\Program Files\OpenJDK\jdk-21.0.2\lib\security\cacerts" -storepass changeit -alias "<alias>" -file "<certificate.pem>"
        replace first: <alias>, <certificate.pem>
```

Każdy wiersz to jeden magazyn: który program, która instalacja, czy ufa łańcuchowi i ile certyfikatów zaufanych zawiera. Wiersz z odmową może mieć:

- `run:` - polecenie, które dodaje certyfikat do tego magazynu, ze ścieżkami z tej maszyny,
- `replace first:` - co podstawić przed uruchomieniem, na przykład plik, do którego zapisano certyfikat,
- `needs elevated rights:` - dlaczego polecenie wymaga uprawnień administratora albo roota, gdy ich wymaga,
- `note:` - co jeszcze warto wiedzieć, na przykład które inne programy czytają ten sam magazyn.

[Macierz zaufania](/docs/trust-matrix/) mówi, które magazyny są pytane i jakie polecenie dostaje każdy z nich.

## Szerokość i łamanie linii

Raport ma 100 kolumn szerokości. Zdania łamią się na spacjach. Polecenie, odcisk palca, nazwa certyfikatu i wartość odczytana z maszyny nigdy nie są łamane, bo polecenie złamane na dwie linie wkleiłoby się jako dwa. Linia, która wychodzi poza krawędź, jest przeznaczona do skopiowania w całości.

## Uwagi

Raport kończy się uwagami o tym, czego w tym przebiegu nie sprawdzano i dlaczego, więc brakujący wiersz nigdy nie wygląda jak magazyn, który się zgodził.
