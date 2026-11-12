---
title: Użycie w CI
slug: ci
seoTitle: certdoctor w CI - kody wyjścia i JSON dla pipeline'u
description: "Sprawdź, czy agent budujący dosięga rejestru albo API: kody wyjścia certdoctor, JSON sprawdzony ze schematem i raport zachowany jako artefakt."
lead: "Czy ten agent budujący dosięga rejestru? Jeden krok na to odpowiada, z kodem wyjścia, po którym pipeline może się rozgałęzić."
---

## Jeden krok

```yaml
- name: can the build agent reach the registry
  run: certdoctor https://registry.example.com/ --redact --json --out certdoctor.json
```

JSON jest sprawdzany ze schematem, zanim cokolwiek zostanie zapisane, więc pipeline nigdy nie czyta niedokończonego dokumentu. Zachowaj go jako artefakt, a gdy ktoś ma go przeczytać, zrób z niego stronę przez `--from`.

## Kody wyjścia

Każde zakończenie ma własny kod:

{{< exit-codes >}}

Samo `WARN` nie zatrzymuje budowania: maszyna za firmowym proxy inaczej kończyłaby każdy przebieg porażką, chociaż jej połączenie działa. `4` znaczy, że przebieg znalazł coś złego na drodze do adresu. `5` znaczy, że nie było niczego złego, co mógł zobaczyć, ale co najmniej jednej rzeczy nie dało się ocenić - pipeline, który chce pewności, traktuje to jako porażkę, a taki, który chce tylko prawdziwych porażek, przepuszcza.

## Raport dla ludzi, po fakcie

Późniejszy krok może zrobić stronę z zapisanego JSON-a bez ponownej diagnozy:

```
certdoctor --from certdoctor.json --format html --out certdoctor.html
```

Kończy się `0`, gdy strona jest zapisana, więc krok, który tylko robi stronę, nie zatrzymuje budowania drugi raz. Kod samego werdyktu zostaje w raporcie jako `verdict.exit_code`.

## Windows PowerShell 5.1

Zapisuj JSON przez `--out`, a nie przez `>`. W Windows PowerShell 5.1 `>` zapisuje UTF-16, a tego czytnik JSON-a się nie spodziewa.

## Każda wersja w dzienniku

```
certdoctor --version
```

wypisuje wersję narzędzia, schematu raportu, Go, którym je zbudowano, i platformę, po jednej w linii, więc dziennik sprzed miesięcy nadal mówi, co wytworzyło werdykt.
