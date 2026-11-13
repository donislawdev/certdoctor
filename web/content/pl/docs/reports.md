---
title: Raporty i formaty
slug: raporty
seoTitle: Raporty Cert Doctor - Markdown, HTML, JSON i maskowanie
description: "Zapisz raport Cert Doctor jako Markdown do zgłoszenia, samodzielną stronę HTML albo JSON, zamaskuj nazwy hostów przez --redact i zrób stronę z JSON-a."
lead: "Jeden przebieg, cztery sposoby na zachowanie tego, co znalazł, i maska na to, co nie powinno wyjść poza firmę."
---

## Cztery formaty

| Format | Flaga | Co to jest |
|---|---|---|
| terminal | domyślny | raport tak, jak go czytasz, na 100 kolumn, w kolorze, gdy wyjściem jest terminal |
| Markdown | `--format md` | ten sam raport do zgłoszenia albo na czat |
| HTML | `--format html` | jedna samodzielna strona, bez żadnego skryptu i bez pobierania czegokolwiek |
| JSON | `--format json` albo `--json` | raport jako dane, sprawdzony ze schematem, zanim zostanie wypisany |

Każdy format niesie te same ustalenia. Raport w jednym formacie nie pomija niczego, co ma inny.

## Zapis do pliku

`--out` zapisuje raport pod podaną ścieżką, zamiast go wypisywać:

```
certdoctor https://api.example.com/ --format html --out report.html
```

To jedyny plik, jaki Cert Doctor kiedykolwiek zapisuje. Jeśli nie da się go zapisać - brak miejsca, brak uprawnień - przebieg kończy się kodem wyjścia `6` i mówi dlaczego.

## Maskowanie wewnętrznych nazw

Raport zawiera wewnętrzne nazwy hostów, ścieżki w systemie plików i nazwy użytkowników, bo to czyni go przydatnym w zgłoszeniu. `--redact` je maskuje:

```
certdoctor https://api.example.com/ --redact --format md --out report.md
```

Z poświadczeniami jest inaczej. Hasła do proxy, nagłówki autoryzacji i ciasteczka są maskowane zawsze, z `--redact` i bez, bo maska zależna od flagi jest o jedną zapomnianą flagę od wycieku.

> Przeczytaj raport, zanim wkleisz go w publiczne miejsce. Maskowanie to filtr, a nie gwarancja.

## Strona z zapisanego raportu

`--from` bierze raport zapisany wcześniej z `--json` i zapisuje go jeszcze raz w innym formacie, niczego nie uruchamiając:

```
certdoctor https://api.example.com/ --json --out report.json
certdoctor --from report.json --format html --out report.html
```

Pojedynczy myślnik czyta JSON ze standardowego wejścia. `--from` kończy się kodem wyjścia `0`, gdy strona jest zapisana, cokolwiek znalazł raport, a własny werdykt przebiegu zostaje w raporcie.

## Schemat JSON

`certdoctor --version` wypisuje wersję narzędzia i schematu raportu, który wytwarza, więc plik JSON sprzed pół roku nadal mówi, co go wytworzyło:

```
certdoctor --version
```
