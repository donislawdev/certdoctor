---
title: Opis wiersza poleceń
linkTitle: Wiersz poleceń
slug: wiersz-polecen
seoTitle: Wiersz poleceń certdoctor - każda flaga
description: "Każda flaga wiersza poleceń certdoctor: adres, --pac-url, --from, --format, --json, --out, --redact, --quiet, --verbose, limity czasu i pozostałe."
lead: "Każda flaga wiersza poleceń, w grupach i kolejności, w jakiej wypisuje je `certdoctor --help`. Program pisze swoje opisy po angielsku, a tu są przetłumaczone."
---

## Użycie

```
certdoctor <url> [options]
certdoctor --from <file> [options]
```

Adres wymaga jawnego schematu `http://` albo `https://`. Bez niego nie da się odróżnić nazwy hosta od numeru portu. `--from` zajmuje miejsce adresu: niczego nie uruchamia, zapisuje zachowany raport w żądanym formacie i kończy się `0`, gdy jest zapisany.

{{< switches >}}

## Środowisko

`NO_COLOR` ustawiona na dowolną niepustą wartość wyłącza kolory. To jedyna zmienna, która zmienia działanie certdoctor, i zmienia tylko wygląd raportu. Zmienne proxy i magazynów zaufania są czytane jako rzecz do zdiagnozowania, nigdy jako konfiguracja certdoctor.

## Kody wyjścia

Każde zakończenie ma własny kod. Wymienia je strona [kody wyjścia](/docs/exit-codes/).
