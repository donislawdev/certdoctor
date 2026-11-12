---
title: Kody wyjścia
slug: kody-wyjscia
seoTitle: Kody wyjścia certdoctor - co znaczy każde zakończenie
description: "Kody wyjścia certdoctor: 0 w porządku, 4 znaleziono usterkę, 5 czegoś nie dało się ocenić, oraz kody dla składni, konfiguracji, zapisu i przerwania."
lead: "Każdy sposób zakończenia przebiegu ma własny kod, a zbiór jest kompletny: pipeline może się po nim rozgałęzić."
---

{{< exit-codes >}}

## Które mówią coś o twojej maszynie

`4` i `5` dotyczą maszyny i badanego adresu. `4` znaczy, że przebieg się udał i znalazł co najmniej jedno `FAIL` - coś na drodze do adresu jest nie tak. `5` znaczy, że nie znalazł usterki, ale co najmniej jednej rzeczy nie dało się ocenić, a raport mówi której i dlaczego. Żaden z nich nie znaczy, że zawiódł sam certdoctor: to jest `1`.

## Ostrzeżenia

Samo `WARN` kończy się `0`. Maszyna za firmowym proxy inaczej kończyłaby każdy przebieg porażką, chociaż jej połączenie działa bez zarzutu. Ostrzeżenia zostają w raporcie i w JSON-ie, dla pipeline'u, który chce zdecydować sam.

## Strona z zapisanego raportu

`certdoctor --from report.json --format html --out report.html` kończy się `0`, gdy strona jest zapisana, cokolwiek znalazł raport. Własny kod przebiegu zostaje w raporcie jako `verdict.exit_code`.
