---
title: Pobierz Cert Doctor
linkTitle: Pobierz
slug: pobierz
seoTitle: Pobierz Cert Doctor na Windows, Linux i macOS
description: "Pobierz Cert Doctor na Windows, Linux i macOS: wiersz poleceń jako jeden plik bez instalacji i okno na Windows, Linux i macOS."
lead: "Weź archiwum dla swojego systemu ze [strony wydań](https://github.com/donislawdev/certdoctor/releases/latest) i rozpakuj je. Nic się nie instaluje."
---

## Wiersz poleceń

{{< downloads "certdoctor" >}}

Na Linuksie wiersz poleceń nie potrzebuje biblioteki C, więc ten sam plik działa w Alpine, w Ubuntu i w obrazie, w którym nie ma nic innego. `certdoctor --license` wypisuje licencję i noty kodu innych autorów, który jest w nim zawarty.

## Okno

`certdoctor-gui` ma własne archiwa, na trzy systemy. Każde zawiera też wiersz poleceń, bo okno go uruchamia:

{{< downloads "certdoctor-gui" >}}

Trzymaj pliki z archiwum okna razem. Dlaczego, mówi opis [okna](/docs/window/).

Każde archiwum zawiera też `LICENSE`, `THIRD-PARTY-NOTICES.md` i README, a archiwa okna także `THIRD-PARTY-NOTICES-GUI.md`.

## Sprawdź pobrany plik

Każde wydanie podaje SHA-256 każdego pliku w `verify-SHA256SUMS.txt`, a GitHub podpisuje oświadczenie o tym, co weszło do każdego z nich. Polecenia pokazuje strona [sprawdź pobrany plik](/docs/verify-a-download/).

## Ze źródeł

Z Go {{< go-version >}} albo nowszym:

```
git clone https://github.com/donislawdev/certdoctor
cd certdoctor
CGO_ENABLED=0 go build ./cmd/certdoctor
```

W PowerShellu najpierw ustaw zmienną w osobnej linii: `$env:CGO_ENABLED = "0"`, a potem `go build ./cmd/certdoctor`. `CGO_ENABLED=0` daje tę samą statyczną binarkę, którą niosą wydania, tę, która działa bez zmian w obrazie Alpine.

## Dalej

[Pierwsze kroki](/docs/getting-started/) prowadzą od pobrania do pierwszego raportu.
