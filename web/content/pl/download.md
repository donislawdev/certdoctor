---
title: Pobierz Cert Doctor
linkTitle: Pobierz
slug: pobierz
seoTitle: Pobierz Cert Doctor na Windows, Linux i macOS
description: "Pobierz Cert Doctor na Windows, Linux i macOS: wiersz poleceń jako jeden plik, okno i instalator na Windows."
lead: "Weź archiwum dla swojego systemu ze [strony wydań](https://github.com/donislawdev/certdoctor/releases/latest) i rozpakuj je - programy działają tam, gdzie je rozpakujesz. Na Windowsie na x64 możesz go zamiast tego zainstalować."
---

## Wiersz poleceń

{{< downloads "certdoctor" >}}

Na Linuksie wiersz poleceń nie potrzebuje biblioteki C, więc ten sam plik działa w Alpine, w Ubuntu i w obrazie, w którym nie ma nic innego. `certdoctor --license` wypisuje licencję i noty kodu innych autorów, który jest w nim zawarty.

## Okno

`certdoctor-gui` ma własne archiwa, na trzy systemy. Każde zawiera też wiersz poleceń, bo okno go uruchamia:

{{< downloads "certdoctor-gui" >}}

Trzymaj pliki z archiwum okna razem. Dlaczego, mówi opis [okna](/docs/window/).

Każde archiwum zawiera też `LICENSE`, `THIRD-PARTY-NOTICES.md` i README, a archiwa okna także `THIRD-PARTY-NOTICES-GUI.md`.

## Instalator na Windows

{{< downloads "certdoctor-setup" >}}

Instaluje okno i wiersz poleceń w `C:\Program Files\Cert Doctor` dla każdego konta na komputerze, dopisuje ten folder do systemowej zmiennej `PATH` i dodaje Cert Doctor do menu Start. Instalacja prosi o uprawnienia administratora, a uruchamianie Cert Doctor ich nie wymaga. Instalator jest podpisany i instaluje pliki z archiwum okna dla Windows. Żeby wpisać `certdoctor`, otwórz potem nowy terminal, bo ten, który był już otwarty, nie widzi nowego `PATH`.

Nowsza wersja instaluje się na starszą i niczego nie zamyka. Jeśli Cert Doctor właśnie działa, Windows poprosi o jego zamknięcie albo o późniejszy restart, a następne uruchomienie to już nowa wersja. Żeby go usunąć, odinstaluj Cert Doctor w Ustawieniach, w sekcji Aplikacje. Plik, który sam dodasz do jego folderu, zostaje, tak jak ustawienia okna.

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
