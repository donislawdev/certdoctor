---
title: Bezpieczeństwo i prywatność
slug: bezpieczenstwo
seoTitle: Bezpieczeństwo - czego Cert Doctor nigdy nie robi
description: "Cert Doctor nic nie zmienia na maszynie, nie uruchamia napraw, łączy się tylko tam, gdzie wskażesz, zawsze maskuje poświadczenia i nie wymaga administratora."
lead: "Narzędzie, które uruchamiasz tam, gdzie połączenia padają, widzi wewnętrzne nazwy, ścieżki i serwery proxy. Oto obietnice, których dotrzymuje."
---

## Niczego nie zmienia

Cert Doctor nigdy nie zapisuje do magazynu zaufania, nigdy nie edytuje pliku konfiguracyjnego i nigdy nie uruchamia poleceń, które wypisuje. Jedyny plik, jaki zapisuje, to raport, pod ścieżką podaną w `--out`. Narzędzie diagnostyczne, które po cichu zmienia magazyny zaufania, byłoby narzędziem, któremu nikt nie powinien dawać uprawnień administratora.

Okno zachowuje jedno własne ustawienie, folder, do którego ostatnio zapisano raport. Gdzie, mówi opis [okna](/docs/window/).

## Nie uruchamia napraw

Każde polecenie w raporcie jest do przeczytania, dopasowania i uruchomienia przez ciebie. Wiersz mówi, kiedy jego polecenie wymaga uprawnień administratora albo roota, i dlaczego, zanim je uruchomisz.

## Łączy się tylko tam, gdzie wskażesz

Przebieg łączy się z podanym adresem, adresami IP, na które się rozwiązuje, skonfigurowanymi serwerami DNS, twoimi proxy i skryptem PAC wskazanym przez maszynę. Z niczym więcej: bez telemetrii, bez sprawdzania aktualizacji, bez jakiegokolwiek raportowania. Na Windowsie magazyn zaufania jest pytany z wyłączonym każdym pobieraniem z sieci, więc nawet Windows nie pobiera niczego w imieniu Cert Doctor.

## Poświadczenia nigdy nie trafiają do raportu

Nazwy użytkowników i hasła w adresach proxy, nagłówki autoryzacji i ciasteczka są maskowane zawsze, z `--redact` i bez. `--redact` maskuje dodatkowo nazwy hostów, ścieżki w systemie plików i nazwy użytkowników, dla raportu, który wychodzi poza firmę.

## Nie wymaga uprawnień administratora

Działa jako ten, kto go uruchomił, a raport zapisuje, z jakimi uprawnieniami działał, bo od nich może zależeć, jak wygląda magazyn. O uprawnienia administratora prosi tylko instalator na Windows, bo instaluje program dla każdego konta na komputerze.

## Co uruchamia

Żeby dowiedzieć się, czemu ufają niektóre środowiska, Cert Doctor uruchamia ich własne programy i czyta odpowiedź: `node` i `python` z własnym, stałym skryptem oraz `curl --version`, żeby zobaczyć, jak zbudowano ten curl. Te programy startują bez zmiennych środowiskowych, które kazałyby im wczytać inny kod albo zapisywać pliki.

## Zgłaszanie podatności

Problem z bezpieczeństwem zgłoś prywatnie, tak jak mówi [SECURITY.md](https://github.com/donislawdev/certdoctor/blob/main/SECURITY.md) w repozytorium, a nie w publicznym zgłoszeniu. Wszystko inne trafia do [listy zgłoszeń](https://github.com/donislawdev/certdoctor/issues).
