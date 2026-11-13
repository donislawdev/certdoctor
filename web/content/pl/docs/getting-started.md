---
title: Pierwsze kroki
slug: pierwsze-kroki
seoTitle: Pierwsze kroki - pierwszy raport Cert Doctor
description: "Pobierz Cert Doctor, uruchom go na adresie, który nie działa, i przeczytaj zdanie, które nazywa przyczynę. Potem wypróbuj go na celowo zepsutej stronie."
lead: "Od pobrania do zdania, które nazywa przyczynę, w mniej więcej dwie minuty."
---

## Czego potrzebujesz

Komputera z Windowsem, Linuksem albo macOS na Apple silicon i adresu, który nie działa. Nic się nie instaluje: [pobierasz](/download/) archiwum z jednym programem, a na Linuksie ten program to jeden statyczny plik, który działa też w kontenerze. Uprawnienia administratora nie są potrzebne.

## Uruchom go na adresie

Otwórz terminal w folderze z rozpakowanym archiwum i uruchom Cert Doctor z adresem dokładnie takim, jakiego używa program, który nie działa, z `https://` albo `http://` na początku:

```
certdoctor https://api.example.com/
```

Schemat jest wymagany. Bez niego nie da się odróżnić nazwy hosta od numeru portu. Przebieg trwa kilka sekund, a dłużej, gdy serwer DNS albo proxy nie odpowiada - żaden przebieg nie trwa dłużej niż 60 sekund, chyba że dasz mu więcej przez `--timeout`.

## Przeczytaj pierwsze zdanie

Raport zaczyna się od jednego zdania, które nazywa przyczynę słowami warstwy, która o niej przesądziła. Pod nim jest kod wyjścia, potem każda warstwa z dowodami, a na końcu uwagi o tym, czego nie sprawdzano. Gdy magazyn zaufania odrzuca łańcuch serwera, jego wiersz ma linię `run:` z poleceniem, które dodałoby tam certyfikat. [Czytanie raportu](/docs/read-the-report/) omawia każdą część.

Cert Doctor wypisuje polecenia. Nigdy ich nie uruchamia. Przeczytaj polecenie, zanim je uruchomisz, i najpierw podstaw to, o co prosi, na przykład `<certificate.pem>`.

## Wypróbuj na zepsutej stronie

[badssl.com](https://badssl.com/) utrzymuje celowo zepsute strony HTTPS. Trzy z nich pokazują trzy różne przyczyny:

```
certdoctor https://untrusted-root.badssl.com/
certdoctor https://incomplete-chain.badssl.com/
certdoctor https://expired.badssl.com/
```

Pierwsza wskazuje urząd certyfikacji, którego nie ma żaden magazyn na twojej maszynie, druga wskazuje serwer, który nie wysyła certyfikatu pośredniego, a trzecia certyfikat po terminie ważności.

> Nie uruchamiaj poleceń naprawczych dla badssl.com. Jego certyfikat główny jest niezaufany celowo, a zaufanie mu sprawiłoby, że twoje magazyny przyjęłyby certyfikat, za którym nikt nie ręczy. Te polecenia są na dzień, w którym odrzucony certyfikat główny będzie certyfikatem twojej firmy.

## Zachowaj raport

Raport można zapisać do pliku: w Markdownie do zgłoszenia, jako jedną stronę HTML albo jako JSON:

```
certdoctor https://api.example.com/ --redact --format md --out report.md
```

`--redact` maskuje nazwy hostów, ścieżki i nazwy użytkowników. [Raporty](/docs/reports/) mówią, co zawiera każdy format.

## Albo użyj okna

`certdoctor-gui` pokazuje ten sam raport bez terminala: wpisz adres, naciśnij Diagnose, przeczytaj raport i zapisz go. Więcej w opisie [okna](/docs/window/).
