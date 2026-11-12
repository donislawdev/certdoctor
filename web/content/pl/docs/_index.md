---
title: Dokumentacja
slug: dokumentacja
seoTitle: Dokumentacja certdoctor - warstwy, macierz zaufania, CLI
description: "Jak certdoctor ustala, dlaczego adres nie działa na tej maszynie: sześć warstw, macierz zaufania, raporty, CI, kontenery, okno i każda flaga."
lead: "Wszystko, co robią wiersz poleceń i okno, i jak czytać to, co mówią."
cards:
  - /docs/getting-started
  - /docs/read-the-report
  - /docs/layers
  - /docs/trust-matrix
  - /docs/proxy-and-pac
  - /docs/reports
  - /docs/ci
  - /docs/containers
  - /docs/window
  - /docs/cli
  - /docs/exit-codes
  - /docs/verify-a-download
---

certdoctor to dwa programy nad jedną diagnozą. `certdoctor` to wiersz poleceń: podajesz mu adres, który nie działa, a on wypisuje raport w terminalu albo zapisuje go do zgłoszenia lub dla pipeline'u. `certdoctor-gui` to okno, które uruchamia ten sam wiersz poleceń i pokazuje ten sam raport, dla każdego, kto woli wpisać adres w pole.

Przebieg idzie drogą, którą idzie połączenie - środowisko, rozwiązywanie nazw, proxy, TCP, TLS - a potem pyta każdy magazyn zaufania, jaki znajdzie na maszynie, czy ufa łańcuchowi, który pokazał serwer. Raport zaczyna się od jednego zdania, które nazywa przyczynę, a każdy magazyn z odmową niesie polecenie, które by go naprawiło.

Jeśli przychodzisz z komunikatem błędu, [strony błędów](/errors/) zaczynają od komunikatu. Jeśli wiesz, który program odmawia, [poradniki](/guides/) zaczynają od programu.
