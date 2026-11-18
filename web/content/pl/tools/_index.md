---
title: Narzędzia
linkTitle: Wszystkie narzędzia
slug: narzedzia
seoTitle: "Narzędzia offline: dekoder JWT, certyfikatów, CSR i NO_PROXY"
description: "Zdekoduj JWT, łańcuch certyfikatów albo CSR i sprawdź listę NO_PROXY na swoim komputerze. Nic nie jest wysyłane i nic się nie łączy. Wiersz poleceń i okno."
lead: "Małe narzędzia do tego, co otacza połączenie. Każde czyta tylko to, co mu dasz, z niczym się nie łączy i niczego nie zmienia."
cards:
  - /tools/jwt-decoder
  - /tools/certificate-decoder
  - /tools/csr-decoder
  - /tools/no-proxy
  - /tools/ksef-certificate-fingerprint
---

Tokena, certyfikatu czy żądania podpisania certyfikatu często lepiej nie wklejać na stronę internetową. Te narzędzia są częścią Cert Doctora, w tym samym [pobraniu](/download/), i czytają to, co im dasz, na twoim komputerze: z terminala, z pliku albo z potoku.

W terminalu `certdoctor tool` wypisuje ich listę, a `certdoctor tool <nazwa> --help` mówi, co każde z nich przyjmuje. W oknie są pod przyciskiem **Tools** na pasku.

Każde narzędzie kończy się kodem wyjścia `0`, gdy udało się odczytać wejście, cokolwiek w nim znalazło, a z `--json` zapisuje dokument JSON, więc skrypt może je uruchomić i przeczytać jego sprawdzenia.
