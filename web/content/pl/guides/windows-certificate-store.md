---
title: Magazyn certyfikatów Windows
slug: magazyn-certyfikatow-windows
seoTitle: Dodaj certyfikat główny do magazynu Windows przez certutil
description: "Dodaj certyfikat główny do magazynu certyfikatów Windows przez certutil: CurrentUser czy LocalMachine, kto czyta każdy z nich i które programy ignorują oba."
lead: "Magazyn twojego konta i magazyn maszyny to dwie różne listy. Usługi czytają jedną, twoje programy obie, a Java i Git żadnej."
---

## Dwa magazyny

Windows trzyma zaufane certyfikaty główne w dwóch miejscach, które mają tu znaczenie:

- **`CurrentUser`** - własny magazyn twojego konta. Czytają go programy, które uruchamiasz, razem z magazynem maszyny. Usługi działające na innych kontach go nie czytają.
- **`LocalMachine`** - magazyn maszyny. Czyta go każde konto i każda usługa, a jego zmiana wymaga uprawnień administratora.

Firmowy certyfikat główny wdrażany przez dział IT zwykle trafia do `LocalMachine`. Certyfikat główny dodany samodzielnie bez uprawnień administratora trafia do `CurrentUser`.

## Kto je czyta

Edge, Chrome, programy .NET, PowerShell, programy w Go, `curl.exe` dostarczany z Windowsem i moduł `ssl` Pythona ufają temu, czemu ufają te magazyny. Java, własny pakiet Git for Windows i Node.js nie: mają własne listy i potrzebują [własnych poleceń](/guides/).

## Zobacz, co mówi każdy magazyn

```
certdoctor https://adres-ktory-nie-dziala/
```

Macierz zaufania ma wiersz `system-store` dla każdego z dwóch magazynów, pytanych z wyłączonym każdym pobieraniem z sieci, więc Windows nie pobiera niczego spod adresów wpisanych w certyfikat serwera. Publiczny certyfikat główny, którego Windows po prostu jeszcze nie pobrał, jest odróżniany od urzędu, którego nikt nie zainstalował, na podstawie kopii listy programu certyfikatów głównych Microsoftu, którą ma ta maszyna.

## Dodaj certyfikat główny

Wiersze niosą polecenie dla swojego magazynu ([dokumentacja certutil](https://learn.microsoft.com/windows-server/administration/windows-commands/certutil)):

```
certutil -user -addstore Root "<certificate.pem>"
certutil -addstore Root "<certificate.pem>"
```

- Pierwsze dodaje do magazynu twojego konta. Windows prosi w oknie dialogowym o potwierdzenie, zanim doda tam certyfikat główny.
- Drugie dodaje do magazynu maszyny, wymaga terminala uruchomionego jako administrator i dociera też do usług.

`-addstore` dodaje jeden certyfikat i zostawia resztę magazynu bez zmian. Podstaw za `<certificate.pem>` pełną ścieżkę do certyfikatu głównego.

## Gdy to zły magazyn

Certyfikat główny w którymkolwiek z tych magazynów nic nie daje Javie, Git for Windows ani Node.js. Mówi o tym uwaga pod wierszem `LocalMachine`, a ich własne wiersze niosą własne polecenia.
