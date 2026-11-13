---
title: Co sprawdza, warstwa po warstwie
linkTitle: Sześć warstw
slug: warstwy
seoTitle: Co sprawdza Cert Doctor - DNS, proxy, TCP, TLS, zaufanie
description: "Sześć warstw przebiegu Cert Doctor: zmienne środowiskowe, DNS z każdego serwera, proxy i PAC, TCP do każdego adresu, łańcuch TLS i macierz zaufania."
lead: "Połączenie może paść w sześciu miejscach. Przebieg patrzy na każde z nich, w kolejności, w jakiej spotyka je połączenie."
---

{{< layers >}}

## L0 Kontekst

Sama maszyna: jaki system, czy działa w kontenerze i które zmienne środowiskowe decydujące o zaufaniu i o proxy są ustawione. Zmienna ustawiona w jednej pisowni, a w drugiej nie - `HTTPS_PROXY` bez `https_proxy` - jest warta uwagi, bo programy nie zgadzają się co do tego, która się liczy. L0 czyta te zmienne, w tej kolejności:

{{< variables >}}

Są czytane jako rzecz do zdiagnozowania. Żadna nie zmienia tego, co robi sam Cert Doctor: jedyna zmienna, której słucha, to `NO_COLOR`, a ona zmienia tylko wygląd raportu.

W raporcie każda ustawiona zmienna ma własny wiersz ze swoją wartością. Nieustawione idą po nich, wypisane razem za jedną etykietą `not set`. Raport `--json` zachowuje osobny wpis dla każdej zmiennej.

## L1 Rozwiązywanie nazw

Nazwa jest sprawdzana dwa razy: każdy skonfigurowany serwer DNS jest pytany wprost, a resolver systemu tak, jak pytają go programy na tej maszynie. Gdy oba widoki się różnią, różnica jest klasyfikowana - podzielony DNS, gdzie serwer wewnętrzny i publiczny odpowiadają inaczej, odpowiedź, która wycieka obok VPN-a, albo nazwa, która nigdzie się nie rozwiązuje. Nazwa, która się nie rozwiązuje, jest przyczyną, cokolwiek dzieje się dalej.

## L2 Proxy

Przez które proxy naprawdę idzie ten adres i kto o tym zdecydował: zmienne środowiskowe, ustawienia internetowe Windows, którymi kierują się Edge, Chrome i .NET, ustawienia WinHTTP, którymi kierują się usługi Windows, i skrypt PAC wskazany przez maszynę. Skrypt PAC jest uruchamiany w piaskownicy, żeby zobaczyć, dokąd kieruje ten adres, a proxy jest pytane, czy chce poświadczeń. Szczegóły w opisie [proxy i PAC](/docs/proxy-and-pac/).

## L3 TCP

Połączenie z każdym adresem, na który rozwiązała się nazwa, równolegle i w raporcie w kolejności adresów. Odrzucone połączenie, nieosiągalna sieć i przekroczony czas są rozróżniane dla każdego adresu, bo wskazują różnych winnych.

## L4 TLS

Uzgodnienie TLS z każdym adresem, który przyjął połączenie, i pełny łańcuch certyfikatów, który pokazał każdy z nich, z odciskami palców i datami ważności. Uzgodnienie jest kończone bez weryfikacji łańcucha, celowo: łańcuch, który nie przechodzi weryfikacji, inaczej nie zostawiłby niczego do obejrzenia, a tu łańcuch jest dowodem.

L4 sprawdza też, czy certyfikat obejmuje nazwę z adresu, czy łańcuch jest kompletny - serwer, który nie wysyła certyfikatu pośredniego, jest wskazany tutaj - i czy każdy adres pokazał ten sam łańcuch. Adres zaczynający się od `http://` nie ma uzgodnienia do wykonania i raport to mówi.

## L5 Macierz zaufania

Łańcuch z L4 przedstawiony każdemu magazynowi zaufania na maszynie: czy ten magazyn mu ufa? Jeden wiersz na magazyn, a każdy wiersz z odmową niesie polecenie, które by go naprawiło. [Macierz zaufania](/docs/trust-matrix/) mówi, które magazyny są pytane.

## Która warstwa przesądza

Zdanie na górze raportu pochodzi z warstwy, która przesądziła o wyniku, a to nie zawsze pierwsza czerwona. Nazwa, która nigdzie się nie rozwiązuje, jest przyczyną, chociaż każda dalsza warstwa też pada. Certyfikat, który nie obejmuje nazwy, jest przyczyną, nawet gdy część magazynów ufa jego urzędowi. Serwer, który nie wysyła certyfikatu pośredniego, jest wskazany jako winny, chociaż każdy magazyn odrzuca wtedy łańcuch.
