---
title: Macierz zaufania
slug: macierz-zaufania
seoTitle: Macierz zaufania - które magazyny na tej maszynie odmawiają
description: "Cert Doctor pyta każdy magazyn zaufania na maszynie - Windows, pakiet Linuksa, każdy JDK, git, curl, node, Python i pip - i wypisuje naprawę dla każdego."
lead: "Przeglądarka działa, curl działa, aplikacja nie. To kilka magazynów zaufania, które się nie zgadzają, a macierz zaufania pokazuje które."
---

## Dlaczego odpowiedzi jest więcej niż jedna

Każde środowisko ma własne zdanie o tym, komu ufać. Java trzyma plik `cacerts` w każdej instalacji, a maszyna programisty często ma kilka JDK, z których ktoś naprawił jeden. Git for Windows ma własny pakiet certyfikatów. Node.js jest zbudowany z własną listą. Python i pip czytają listę, z którą je skonfigurowano. Certyfikat, który firma dodała do magazynu Windows, trafia do części z nich, a do reszty nie, i dlatego jeden program się łączy, a następny nie.

Macierz zaufania zadaje każdemu z nich to samo pytanie o ten sam łańcuch: czy ten magazyn ufa temu, co pokazał serwer?

## Magazyny, które pyta

Jeden wiersz na magazyn, a nie na środowisko:

| Wiersz | Który magazyn |
|---|---|
| `system-store` na Windowsie | magazyn certyfikatów Windows, dwa razy: tak, jak widzi go twoje konto (`CurrentUser`), i tak, jak widzą go usługi (`LocalMachine`) |
| `system-store` na Linuksie | pakiet certyfikatów CA dystrybucji |
| `java` | `cacerts` każdego JDK i JRE, jakie znajdzie, każdy jako osobny wiersz |
| `git` | każdy `git`, jaki znajdzie, i pakiet, który czyta każdy z nich |
| `curl` | każdy `curl`, jaki znajdzie, i magazyn, który czyta każdy z nich |
| `node` | każdy `node` w PATH, według listy, której ufa ta binarka |
| `python` | każdy Python w PATH, według listy, której ufa jego moduł `ssl` |
| `pip` | `pip` każdego Pythona, według jego własnej reguły |

Raport wymienia rodziny, o które pytał, więc brakujący wiersz zawsze znaczy, że nikt nie patrzył, a nigdy, że magazyn się zgodził. Na maszynie, na której powstał Cert Doctor, jeden przebieg w listopadzie 2026 przeczytał siedemnaście magazynów, w tym osiem środowisk Javy.

## Polecenie dla każdego magazynu

Magazyn, który odmawia, bo nie zna urzędu certyfikacji, dostaje polecenie, które dodaje do niego certyfikat. Polecenia tylko dodają: żadne nie usuwa ani nie zastępuje tego, co magazyn już ma.

| Magazyn | Polecenie, w postaci, w jakiej wypisuje je wiersz |
|---|---|
| Windows, `LocalMachine` | `certutil -addstore Root "<certificate.pem>"`, wymaga uprawnień administratora |
| Windows, `CurrentUser` | `certutil -user -addstore Root "<certificate.pem>"`, po którym Windows prosi o potwierdzenie |
| JDK albo JRE | `keytool -importcert` tej samej instalacji do jej własnego `cacerts`, z prawdziwymi ścieżkami |
| git, curl, pakiet Linuksa, plik CA czytany przez Pythona albo pipa | dopisanie certyfikatu na koniec dokładnie tego pliku: `cat` na Linuksie i macOS, `cmd /c copy /b` na Windowsie |
| node | `NODE_USE_SYSTEM_CA=1`, gdy własna lista systemu domknęłaby łańcuch, w przeciwnym razie dopisanie do pliku wskazanego przez `NODE_EXTRA_CA_CERTS` albo ustawienie tej zmiennej |
| Python na Windowsie | magazyn Windows tego konta, bo stamtąd pochodzi jego lista |

Wiersz mówi, kiedy jego polecenie wymaga uprawnień administratora albo roota, i dlaczego. Mówi też, na co uważać: menedżer pakietów albo aktualizacja środowiska może przepisać pakiet i zgubić dopisany certyfikat, a nowszy JDK przynosi własny `cacerts`.

Cert Doctor wypisuje te polecenia. Nigdy ich nie uruchamia. Każde ma miejsca do podstawienia, wymienione w linii `replace first:` wiersza.

## Gdy wiersz wskazuje inny

Program, który ocenia według innego magazynu, mówi to, zamiast go powtarzać. curl zbudowany na Schannel, bibliotece TLS Windows, ufa temu, czemu ufa magazyn Windows tego konta, więc jego wiersz wskazuje wiersz tego magazynu i jego polecenie. Na Linuksie `curl` albo `git` z pakietów dystrybucji, który czyta pakiet certyfikatów dystrybucji, wskazuje wiersz tego pakietu.

## Jak pytany jest magazyn Windows

Magazyn Windows jest pytany z wyłączonym każdym pobieraniem z sieci. Windows pobrałby inaczej brakujący certyfikat spod adresu wpisanego w certyfikat przez serwer, który właśnie diagnozujesz, a Cert Doctor łączy się tylko tam, gdzie go skierujesz. Publiczny certyfikat główny, którego Windows po prostu jeszcze nie pobrał, jest odróżniany od urzędu, którego nikt nie zainstalował, na podstawie kopii listy programu certyfikatów głównych Microsoftu, którą ma ta maszyna.

## Kto podpisał certyfikat

Nad wierszami macierz mówi, kto podpisał certyfikat serwera i ile magazynów na tej maszynie ma ten urząd. Gdy podpisujący jest urzędem, który część magazynów ma, a część nie, to zwykle firmowy certyfikat główny albo produkt do inspekcji TLS, który trafił tylko do części maszyny. [Inspekcja TLS](/guides/tls-inspection-corporate-proxy/) mówi, jak to czytać.
