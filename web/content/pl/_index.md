---
title: Cert Doctor
seoTitle: "Cert Doctor - dlaczego ta maszyna nie łączy się z adresem"
description: "Napraw PKIX path building failed, unable to get local issuer certificate i SELF_SIGNED_CERT_IN_CHAIN: jedno polecenie sprawdza każdy magazyn zaufania."
hero:
  eyebrow: Wiersz poleceń i okno
  title: Przeglądarka się łączy.
  turn: Twój program nie.
  lead: "**Cert Doctor** przechodzi całą drogę do adresu, który nie działa - DNS, proxy i skrypt PAC, TCP, TLS - a potem pyta każdy magazyn zaufania na tej maszynie, czy ufa temu, co przysłał serwer, i wypisuje polecenie, które naprawia każdy magazyn, który nie ufa."
  facts:
    - Darmowy i otwarty, GPL-3.0
    - Niczego nie zmienia, bez telemetrii
    - Windows, macOS i Linux
  panel_title: Jeden brakujący certyfikat, cztery komunikaty
  panel_rows:
    - text: PKIX path building failed
      from: Java
      page: /errors/pkix-path-building-failed
    - text: unable to get local issuer certificate
      from: curl, git, Python
      page: /errors/unable-to-get-local-issuer-certificate
    - text: SELF_SIGNED_CERT_IN_CHAIN
      from: Node.js
      page: /errors/self-signed-certificate-in-certificate-chain
    - text: "x509: certificate signed by unknown authority"
      from: Go
      page: /errors/x509-certificate-signed-by-unknown-authority
  panel_foot: zadaje każdemu z nich to samo pytanie i wskazuje te, które odmawiają
run:
  eyebrow: Prawdziwy przebieg
  title: Najpierw przyczyna, potem polecenie dla każdego magazynu
  text: "Strona, której certyfikatowi głównemu nie ufa żaden magazyn, sprawdzona na Windowsie z Gitem i ośmioma środowiskami Javy. Pierwsze zdanie nazywa przyczynę. Pod nim każdy magazyn ma własny wiersz, a każdy wiersz z odmową niesie polecenie, które dodałoby tam certyfikat główny, ze ścieżkami z tej maszyny. Cert Doctor wypisuje polecenia. Nigdy ich nie uruchamia."
  caption: Windows, fragment
  command: certdoctor https://untrusted-root.badssl.com/
  # Fragment prawdziwego przebiegu z 2026-11-12, wycięty linia po linii z tego, co wypisał.
  output: runs/untrusted-root-windows.txt
  link:
    text: Jak czytać raport
    page: /docs/read-the-report
steps:
  eyebrow: Jak to działa
  title: Jedno polecenie, cała droga
  items:
    - title: Wskaż adres, który nie działa
      text: "`certdoctor https://api.example.com/` - na laptopie, na agencie budującym albo w kontenerze, gdzie połączenie pada."
    - title: Przechodzi całą drogę
      text: "Każdy serwer DNS zapytany wprost, proxy, którego naprawdę użyją twoje programy, połączenie TCP z każdym adresem i pełny łańcuch certyfikatów z każdego z nich."
    - title: Odpowiada każdy magazyn zaufania
      text: "Magazyn Windows, pakiet CA Linuksa, każdy JDK i JRE, każdy git, curl, node, Python i pip, który znajdzie, każdy z poleceniem, które by go naprawiło."
layers:
  eyebrow: Sześć warstw
  title: Co sprawdza
  text: "Każda warstwa odpowiada na jedno pytanie. Zdanie na górze raportu pochodzi z warstwy, która przesądziła o wyniku, a to nie zawsze jest pierwsza czerwona."
  link:
    text: Każda warstwa po kolei
    page: /docs/layers
errors:
  eyebrow: Komunikaty błędów
  title: Znajdź komunikat, który widzisz
  text: "Każde środowisko opisuje ten sam problem po swojemu. Każda strona mówi, co znaczy komunikat, jakie ma przyczyny i jak Cert Doctor ustala, która dotyczy ciebie."
  pages:
    - /errors/pkix-path-building-failed
    - /errors/unable-to-get-local-issuer-certificate
    - /errors/self-signed-certificate-in-certificate-chain
    - /errors/x509-certificate-signed-by-unknown-authority
    - /errors/missing-intermediate-certificate
    - /errors/407-proxy-authentication-required
  link:
    text: Wszystkie komunikaty
    page: /errors
guides:
  eyebrow: Poradniki
  title: Napraw to w magazynie, który tego potrzebuje
  text: "Przeglądarka, JDK, Git for Windows i Python mogą ufać różnym listom. Poradniki mówią, gdzie każde z nich trzyma swoją listę i jakie polecenie dodaje do niej certyfikat."
  pages:
    - /guides/java-cacerts-keytool
    - /guides/git-ssl-certificate
    - /guides/node-extra-ca-certs
    - /guides/python-pip-certificates
    - /guides/windows-certificate-store
    - /guides/tls-inspection-corporate-proxy
  link:
    text: Wszystkie poradniki
    page: /guides
pipeline:
  eyebrow: Zgłoszenia i pipeline'y
  title: Raport do zgłoszenia, kod wyjścia dla CI
  text: "Markdown, jedna samodzielna strona HTML albo JSON sprawdzony ze schematem, zanim zostanie wypisany. `--redact` maskuje nazwy hostów, ścieżki i nazwy użytkowników, a poświadczenia są maskowane zawsze. Każde zakończenie ma własny kod wyjścia, a samo ostrzeżenie nie zatrzymuje budowania."
  caption: cztery sposoby na zachowanie raportu
  output: |-
    # raport do załączenia w zgłoszeniu
    certdoctor https://api.example.com/ --redact --format md --out report.md

    # jedna strona HTML bez żadnego skryptu
    certdoctor https://api.example.com/ --format html --out report.html

    # JSON dla pipeline'u, sprawdzony ze schematem
    certdoctor https://api.example.com/ --json --out report.json

    # ten sam raport później jako strona, bez ponownego przebiegu
    certdoctor --from report.json --format html --out report.html
  link:
    text: Użycie w CI
    page: /docs/ci
promises:
  eyebrow: Czego nigdy nie robi
  title: Bezpieczny na zablokowanej maszynie
  text: "Narzędzie, które uruchamiasz tam, gdzie połączenia padają, widzi wewnętrzne nazwy, ścieżki i serwery proxy. Oto obietnice, których dotrzymuje."
  items:
    - title: Niczego nie zmienia
      text: "Nigdy nie zapisuje do magazynu zaufania ani do pliku konfiguracyjnego. Jedyny plik, jaki zapisuje, to raport, pod ścieżką, którą podasz."
    - title: Nie uruchamia napraw
      text: "Wypisuje każde polecenie do przeczytania i uruchomienia przez ciebie. Sam nie uruchamia żadnego i mówi, kiedy polecenie wymaga uprawnień administratora."
    - title: Łączy się tylko tam, gdzie wskażesz
      text: "Adres, jego adresy IP, twoje serwery DNS, twoje proxy i twój skrypt PAC. Bez telemetrii i bez sprawdzania aktualizacji."
    - title: Poświadczenia zawsze zamaskowane
      text: "Hasła do proxy, nagłówki autoryzacji i ciasteczka nigdy nie trafiają do raportu, z `--redact` i bez."
    - title: Nie potrzebuje uprawnień administratora
      text: "Działa jako ten, kto go uruchomił, a raport mówi, z jakimi uprawnieniami działał."
    - title: Jeden plik, bez instalacji
      text: "Wersja na Linuksa to jeden statyczny plik, który działa bez zmian w obrazach Alpine i Ubuntu."
  link:
    text: Bezpieczeństwo i prywatność
    page: /security
cta:
  title: Dowiedz się, dlaczego nie działa, w jednym przebiegu
  text: "Darmowy i otwarty. Pobierz, rozpakuj i wskaż adres, który nie działa."
---
