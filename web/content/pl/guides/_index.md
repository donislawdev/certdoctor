---
title: Poradniki
linkTitle: Wszystkie poradniki
slug: poradniki
seoTitle: Dodaj certyfikat CA do Javy, gita, Node, Pythona i Windows
description: "Gdzie Java, Git, curl, Node.js, Python, pip, Windows i Linux trzymają zaufane certyfikaty i jakie polecenie dodaje firmowy certyfikat główny do każdego z nich."
lead: "Każde środowisko ma własną listę zaufanych urzędów. Każdy poradnik mówi, gdzie jedno z nich ją trzyma i jak dodać do niej certyfikat."
cards:
  - /guides/java-cacerts-keytool
  - /guides/git-ssl-certificate
  - /guides/curl-ca-bundle
  - /guides/node-extra-ca-certs
  - /guides/python-pip-certificates
  - /guides/windows-certificate-store
  - /guides/linux-ca-bundle
  - /guides/tls-inspection-corporate-proxy
  - /guides/test-a-pac-file
---

Firmowy certyfikat główny dodany do magazynu Windows trafia do przeglądarki i do programów, które czytają ten magazyn. Nie trafia do `cacerts` JDK, do pakietu Git for Windows, do wbudowanej listy Node.js ani do pliku, który czyta Python. Każde z nich potrzebuje certyfikatu dodanego tam, gdzie zagląda.

`certdoctor` mówi, które z nich odmawiają, na maszynie, na której połączenie pada, i wypisuje polecenie dla każdego, ze ścieżkami z tej maszyny. Poradniki wyjaśniają, co robią te polecenia, żeby uruchamiać je ze świadomością, co się zmienia.
