---
title: NODE_EXTRA_CA_CERTS i NODE_USE_SYSTEM_CA
linkTitle: Node.js i npm
seoTitle: "NODE_EXTRA_CA_CERTS i NODE_USE_SYSTEM_CA - wyjaśnienie"
description: "Napraw SELF_SIGNED_CERT_IN_CHAIN w Node.js i npm: NODE_USE_SYSTEM_CA, żeby ufać magazynowi systemu, NODE_EXTRA_CA_CERTS, żeby dodać certyfikat, i który wybrać."
lead: "Node.js ufa liście, z którą go zbudowano, a nie liście systemu. Dwie zmienne ją rozszerzają, a która jest potrzebna, zależy od tego, gdzie już jest twój certyfikat główny."
---

## Którą listę czyta Node.js

Node.js ma własną listę urzędów głównych, wkompilowaną w binarkę. Nie czyta magazynu Windows ani pakietu Linuksa, chyba że mu się to każe. Dwie zmienne środowiskowe dokładają do jego listy i żadna niczego z niej nie usuwa ([dokumentacja Node.js](https://nodejs.org/api/cli.html#node_extra_ca_certsfile)):

- `NODE_USE_SYSTEM_CA=1` dokłada certyfikaty, którym ufa system operacyjny. Czyta ją Node.js od v22.19.0 i od v24.6.0, a żadna wersja v23.
- `NODE_EXTRA_CA_CERTS` wskazuje plik PEM, którego certyfikaty są dokładane.

Node.js czyta obie przy starcie, więc `node`, który już działa - serwer języka w edytorze, obserwator plików - trzyma starą listę, dopóki nie zostanie uruchomiony ponownie. npm działa na Node.js, więc zmienne docierają też do niego.

## Zobacz, czego potrzebuje każdy node

```
certdoctor https://registry.npmjs.org/
```

Każdy `node` w PATH dostaje wiersz, oceniany według listy, której ufa ta binarka. Jego polecenie to pierwsze z tych, które by zadziałało:

1. **`NODE_USE_SYSTEM_CA=1`**, gdy własna lista systemu domknęłaby łańcuch - zwykły przypadek, gdy dział IT już umieścił firmowy certyfikat główny w magazynie systemu. Nic do pobierania.
2. **Dopisanie do pliku wskazanego przez `NODE_EXTRA_CA_CERTS`**, gdy ta zmienna jest już ustawiona, a Node przeczytał z niej certyfikaty. Ponowne ustawienie zmiennej zgubiłoby ten plik.
3. **Ustawienie `NODE_EXTRA_CA_CERTS`** na plik z certyfikatem głównym, gdy nic nie jest ustawione.

Na Windowsie polecenie to `setx`, które zachowuje zmienną dla twojego konta, a na Linuksie i macOS `export`, które trzeba wpisać do profilu powłoki, żeby zostało:

```
setx NODE_USE_SYSTEM_CA 1
export NODE_USE_SYSTEM_CA=1
```

Otwórz potem nowy terminal: `setx` dociera tylko do okien otwartych po jego uruchomieniu.

## Czego nie robić

`NODE_TLS_REJECT_UNAUTHORIZED=0` i `npm config set strict-ssl false` całkiem wyłączają sprawdzanie certyfikatów. `L0` czyta `NODE_TLS_REJECT_UNAUTHORIZED`, więc raport pokazuje, gdy ktoś już to zrobił.
