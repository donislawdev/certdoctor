---
title: self-signed certificate in certificate chain
codeTitle: true
seoTitle: "SELF_SIGNED_CERT_IN_CHAIN: naprawa w npm, Node i git"
description: "npm ERR! SELF_SIGNED_CERT_IN_CHAIN i self-signed certificate in certificate chain w Node.js, git i Pythonie: dlaczego pojawia się za proxy i jak to naprawić."
lead: "Łańcuch kończy się certyfikatem głównym, któremu ten program nie ufa. W sieci firmowej to prawie zawsze certyfikat firmy albo jej proxy z inspekcją."
messages:
  - from: npm
    text: "npm ERR! code SELF_SIGNED_CERT_IN_CHAIN"
  - from: Node.js
    text: "Error: self-signed certificate in certificate chain"
  - from: git, curl
    text: "SSL certificate problem: self-signed certificate in certificate chain"
  - from: Python, pip
    text: "certificate verify failed: self-signed certificate in certificate chain"
---

## Co to znaczy

Każdy łańcuch kończy się certyfikatem głównym, który podpisuje sam siebie. To normalne. Ten komunikat mówi, że łańcuch, który dostał program, zawierał certyfikat główny, którego nie ma na liście zaufanych urzędów programu. Starsze wersje piszą „self signed” bez łącznika.

To nie znaczy, że serwer ma źle skonfigurowany, domowej roboty certyfikat, chociaż i tak bywa. W sieci firmowej zwykle znaczy, że coś między tobą a serwerem podpisuje połączenie na nowo własnym certyfikatem głównym.

## Częste przyczyny

- **Inspekcja TLS.** Firmowe proxy odszyfrowuje i na nowo podpisuje ruch HTTPS własnym certyfikatem głównym. Dział IT zainstalował go w magazynie systemu, a Node.js, npm, Git for Windows i Python czytają własne listy.
- **Prywatny urząd certyfikacji.** Wewnętrzny serwer z certyfikatem od własnego urzędu firmy, któremu ufają maszyny, które dostały jego certyfikat główny.
- **Serwer, który naprawdę używa samopodpisanego certyfikatu głównego**, na przykład środowisko testowe.

## Ustal, która dotyczy ciebie

```
certdoctor https://adres-ktory-nie-dziala/
```

Macierz zaufania mówi, kto podpisał certyfikat i ile magazynów na tej maszynie ma ten urząd. Certyfikat główny, który ma magazyn Windows, a nie mają node i git, to certyfikat, który dotarł tylko do części maszyny. Gdy podpisujący jest produktem do inspekcji, który certdoctor rozpoznaje, raport go nazywa.

Każdy wiersz node jest oceniany według listy, której ufa ta binarka `node`, a jego polecenie zależy od tego, co domknęłoby łańcuch: włączenia własnej listy systemu, jeśli ma ona ten certyfikat główny, albo dodania go do pliku wskazanego przez `NODE_EXTRA_CA_CERTS`.

## Napraw to

- Node.js i npm - [NODE_EXTRA_CA_CERTS i NODE_USE_SYSTEM_CA](/guides/node-extra-ca-certs/)
- git - [Git i certyfikaty SSL](/guides/git-ssl-certificate/)
- Python i pip - [certyfikaty Pythona i pipa](/guides/python-pip-certificates/)
- Zdobycie firmowego certyfikatu głównego - [inspekcja TLS](/guides/tls-inspection-corporate-proxy/)

## Czego nie robić

`npm config set strict-ssl false` i `NODE_TLS_REJECT_UNAUTHORIZED=0` wyłączają weryfikację dla wszystkiego, z czym łączy się ten proces. certdoctor czyta `NODE_TLS_REJECT_UNAUTHORIZED` w `L0`, więc raport pokazuje, gdy ktoś już to zrobił.
