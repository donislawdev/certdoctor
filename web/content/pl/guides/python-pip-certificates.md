---
title: Certyfikaty Pythona i pipa
slug: python-pip-certyfikaty
seoTitle: "pip i Python CERTIFICATE_VERIFY_FAILED: właściwa naprawa"
description: "Napraw pip i Python CERTIFICATE_VERIFY_FAILED: której liście ufa każdy Python i pip, certifi, truststore od pip 24.2, REQUESTS_CA_BUNDLE i PIP_CERT."
lead: "Moduł `ssl` Pythona, `requests` i pip mogą ufać różnym listom. Znajdź tę, którą czyta program, który pada, zanim cokolwiek zmienisz."
---

## Którą listę czyta Python

Moduł `ssl` Pythona ufa temu, co jego OpenSSL ma czytać. Na Linuksie to zwykle pakiet dystrybucji, na Windowsie magazyn certyfikatów Windows, który Python czyta za każdym razem, gdy program tworzy domyślny kontekst TLS ([dokumentacja ssl](https://docs.python.org/3/library/ssl.html#ssl.SSLContext.load_default_certs)). `SSL_CERT_FILE` kieruje go na inny plik.

## Którą listę czyta pip

pip ma własną regułę ([dokumentacja pip](https://pip.pypa.io/en/stable/topics/https-certificates/)):

- **od pip 24.2** pip używa `truststore`, które pyta własny magazyn systemu operacyjnego - firmowy certyfikat główny, który dział IT umieścił w magazynie Windows, dociera do pipa,
- **przed 24.2** albo z `--use-deprecated=legacy-certs` pip ufa jednemu plikowi: pakietowi `certifi`, który ze sobą niesie, albo plikowi wskazanemu przez `PIP_CERT`, jego ustawienie `cert` albo `REQUESTS_CA_BUNDLE`.

Tak wskazany plik zastępuje listę certifi, a nie dokłada do niej.

## Zobacz, czemu ufa każdy Python i pip

```
certdoctor https://pypi.org/
```

Każdy Python w PATH dostaje wiersz `python`, oceniany według listy, której ufa jego moduł `ssl`, a pip każdego Pythona dostaje wiersz `pip`, oceniany według własnej reguły pipa: `truststore` albo `certifi` i plik wskazany dla niego. `L0` pokazuje, czy ustawiono `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` albo `PIP_CERT`.

## Dodaj certyfikat główny

Polecenie zależy od wiersza:

- **Python na Windowsie**: magazyn Windows tego konta, `certutil -user -addstore Root "<certificate.pem>"`. Windows prosi o potwierdzenie, a każdy Python uruchomiony później go czyta.
- **Python albo pip czytający plik**: dopisanie certyfikatu głównego do tego pliku, tak jak wypisuje to wiersz. Każdy program czytający ten sam plik też zaczyna ufać certyfikatowi, a narzędzie, które utrzymuje plik - `update-ca-certificates`, `update-ca-trust` - może go przepisać i zgubić dopisany certyfikat. Jak sprawić, żeby został, mówi poradnik [pakiet CA Linuksa](/guides/linux-ca-bundle/).
- **pip tylko na certifi, bez wskazanego pliku**: bez polecenia, a wiersz mówi dlaczego - wskazanie pliku zastąpiłoby listę certifi. pip od 24.2 czyta zamiast tego magazyn systemu.

## Python 3.13

Python 3.13 odrzuca też certyfikaty, które łamią ścisłe reguły OpenSSL. Gdy wiersz nazywa regułę, a nie nieznany urząd, dotyczy cię strona [Python 3.13 certificate verify failed](/errors/python-3-13-strict-certificate-checks/).

## Czego nie robić

`verify=False` w `requests` i `--trusted-host` w pip pomijają weryfikację dla tych połączeń. Ukrywają problem, zamiast go naprawić.
