---
title: Python 3.13 certificate verify failed
slug: python-3-13-scisle-sprawdzanie-certyfikatow
seoTitle: "Python 3.13: Basic Constraints not marked critical, naprawa"
description: "Python 3.13 pada z Missing Authority Key Identifier albo Basic Constraints of CA cert not marked critical. Który certyfikat łamie którą regułę."
lead: "Python 3.13 włączył ścisłe sprawdzanie OpenSSL. Certyfikat główny firmy albo inspekcji, który starsze Pythony przyjmowały, teraz może zostać odrzucony za to, jak go zrobiono."
messages:
  - from: Python 3.13
    text: "certificate verify failed: Basic Constraints of CA cert not marked critical"
  - from: Python 3.13
    text: "certificate verify failed: Missing Authority Key Identifier"
---

## Co to znaczy

Od Pythona 3.13 domyślny kontekst TLS ustawia flagę OpenSSL `VERIFY_X509_STRICT` ([dokumentacja Pythona](https://docs.python.org/3/library/ssl.html#ssl.create_default_context)). Z nią OpenSSL odrzuca certyfikaty, które łamią reguły standardu, nawet gdy łańcuch prowadzi do zaufanego certyfikatu głównego: certyfikat urzędu, którego rozszerzenie Basic Constraints nie jest oznaczone jako krytyczne, certyfikat bez Authority Key Identifier i podobne.

Publiczne urzędy wystawiają certyfikaty, które przechodzą. Certyfikaty zrobione ręcznie, przez stary wewnętrzny urząd albo przez niektóre produkty do inspekcji TLS mogą nie przejść, więc ten sam adres działa w Pythonie 3.12 i pada w 3.13.

## Ustal, który certyfikat łamie którą regułę

```
certdoctor https://adres-ktory-nie-dziala/
```

Każdy Python w PATH ma własny wiersz w macierzy zaufania. Na Pythonie z OpenSSL w wersji 3 Cert Doctor stosuje te same ścisłe reguły do łańcucha, który zbudowałby OpenSSL, a wiersz nazywa certyfikat i regułę, którą łamie, zamiast samej odmowy. Pozostałe wiersze pokazują, czy ten sam certyfikat główny jest zaufany przez całą resztę, co zwykle jest prawdą.

## Napraw to

Trwałą naprawą jest certyfikat zgodny z regułami: kto prowadzi urząd, wystawia go ponownie z Basic Constraints oznaczonym jako krytyczne i z Authority Key Identifier. Dla firmowego certyfikatu głównego albo produktu do inspekcji to prośba do działu IT albo do producenta, a wiersz raportu jest dowodem.

Dodanie certyfikatu głównego do magazynu zaufania Pythona nie pomaga, gdy jest on już zaufany: odmowa dotyczy tego, jak zrobiono certyfikat, a nie tego, komu ufa Python.

We własnym kodzie, zanim certyfikat zostanie wystawiony ponownie, kontekst może zdjąć ścisłą flagę tylko dla tego połączenia:

```python
import ssl
context = ssl.create_default_context()
context.verify_flags &= ~ssl.VERIFY_X509_STRICT
```

To zostawia każde inne sprawdzenie, w tym łańcuch i nazwę.
