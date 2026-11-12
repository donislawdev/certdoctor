---
title: Inspekcja TLS i certyfikaty firmowe
linkTitle: Inspekcja TLS
slug: inspekcja-tls-proxy-firmowe
seoTitle: Błędy SSL za firmowym proxy - inspekcja TLS wyjaśniona
description: "Za firmowym proxy z inspekcją TLS Java, git, npm i pip padają, a przeglądarka działa. Zobacz, kto podpisał certyfikat i gdzie go brakuje."
lead: "Sieć firmowa może odszyfrowywać i na nowo podpisywać HTTPS. Przeglądarka ufa firmowemu certyfikatowi głównemu, a każdy program z własną listą nie."
---

## Co robi inspekcja TLS

Proxy z inspekcją TLS - robi to wiele firmowych produktów bezpieczeństwa - stoi między twoją maszyną a internetem. Odpowiada na twoje połączenie certyfikatem, który zrobiło na miejscu dla tej strony, podpisanym własnym certyfikatem głównym, i otwiera własne połączenie z prawdziwym serwerem. Twoja maszyna mu ufa, bo dział IT zainstalował ten certyfikat główny, zwykle w magazynie systemu.

Programy, które czytają magazyn systemu, się łączą. Java, Git for Windows, Node.js i pip na certifi czytają własne listy i padają z [PKIX path building failed](/errors/pkix-path-building-failed/), [unable to get local issuer certificate](/errors/unable-to-get-local-issuer-certificate/) albo [SELF_SIGNED_CERT_IN_CHAIN](/errors/self-signed-certificate-in-certificate-chain/).

## Zobacz, kto podpisał certyfikat

```
certdoctor https://api.example.com/
```

Macierz zaufania mówi, kto podpisał certyfikat, który pokazał serwer, z jego odciskiem palca, i ile magazynów na tej maszynie ma ten urząd. Urząd, który ma magazyn Windows, a nie mają JDK i Node.js, to certyfikat główny, który dotarł tylko do części maszyny - zwykły obraz firmowego certyfikatu głównego albo produktu do inspekcji.

Gdy certyfikat nazywa produkt do inspekcji tak, jak publikuje to jego producent, raport nazywa produkt. W przeciwnym razie mówi, kto podpisał i ile magazynów go zna, i nic więcej, bo z jednego połączenia proxy z inspekcją i własny urząd firmy wyglądają tak samo. Powiedzieć komuś, że jego ruch jest przechwytywany, gdy nie jest, to szkoda, a nie szczegół.

## Zdobądź certyfikat główny

Dodać trzeba certyfikat główny na szczycie łańcucha, a nie certyfikat samej strony:

- **Poproś dział IT** o firmowy certyfikat główny w formacie PEM (Base-64). Pochodzenie takiego certyfikatu nie budzi wątpliwości.
- **Wyeksportuj go z magazynu Windows**, gdzie dział IT już go zainstalował: otwórz `certmgr.msc`, znajdź certyfikat główny w Zaufanych głównych urzędach certyfikacji i wyeksportuj go jako X.509 kodowany Base-64.
- **Porównaj odciski palców.** Odcisk palca z raportu certdoctor to to, z czym porównujesz otrzymany plik, zanim mu zaufasz.

Potem użyj poleceń, które macierz zaufania wypisała dla każdego magazynu z odmową.

## Dokąd go dodać

| Program | Poradnik |
|---|---|
| Java, Maven, Gradle | [Java cacerts i keytool](/guides/java-cacerts-keytool/) |
| git | [Git i certyfikaty SSL](/guides/git-ssl-certificate/) |
| Node.js, npm | [NODE_EXTRA_CA_CERTS](/guides/node-extra-ca-certs/) |
| Python, pip | [Certyfikaty Pythona i pipa](/guides/python-pip-certificates/) |
| Obrazy Dockera, Linux | [Pakiet CA Linuksa](/guides/linux-ca-bundle/) |
