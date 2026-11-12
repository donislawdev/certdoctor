---
title: PKIX path building failed
codeTitle: true
seoTitle: "PKIX path building failed: przyczyny i naprawa"
description: "PKIX path building failed i unable to find valid certification path to requested target w Javie: dlaczego jeden JDK odmawia i które polecenie keytool pomaga."
lead: "Java nie zbudowała łańcucha od certyfikatu serwera do urzędu w swoim `cacerts`. Pytanie brzmi: która Java i dlaczego w jej `cacerts` brakuje tego, co ma system."
messages:
  - from: Java
    text: "javax.net.ssl.SSLHandshakeException: PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target"
  - from: Maven, Gradle
    text: "PKIX path building failed: unable to find valid certification path to requested target"
---

## Co to znaczy

Każda instalacja Javy ma własną listę zaufanych urzędów, plik `cacerts` w swoim folderze `lib/security`. Java czyta ten plik, a nie magazyn certyfikatów Windows, a JDK rozpakowany samodzielnie nie podąża też za pakietem certyfikatów Linuksa. Gdy łańcuch serwera nie prowadzi do urzędu z tego pliku, Java odrzuca połączenie z tym komunikatem. Maven, Gradle, Jenkins, IntelliJ i każdy inny program na tym JDK pokazują go, otoczony własnymi słowami.

## Częste przyczyny

- **Firmowy certyfikat główny, który nie dotarł do Javy.** Firma albo jej proxy z inspekcją TLS podpisuje połączenia własnym urzędem, który dział IT dodał do magazynu systemu. Przeglądarki i curl mu ufają, a JDK nie.
- **Naprawiono nie ten JDK.** Maszyna często ma kilka JDK i JRE - jeden dla IDE, jeden do budowania, jeden dołączony do narzędzia. Certyfikat trafił do jednego `cacerts`, a program, który pada, działa na innym.
- **Aktualizacja JDK przyniosła świeży `cacerts`.** Nowsza wersja nie przenosi certyfikatów dodanych do starej.
- **Serwer nie wysyła certyfikatu pośredniego.** Wtedy żaden klient nie zbuduje łańcucha bez pomocy, a winny jest serwer. Opisuje to strona [brak certyfikatu pośredniego](/errors/missing-intermediate-certificate/).

## Ustal, która dotyczy ciebie

```
certdoctor https://adres-ktory-nie-dziala/
```

Macierz zaufania ma jeden wiersz na każdy JDK i JRE, jaki certdoctor znajdzie, każdy z własnym `cacerts`. Pokazuje, które z nich odrzucają łańcuch, podczas gdy magazyn systemu go przyjmuje, kto podpisał certyfikat, a dla każdego odmawiającego JDK dokładne polecenie `keytool` ze ścieżkami tej instalacji:

```
      java C:\Program Files\OpenJDK\jdk-21.0.2 does NOT trust the presented chain (106
        anchors)  detected
        run: "C:\Program Files\OpenJDK\jdk-21.0.2\bin\keytool" -importcert -trustcacerts -keystore "C:\Program Files\OpenJDK\jdk-21.0.2\lib\security\cacerts" -storepass changeit -alias "<alias>" -file "<certificate.pem>"
```

Jeśli werdykt mówi zamiast tego, że serwer nie wysłał wystawcy swojego certyfikatu, naprawa należy do serwera.

## Napraw to

Zaimportuj brakujący certyfikat główny do `cacerts` JDK, który pada, jego własnym `keytool`, tak jak wypisuje to wiersz. Podstaw za `<alias>` nazwę wpisu, a za `<certificate.pem>` plik z certyfikatem głównym. Przeprowadza przez to poradnik [Java cacerts i keytool](/guides/java-cacerts-keytool/), razem z tym, skąd wziąć certyfikat.

Potem uruchom certdoctor ponownie: wiersz zmieni się na zaufany, a pozostałe JDK pokażą, czy potrzebują tego samego.

## Czego nie robić

Nie wyłączaj sprawdzania certyfikatów w aplikacji i nie ustawiaj menedżera zaufania, który przyjmuje wszystko. To usuwa błąd, przyjmując każdy certyfikat od każdego, także taki, który pokaże atakujący.
