---
title: Dodaj certyfikat do Java cacerts przez keytool
linkTitle: Java cacerts i keytool
seoTitle: "Java cacerts: import certyfikatu przez keytool"
description: "Zaimportuj firmowy certyfikat główny do Java cacerts przez keytool, znajdź każdy JDK i JRE na maszynie i zobacz, które odmawiają, z poleceniem dla każdego."
lead: "Każdy JDK i JRE ma własny `cacerts`. Liczy się ten, na którym działa program, który pada, a maszyna zwykle ma ich więcej niż jeden."
---

## Gdzie Java trzyma swoją listę

Każda instalacja Javy ma plik `cacerts` w swoim folderze `lib/security` - `C:\Program Files\OpenJDK\jdk-21.0.2\lib\security\cacerts`, `/usr/lib/jvm/java-21-openjdk/lib/security/cacerts` - i ufa urzędom z tego pliku. Jego domyślne hasło to `changeit`, opublikowane, a nie tajne. Program, który pada z [PKIX path building failed](/errors/pkix-path-building-failed/), nie ma urzędu w `cacerts` tej Javy, na której działa.

## Znajdź każdą Javę na maszynie

```
certdoctor https://adres-ktory-nie-dziala/
```

Macierz zaufania ma jeden wiersz `java` na każdy znaleziony JDK i JRE, każdy z własnym `cacerts` i liczbą zaufanych certyfikatów. Wiersze z odmową niosą polecenie dla tej instalacji:

```
      java C:\Program Files\OpenJDK\jdk-21.0.2 does NOT trust the presented chain (106
        anchors)  detected
        needs elevated rights: this store is outside this account's own files, so it belongs to
                               every account on the machine
        run: "C:\Program Files\OpenJDK\jdk-21.0.2\bin\keytool" -importcert -trustcacerts -keystore "C:\Program Files\OpenJDK\jdk-21.0.2\lib\security\cacerts" -storepass changeit -alias "<alias>" -file "<certificate.pem>"
        replace first: <alias>, <certificate.pem>
```

## Zaimportuj certyfikat

Polecenie używa `keytool` z tej samej instalacji co `cacerts`, który zmienia, więc nowszy albo starszy `keytool` nie przepisze pliku w swoim formacie. Zanim je uruchomisz:

1. Zapisz certyfikat główny do pliku. Jak go zdobyć, mówi strona [inspekcja TLS](/guides/tls-inspection-corporate-proxy/).
2. Podstaw za `<certificate.pem>` pełną ścieżkę do tego pliku, a za `<alias>` nazwę wpisu, na przykład `company-root`.
3. Uruchom je w terminalu z uprawnieniami administratora, gdy wiersz mówi, że ich wymaga, a wymaga dla JDK w `Program Files` albo `/usr/lib/jvm`.

Na Windowsie polecenie jest napisane dla Wiersza polecenia (`cmd.exe`). W PowerShellu postaw przed nim `&` i spację.

`keytool -importcert` dodaje jeden wpis i zostawia resztę pliku bez zmian ([dokumentacja keytool](https://docs.oracle.com/en/java/javase/21/docs/specs/man/keytool.html)). Uruchom potem Cert Doctor ponownie: wiersz zmieni się na zaufany.

## Gdy problem wraca

Aktualizacja JDK instaluje nowy `cacerts` i nie przenosi twojego certyfikatu, a każdy wiersz to mówi. Po aktualizacji uruchom Cert Doctor ponownie i zaimportuj do nowej instalacji.

## Inne JDK, które też tego potrzebują

Macierz wymienia każdą Javę, jaką znajdzie, więc od razu widać, które inne instalacje - wbudowane środowisko IDE, stare JRE, którego wciąż używa jakieś narzędzie - potrzebują tego samego importu.
