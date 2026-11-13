---
title: Brak certyfikatu pośredniego
slug: brak-certyfikatu-posredniego
seoTitle: "Niepełny łańcuch: serwer nie wysyła certyfikatu pośredniego"
description: "Działa w przeglądarce, pada w curl, Javie i Pythonie? Serwer nie wysyła certyfikatu pośredniego. Jak udowodnić, że winny jest serwer, i jak to naprawić."
lead: "Przeglądarka się łączy, a wszystko inne pada, bo serwer wysyła swój certyfikat bez tego, który go wystawił."
messages:
  - from: curl, git, Python
    text: "unable to get local issuer certificate"
  - from: Java
    text: "PKIX path building failed: unable to find valid certification path to requested target"
  - from: Node.js
    text: "unable to verify the first certificate (UNABLE_TO_VERIFY_LEAF_SIGNATURE)"
---

## Co to znaczy

Serwer powinien wysyłać swój certyfikat i każdy certyfikat pośredni między nim a certyfikatem głównym. Certyfikat główny klient już ma. Gdy serwer pomija certyfikat pośredni, klient nie ma jak połączyć certyfikatu serwera z certyfikatem głównym, któremu ufa.

Przeglądarki często to ukrywają, bo pamiętają certyfikaty pośrednie spotkane na innych stronach, a niektóre pobierają brakujące. curl, Java, Python i Node.js tego nie robią, więc padają na tym samym adresie. Dlatego problem wygląda jak problem twojej maszyny, chociaż nim nie jest.

## Ustal, czy dotyczy ciebie

```
certdoctor https://incomplete-chain.badssl.com/
```

`L4` liczy certyfikaty, które pokazał serwer, i sprawdza, czy wystawca każdego z nich jest wśród nich. Gdy serwer jakiś pominął i żaden magazyn na maszynie nie zbudował bez niego ścieżki, Cert Doctor wskazuje serwer:

```
x The server presented 1 certificate(s) and did not send the issuer of the first one, so only a
  client that already holds it can build a path, and none of the 10 store(s) assessed here built one
  - this is a fact about the server rather than about this machine.
```

Raport zrobiony z `--redact --format md` jest dowodem do załączenia w zgłoszeniu dla tego, kto prowadzi serwer.

## Napraw to

Na serwerze: skonfiguruj go tak, żeby wysyłał pełny łańcuch - swój certyfikat, a za nim certyfikaty pośrednie, po kolei. Większość serwerów przyjmuje jeden plik z łańcuchem, a nie sam certyfikat.

Na kliencie, doraźnie, zanim serwer zostanie naprawiony: dodanie certyfikatu pośredniego do magazynu zaufania klienta pozwala temu jednemu klientowi zbudować ścieżkę. Macierz zaufania pokazuje, które magazyny tego potrzebują.

## Czego nie robić

Nie wyłączaj weryfikacji, żeby to obejść. Certyfikat serwera może być w pełni ważny, a naprawą jest jeden plik na serwerze.
