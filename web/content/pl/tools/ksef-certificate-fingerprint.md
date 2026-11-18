---
title: Odcisk palca certyfikatu w KSeF
slug: odcisk-palca-certyfikatu-ksef
seoTitle: "Odcisk palca certyfikatu KSeF: SHA-256 bez wysyłania pliku"
description: "Odcisk palca, o który pyta KSeF, to SHA-256 certyfikatu. Odczytaj go z pliku .cer lub .crt na swoim komputerze i zapisz wielkimi literami, jak robi to KSeF."
lead: "KSeF rozpoznaje certyfikat bez numeru NIP ani PESEL po odcisku palca: skrócie SHA-256 całego certyfikatu, 64 cyfrach szesnastkowych."
---

## Czym jest odcisk palca w KSeF

Podręcznik użytkownika Modułu Certyfikatów i Uprawnień (MCU) Ministerstwa Finansów definiuje odcisk palca certyfikatu jako wartość wyliczoną z certyfikatu funkcją skrótu opartą na SHA-256, prezentowaną jako ciąg 64 znaków ([podręcznik MCU](https://ksef.podatki.gov.pl/media/0iafuqe5/podrecznik-uzytkownika-modulu-certyfikatow-i-uprawnien-mcu.pdf), listopad 2025, strona 5). Oficjalny klient Ministerstwa w Javie liczy go z zakodowanego certyfikatu i zapisuje wielkimi literami ([`getSha256Fingerprint`](https://github.com/CIRFMF/ksef-client-java/blob/main/ksef-client/src/main/java/pl/akmf/ksef/sdk/api/services/DefaultCertificateService.java)), a klient w C# przyjmuje dokładnie 64 wielkie cyfry szesnastkowe ([`RegexPatterns`](https://github.com/CIRFMF/ksef-client-csharp/blob/main/KSeF.Client/Validation/RegexPatterns.cs)).

To odcisk palca SHA-256 certyfikatu - ta sama wartość, którą [dekoder certyfikatów](/tools/certificate-decoder/) wypisuje w wierszu `SHA-256`.

To nie jest pole **Thumbprint**, które Windows pokazuje dla certyfikatu, choć polska dokumentacja Microsoftu też nazywa je odciskiem palca: tamto to SHA-1, 40 znaków ([X509Certificate2.Thumbprint](https://learn.microsoft.com/pl-pl/dotnet/api/system.security.cryptography.x509certificates.x509certificate2.thumbprint)). KSeF chce 64 znaków SHA-256.

## Kiedy jest potrzebny

Certyfikatu kwalifikowanego, który nie zawiera ani NIP, ani PESEL, można używać w KSeF dopiero po nadaniu uprawnień na jego odcisk palca (podręcznik MCU, strona 17). Tak samo można nadać uprawnienia osobie albo podmiotowi unijnemu ([dokumentacja API KSeF, uprawnienia](https://github.com/CIRFMF/ksef-docs/blob/main/uprawnienia.md)).

## Odczytaj go z pliku certyfikatu

Potrzebny jest sam certyfikat, bez klucza prywatnego - zwykle plik `.cer` albo `.crt`, w PEM albo w DER:

```
certdoctor tool cert --file certyfikat.cer
```

Odcisk palca to wiersz `SHA-256`:

```
  SHA-256           7767265b01d8e5c8c7eff9300a10706d8e3dad5ccb55f688acaabbc28cca3d34
```

Dekoder zapisuje go małymi literami, a KSeF wielkimi - to te same 64 cyfry. Żeby wypisać go wielkimi literami w PowerShell:

```
(certdoctor tool cert --file certyfikat.cer --json | ConvertFrom-Json).data.certificates[0].fingerprint_sha256.ToUpper()
```

Na Linuksie i macOS, z `jq`:

```
certdoctor tool cert --file certyfikat.cer --json | jq -r '.data.certificates[0].fingerprint_sha256' | tr a-f A-F
```

Plik jest czytany na twoim komputerze i nic nie jest nigdzie wysyłane. Plik `.pfx` albo `.p12` zawiera też klucz prywatny i nie jest plikiem certyfikatu, więc dekoder go odrzuca.

## Druga droga: MCU

MCU wylicza odcisk palca certyfikatu kwalifikowanego z pliku, który nim podpiszesz: pobierz plik, podpisz go certyfikatem kwalifikowanym, przekaż podpisany plik i naciśnij **Pobierz odcisk palca** (podręcznik MCU, strony 17-18). Obie drogi dają SHA-256 tego samego certyfikatu.

## Certyfikaty KSeF

Certyfikaty, które wydaje samo MCU - certyfikaty KSeF do uwierzytelniania i do faktur w trybie offline - pobiera się w formacie PEM z rozszerzeniem `.crt` (podręcznik MCU, strona 85). Dekoder certyfikatów czyta je jak każde inne: dla kogo są, kiedy wygasają, jaki mają klucz i odciski palca.

```
certdoctor tool cert --file Certyfikat_testowy.crt
```
