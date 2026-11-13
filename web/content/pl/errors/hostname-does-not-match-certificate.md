---
title: Nazwa hosta nie pasuje do certyfikatu
slug: nazwa-hosta-nie-pasuje-do-certyfikatu
seoTitle: "Niezgodna nazwa hosta: certyfikat SSL dla innej nazwy"
description: "no alternative certificate subject name matches target host name, ERR_TLS_CERT_ALTNAME_INVALID i Hostname mismatch: dlaczego nazwa i certyfikat się różnią."
lead: "Certyfikat jest ważny, ale nie dla nazwy z adresu. Żaden magazyn zaufania tego nie naprawi, a Cert Doctor mówi to, zanim zapyta którykolwiek."
messages:
  - from: curl, git
    text: "SSL: no alternative certificate subject name matches target host name 'wrong.host.badssl.com'"
  - from: Node.js
    text: "Hostname/IP does not match certificate's altnames (ERR_TLS_CERT_ALTNAME_INVALID)"
  - from: Python
    text: "certificate verify failed: Hostname mismatch, certificate is not valid for 'wrong.host.badssl.com'"
  - from: Go
    text: "x509: certificate is valid for *.badssl.com, badssl.com, not wrong.host.badssl.com"
  - from: Java
    text: "No subject alternative DNS name matching wrong.host.badssl.com found."
---

## Co to znaczy

Certyfikat wymienia hosty, dla których jest wystawiony. Klient porównuje nazwę z adresu z tymi nazwami i odrzuca połączenie, gdy żadna jej nie obejmuje, bez względu na to, jak zaufany jest urząd certyfikatu.

## Częste przyczyny

- **Adres używa innej nazwy serwera** - adresu IP, krótkiej nazwy wewnętrznej, starego aliasu - której certyfikat nie wymienia.
- **Gwiazdka, która nie sięga.** `*.example.com` obejmuje `api.example.com`, a nie obejmuje `v2.api.example.com` ani samego `example.com`.
- **Wspólny adres podaje nie tę stronę** albo load balancer pokazuje swój domyślny certyfikat.
- **Coś pośrodku odpowiada zamiast serwera**, z własnym certyfikatem.

## Ustal, która dotyczy ciebie

```
certdoctor https://wrong.host.badssl.com/
```

`L4` porównuje nazwę z adresu z certyfikatem każdego adresu IP, a werdykt mówi, co obejmuje certyfikat:

```
x The server presented a certificate for *.badssl.com, badssl.com, and none of those names covers
  wrong.host.badssl.com - clients refuse that whatever they trust, so this is a fact about the
  server or about the name used to reach it.
```

Obejmowane nazwy i wystawca są w `L4` dla każdego adresu, więc load balancer z jednym adresem, który odpowiada inaczej, od razu się wyróżnia.

## Napraw to

Użyj nazwy, którą obejmuje certyfikat, albo poproś o ponowne wystawienie certyfikatu z potrzebną nazwą. Dodanie czegokolwiek do magazynu zaufania nie pomoże, bo problemem nigdy nie był urząd.

## Czego nie robić

Wyłączenie sprawdzania nazwy hosta w kliencie sprawia, że przyjmuje on ważny certyfikat dowolnej strony, także należącej do atakującego.
