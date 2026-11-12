---
title: 407 Proxy Authentication Required
codeTitle: true
seoTitle: "407 Proxy Authentication Required: które proxy i dlaczego"
description: "407 Proxy Authentication Required w curl, git, npm, pip i Javie: ustal, przez które proxy naprawdę idzie adres i jakich poświadczeń ono chce."
lead: "Między tobą a serwerem stoi proxy i chce wiedzieć, kto pyta. Najpierw ustal które proxy i co przyjmuje."
messages:
  - from: curl, git
    text: "CONNECT tunnel failed, response 407"
  - from: Java
    text: "Unable to tunnel through proxy. Proxy returns \"HTTP/1.1 407 Proxy Authentication Required\""
  - from: npm, pip
    text: "407 Proxy Authentication Required"
---

## Co to znaczy

Program wysłał żądanie przez proxy, a proxy odmówiło przekazania go dalej bez poświadczeń. Serwer nie został osiągnięty, więc to nic nie mówi o serwerze ani o jego certyfikacie.

## Częste przyczyny

- **Program używa proxy, którego się nie spodziewasz.** Zmienna taka jak `HTTPS_PROXY` albo skrypt PAC kieruje ten adres przez proxy, przez które przeglądarka przechodzi dzięki twojemu logowaniu do Windows, a ten program nie potrafi.
- **Proxy chce logowania, którego program nie umie dać.** Wiele firmowych proxy przyjmuje Negotiate albo NTLM, które przeglądarka robi twoim kontem Windows, a narzędzie wiersza poleceń zwykle nie.
- **Poświadczenia w adresie proxy są złe albo nieaktualne.**

## Ustal, które proxy i czego chce

```
certdoctor https://adres-ktory-nie-dziala/
```

`L2` pokazuje każde miejsce na maszynie, które wskazuje proxy - zmienne środowiskowe, ustawienia internetowe Windows, ustawienia WinHTTP i skrypt PAC - i które z nich dotyczy tego adresu. Potem certdoctor pyta to proxy, czy przyjmie połączenie bez poświadczeń, a gdy odpowie `407`, raport wymienia metody uwierzytelniania, które oferuje.

Hasła wpisane w adresy proxy nigdy nie trafiają do raportu: są odcinane w miejscu, w którym adres jest czytany.

## Napraw to

- Jeśli adres w ogóle nie powinien iść przez proxy, dodaj jego host do `NO_PROXY` dla tego programu albo zapytaj właściciela skryptu PAC.
- Jeśli proxy przyjmuje uwierzytelnianie Basic, program może nieść nazwę użytkownika i hasło w adresie proxy.
- Jeśli oferuje tylko Negotiate albo NTLM, zapytaj, czy proxy może przepuszczać ten program bez logowania, albo użyj programu, który umie się logować tymi metodami.

Więcej o tym, jak zapada decyzja o proxy, mówi strona [proxy i skrypt PAC](/docs/proxy-and-pac/).
