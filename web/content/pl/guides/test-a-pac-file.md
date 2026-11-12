---
title: Sprawdź plik PAC
slug: test-pliku-pac
seoTitle: Sprawdź plik PAC - które proxy wybiera dla adresu
description: "Ustal, które proxy wybiera skrypt PAC dla adresu, uruchom skrypt, którego używa maszyna, albo dowolny inny i porównaj go z resztą ustawień proxy."
lead: "Skrypt PAC adres po adresie decyduje, którego proxy użyć. Jedynym sposobem, żeby wiedzieć, co robi z twoim adresem, jest jego uruchomienie."
---

## Czym jest skrypt PAC

Plik automatycznej konfiguracji proxy to funkcja w JavaScripcie, `FindProxyForURL(url, host)`, która dla każdego adresu zwraca `DIRECT` albo listę serwerów proxy ([MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Proxy_servers_and_tunneling/Proxy_Auto-Configuration_PAC_file)). Firmy używają go, żeby puszczać wewnętrzne hosty obok proxy, a wszystko inne przez nie. Przeglądarki i wiele programów Windows kieruje się skryptem wskazanym przez maszynę. Narzędzia wiersza poleceń zwykle nie i czytają zamiast tego zmienne proxy - to jeden z powodów, dla których przeglądarka i skrypt się nie zgadzają.

## Uruchom skrypt, którego używa maszyna

```
certdoctor https://api.example.com/
```

`L2` znajduje skrypt wskazany przez maszynę, pobiera go, uruchamia w piaskownicy dla tego adresu i pokazuje jego odpowiedź obok każdego innego miejsca, które wskazuje proxy: zmiennych środowiskowych, ustawień internetowych Windows i ustawień WinHTTP. Gdy się nie zgadzają, widać, który program kieruje się którym.

## Uruchom dowolny skrypt po adresie

```
certdoctor https://api.example.com/ --pac-url http://wpad.example.com/proxy.pac
```

`--pac-url` pyta o skrypt niezależnie od tego, czy cokolwiek na maszynie go wskazuje. Na Linuksie, gdzie nie ma systemowego ustawienia PAC, to jest sposób, żeby zapytać. Uruchom go raz dla każdego adresu, który cię interesuje: skrypt często kieruje różne hosty różnymi drogami.

## Co znaczy odpowiedź

- **Proxy** - ten adres idzie przez nie. certdoctor pyta wtedy to proxy, czy chce poświadczeń, i wskazuje [407](/errors/407-proxy-authentication-required/).
- **`DIRECT`** - ten adres idzie prosto do serwera.
- **Brak użytecznej odpowiedzi** - raportowany jako `UNKNOWN` z powodem, nigdy jako `DIRECT`, bo zgadywanie „bez proxy” kazałoby ci szukać w złym miejscu.
