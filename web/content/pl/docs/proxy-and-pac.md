---
title: Proxy i skrypt PAC
slug: proxy-i-pac
seoTitle: Którego proxy używa ten adres? Diagnoza proxy i PAC
description: "Jak Cert Doctor ustala, przez które proxy naprawdę idzie adres: zmienne środowiskowe, ustawienia internetowe i WinHTTP w Windows, skrypt PAC i odpowiedź 407."
lead: "Na jednej maszynie o proxy decyduje kilka miejsc naraz, a różne programy słuchają różnych."
---

## Gdzie zapada decyzja o proxy

Warstwa proxy, `L2`, czyta każde miejsce, które może wskazać proxy, i pokazuje je obok siebie:

- **zmienne środowiskowe** - `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY` i `NO_PROXY`, każda w obu pisowniach, którymi kierują się narzędzia wiersza poleceń i większość środowisk,
- **ustawienia internetowe Windows** - którymi kierują się Edge, Chrome i programy .NET, razem z adresem skryptu PAC,
- **ustawienia WinHTTP** - którymi kierują się usługi Windows, osobne od powyższych i często od nich różne.

Gdy się nie zgadzają, raport mówi, który program kieruje się którym, więc przeglądarka, która się łączy, i usługa, która nie, przestają być zagadką.

## Skrypt PAC

Skrypt automatycznej konfiguracji proxy to mały program w JavaScripcie, który adres po adresie decyduje, którego proxy użyć. Wiele firm puszcza jeden host obok proxy, przez które idzie cała reszta, a jedynym sposobem, żeby wiedzieć, co skrypt robi z twoim adresem, jest jego uruchomienie.

Cert Doctor pobiera skrypt wskazany przez maszynę i uruchamia go w piaskownicy, żeby zobaczyć, dokąd kieruje ten adres. Odpowiedź jest podawana dla samego skryptu, a nie dla ustawienia, które go wskazało, więc dwa ustawienia wskazujące dwa niezgodne skrypty są pokazane oba.

Skrypt, który nie odpowiada niczym użytecznym, jest raportowany jako `UNKNOWN`, nigdy jako połączenie bezpośrednie: zgadywanie „bez proxy” kazałoby ci szukać w złym miejscu.

## Skrypt PAC, którego maszyna nie wskazuje

`--pac-url` pyta o skrypt po jego adresie, niezależnie od tego, czy cokolwiek na maszynie go wskazuje. Na Linuksie, gdzie nie ma systemowego ustawienia PAC, to jest sposób, żeby zapytać:

```
certdoctor https://api.example.com/ --pac-url http://wpad.example.com/proxy.pac
```

## Czy proxy chce poświadczeń

Gdy proxy ma zastosowanie, Cert Doctor pyta je, czy przyjmie połączenie bez poświadczeń. Proxy, które odpowiada `407 Proxy Authentication Required`, jest wskazane razem z metodami uwierzytelniania, które oferuje. Co z tym zrobić, mówi strona [407 Proxy Authentication Required](/errors/407-proxy-authentication-required/).

## Hasła w adresach proxy

Adres proxy może zawierać nazwę użytkownika i hasło, jak w `http://user:secret@proxy:8080`. Hasło jest odcinane w miejscu, w którym adres jest czytany, więc nigdy nie trafia do raportu ani do dziennika, z `--redact` i bez.
