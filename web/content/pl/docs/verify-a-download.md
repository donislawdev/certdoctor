---
title: Sprawdź pobrany plik
slug: sprawdz-pobrany-plik
seoTitle: Sprawdź pobrany certdoctor - sumy kontrolne i atestacja
description: "Sprawdź archiwum certdoctor z listą SHA-256 wydania i udowodnij, skąd pochodzi, podpisanym przez GitHuba zestawieniem składników."
lead: "Dwa pytania: czy to plik, który opublikowało wydanie, i czy wydanie zbudowano z tego repozytorium?"
---

## Czy to plik, który opublikowało wydanie

Każde wydanie podaje SHA-256 każdego publikowanego pliku w `verify-SHA256SUMS.txt`. Pobierz go obok archiwum, a potem na Linuksie albo macOS:

{{< readme-check 1 >}}

Na Windowsie, w PowerShellu, `True` obok archiwum znaczy, że to plik, który opublikowało wydanie:

{{< readme-check 2 >}}

## Czy zbudowano go z tego repozytorium

Plik z sumami z tej samej strony dowodzi tylko, że oba się zgadzają. Skąd pochodzą, dowodzi oświadczenie, które GitHub podpisał przy tworzeniu wydania, a sprawdza je [GitHub CLI](https://cli.github.com/):

{{< readme-check 3 >}}

To oświadczenie jest zestawieniem składników - każdy moduł wkompilowany w program, razem z narzędziami Go, z licencją i wersją - i obejmuje każdy plik wydania. Typ predykatu trzeba podać, bo bez niego `gh` pyta o pochodzenie buildu, a to inne oświadczenie.

Archiwum na Linuksa to dokładnie te bajty, które wytworzył build, więc odpowiada za nie też pochodzenie samego buildu:

{{< readme-check 4 >}}

## Podpis

Programy na Windows i macOS są podpisywane po buildzie, więc ich bajty nie są już bajtami buildu, a drugie polecenie celowo nic dla nich nie znajduje. Odpowiada za nie podpis: Windows sprawdza go przy uruchomieniu programu, a na macOS `spctl -a -vv certdoctor.app` - albo `certdoctor-gui.app` - pyta Gatekeepera.
