---
title: Okno
slug: okno
seoTitle: certdoctor-gui - diagnoza certyfikatów w oknie
description: "certdoctor-gui pokazuje ten sam raport w oknie na Windowsie, Linuksie i macOS: wpisz adres, naciśnij Diagnose, przeczytaj raport i zapisz go."
lead: "Ta sama diagnoza bez terminala, dla każdego, kto woli wpisać adres w pole."
---

## Co robi

Wpisz adres, który nie działa, naciśnij **Diagnose** i przeczytaj raport: zdanie z przyczyną na górze, warstwy po lewej, dowody każdej z nich obok. Zapisz raport jako HTML, Markdown albo JSON do zgłoszenia.

Okno uruchamia wiersz poleceń, który leży obok niego, i pokazuje to, co on zgłasza, więc nie wie niczego, czego nie wie wiersz poleceń, i oba nigdy się nie różnią. Opcje, które oferuje, to flagi wiersza poleceń.

## Gdzie działa

{{< downloads "certdoctor-gui" >}}

Każde archiwum zawiera też wiersz poleceń. [Strona pobierania](/download/) ma je wszystkie.

## Trzymaj jego pliki razem

Okno uruchamia `certdoctor`, który leży obok niego, więc trzymaj pliki archiwum w jednym folderze.

Na Windowsie folder `opengl` zawiera renderer programowy. Na maszynie, której sterownik grafiki nie oferuje OpenGL 2.1 - na maszynie wirtualnej bez akceleracji 3D albo w sesji Pulpitu zdalnego - okno samo uruchamia się z nim ponownie.

Na macOS trzymaj pakiet i dowiązania obok niego razem. Podpis i notaryzacja Apple należą do pakietu, więc program skopiowany z niego osobno nie jest programem, który Apple sprawdził.

Na Linuksie okno potrzebuje sesji pulpitu z OpenGL. Ładuje `libGL.so.1` i `libwayland-client.so.0`, które ma instalacja z pulpitem.

## Co zachowuje

Jedno ustawienie: folder, do którego ostatnio zapisano raport, w `preferences.json` w folderze użytkownika - `AppData\Roaming\fyne\dev.donislaw.certdoctor` na Windowsie, `~/.config/fyne/dev.donislaw.certdoctor` na Linuksie i `~/Library/Preferences/fyne/dev.donislaw.certdoctor` na macOS. Fyne, biblioteka, w której zbudowano okno, tworzy ten folder, gdy okno startuje, a także pusty folder o tej samej nazwie w folderze pamięci podręcznej użytkownika. Usuń oba, gdy usuwasz okno.
