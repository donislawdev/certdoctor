---
title: Git i certyfikaty SSL
slug: git-certyfikat-ssl
seoTitle: "Git SSL certificate problem: dodaj CA do pakietu Gita"
description: "Napraw git SSL certificate problem: unable to get local issuer certificate. Który pakiet CA czyta każdy git, Schannel i polecenie, które dodaje certyfikat."
lead: "Git przez HTTPS ufa pakietowi, z którym go zbudowano albo skonfigurowano. Na Windowsie to często własny pakiet Gita, a nie magazyn Windows."
---

## Którą listę czyta git

Git oddaje HTTPS curlowi i ufa liście, którą dostał curl. Git for Windows ma własny pakiet, `ca-bundle.crt` w swojej instalacji, i czyta go, chyba że `http.sslBackend` jest ustawione na `schannel`, co każe mu używać magazynu Windows ([dokumentacja git-config](https://git-scm.com/docs/git-config#Documentation/git-config.txt-httpsslBackend)). `http.sslCAInfo` w pliku konfiguracji gita albo `GIT_SSL_CAINFO` w środowisku kieruje go na inny plik ([dokumentacja git-config](https://git-scm.com/docs/git-config#Documentation/git-config.txt-httpsslCAInfo)).

Firmowy certyfikat główny w magazynie Windows trafia więc do przeglądarki, a nie do gita, i dlatego git pada z [unable to get local issuer certificate](/errors/unable-to-get-local-issuer-certificate/), podczas gdy przeglądarka się łączy.

## Zobacz, który plik czyta każdy git

```
certdoctor https://git.example.com/
```

Macierz zaufania ma wiersz dla każdego znalezionego `git`, z plikiem, który czyta, tym, czy ten plik ufa łańcuchowi, i poleceniem, które dodaje certyfikat główny:

```
      git C:\Program Files\Git\cmd\git.exe does NOT trust the presented chain (120
        anchors)  detected
        needs elevated rights: this store is outside this account's own files, so it belongs to
                               every account on the machine
        run: cmd /c copy /b "C:\Program Files\Git\ucrt64\etc\ssl\certs\ca-bundle.crt"+"<certificate.pem>" "C:\Program Files\Git\ucrt64\etc\ssl\certs\ca-bundle.crt"
```

`L0` pokazuje, czy ustawiono `GIT_SSL_CAINFO` albo `GIT_SSL_CAPATH`, a wiersz czyta konfigurację gita tak, jak czyta ją git.

## Dodaj certyfikat główny

Polecenie dopisuje certyfikat na koniec pakietu, który czyta git - `cmd /c copy /b` na Windowsie, `cat ... >>` na Linuksie i macOS - i zostawia każdy certyfikat, który już w nim jest. Podstaw za `<certificate.pem>` pełną ścieżkę do certyfikatu głównego w formacie PEM i uruchom polecenie z uprawnieniami administratora, gdy wiersz tak mówi.

Ponowna instalacja albo aktualizacja Gita przepisuje jego pakiet i gubi to, co dopisano, a wiersz też o tym mówi. Na Windowsie drugą drogą jest przełączenie gita na Schannel przez `git config --global http.sslBackend schannel`: git ufa wtedy temu, czemu ufa magazyn Windows, w tym firmowemu certyfikatowi głównemu, który dział IT już tam umieścił.

## Czego nie robić

`git config http.sslVerify false` wyłącza sprawdzanie certyfikatów dla każdego repozytorium, którego dotyczy.
