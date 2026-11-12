---
title: W kontenerze
slug: kontenery
seoTitle: Diagnoza błędów certyfikatów w kontenerze Docker
description: "Skopiuj statyczną binarkę na Linuksa do kontenera i uruchom ją tam: raport opisuje wtedy DNS, proxy i magazyny zaufania kontenera, a nie hosta."
lead: "Kontener to osobna maszyna, z własnym resolverem, własnymi zmiennymi proxy i własnym pakietem certyfikatów. Pytaj jego, a nie hosta."
---

## Dlaczego odpowiedź hosta nie jest odpowiedzią kontenera

Obraz ma własny pakiet certyfikatów CA, często starszy albo mniejszy niż hosta, a firmowy certyfikat główny dodany na hoście nigdy do niego nie trafia. Jego zmienne proxy to to, co ustawił obraz albo polecenie uruchomienia, a jego resolver to ten, który dało mu środowisko kontenerów. Dlatego ten sam adres działa na hoście i nie działa w kontenerze.

## Skopiuj i uruchom

Wersja certdoctor na Linuksa to jeden statyczny plik bez zależności od biblioteki C, więc działa bez zmian w Alpine, w Ubuntu i w obrazie, w którym nie ma nic innego:

```
docker cp certdoctor my-container:/tmp/certdoctor
docker exec my-container /tmp/certdoctor https://api.example.com/
```

Raport opisuje wtedy kontener: jego zmienne środowiskowe, jego serwery DNS, jego proxy i każdy magazyn zaufania w środku. `L0` mówi, że działa w kontenerze.

Weź archiwum dla architektury kontenera: `linux_amd64` dla obrazów x64, `linux_arm64` dla obrazów Arm. [Strona pobierania](/download/) ma oba.

## W Dockerfile, podczas budowania

Ta sama binarka może działać na etapie budowania, żeby zobaczyć, dlaczego krok, który coś pobiera, pada:

```
COPY certdoctor /usr/local/bin/certdoctor
RUN certdoctor https://registry.example.com/ || true
```

`|| true` pozwala budowaniu iść dalej, żeby dało się przeczytać raport. Usuń tę linię, gdy przyczyna jest naprawiona.
