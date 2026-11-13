---
title: "x509: certificate signed by unknown authority"
codeTitle: true
seoTitle: "x509: certificate signed by unknown authority: naprawa"
description: "x509: certificate signed by unknown authority w programach w Go, Dockerze, kubectl, Terraform i Helm: dlaczego decyduje magazyn systemu i jak to naprawić."
lead: "Programy napisane w Go ufają temu, czemu ufa system operacyjny. Gdy to wypisują, w magazynie systemu - albo w pakiecie w kontenerze - brakuje urzędu."
messages:
  - from: programy w Go
    text: "tls: failed to verify certificate: x509: certificate signed by unknown authority"
  - from: Docker, kubectl, Terraform, Helm
    text: "x509: certificate signed by unknown authority"
---

## Co to znaczy

Biblioteka TLS języka Go weryfikuje łańcuch serwera w magazynie zaufania platformy: w magazynie certyfikatów Windows na Windowsie i w pakiecie certyfikatów CA dystrybucji na Linuksie. Ten komunikat mówi, że łańcuch nie prowadzi do żadnego urzędu z tego magazynu. Docker, kubectl, Terraform, Helm i wiele innych narzędzi jest napisanych w Go, więc wszystkie go wypisują.

## Częste przyczyny

- **Kontener bez firmowego certyfikatu głównego.** Host ufa urzędowi firmy, a własny, często minimalny pakiet certyfikatów obrazu nie.
- **Inspekcja TLS w sieci.** Proxy na nowo podpisuje połączenia certyfikatem głównym, którego nigdy nie dodano do magazynu tej maszyny albo tego obrazu.
- **Wewnętrzny serwer z prywatnym urzędem**, którego certyfikatu głównego ta maszyna nigdy nie dostała.
- **Serwer nie wysyła certyfikatu pośredniego.** Opisuje to strona [brak certyfikatu pośredniego](/errors/missing-intermediate-certificate/).

## Ustal, która dotyczy ciebie

Uruchom Cert Doctor tam, gdzie program pada - na hoście albo w kontenerze:

```
certdoctor https://registry.example.com/
```

Wiersz `system-store` to magazyn platformy, który czyta program w Go. Pokazuje, czy ten magazyn ufa łańcuchowi, kto podpisał certyfikat i polecenie, które dodaje certyfikat główny: `certutil` na Windowsie, dopisanie do pakietu dystrybucji na Linuksie. W kontenerze [skopiuj statyczną binarkę do środka](/docs/containers/), a raport opisze pakiet kontenera, a nie hosta.

## Napraw to

- Windows - [magazyn certyfikatów Windows](/guides/windows-certificate-store/)
- Linux i kontenery - [pakiet CA Linuksa](/guides/linux-ca-bundle/)
- Firmowy certyfikat główny - [inspekcja TLS](/guides/tls-inspection-corporate-proxy/)

`docker pull` to szczególny przypadek: pobiera demon Dockera, a nie kontener, więc certyfikat główny należy do magazynu, który demon czyta na swoim hoście.

## Czego nie robić

Flagi takie jak `--insecure-skip-tls-verify` i `insecure-registries` całkiem przestają sprawdzać certyfikaty dla danego celu. Dodaj zamiast tego certyfikat główny.
