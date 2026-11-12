---
title: Pytania
slug: pytania
seoTitle: certdoctor FAQ - błędy certyfikatów, proxy, magazyny
description: "Odpowiedzi o certdoctor: co robi, czym różni się od openssl s_client i curl -v, czy cokolwiek zmienia, czy wymaga uprawnień administratora i więcej."
lead: "Pytania, które ludzie zadają najpierw, z odpowiedzią w pierwszym zdaniu."
layout: faq
faq:
  - question: Co to jest certdoctor?
    answer: "Narzędzie GUI/CLI, które ustala, dlaczego ta maszyna nie łączy się z adresem i co uruchomić, żeby to naprawić. Przechodzi DNS, proxy i skrypt PAC, TCP i TLS, a potem pyta każdy magazyn zaufania na maszynie, czy ufa łańcuchowi certyfikatów serwera, i wypisuje polecenie, które naprawia każdy magazyn, który nie ufa."
  - question: Dlaczego przeglądarka się łączy, a Java, git albo Python nie?
    answer: "Bo każde z nich ufa innej liście. Przeglądarka na Windowsie czyta magazyn Windows, Java czyta `cacerts` własnej instalacji, Git for Windows czyta własny pakiet, a Python listę, z którą go skonfigurowano. Firmowy certyfikat główny dodany do jednej z nich nie trafia do pozostałych. [Macierz zaufania](/docs/trust-matrix/) pokazuje, która lista odmawia."
  - question: Dlaczego nie wystarczy openssl s_client albo curl -v?
    answer: "Oba odpowiadają za siebie. `openssl s_client` mówi, co myśli magazyn OpenSSL, a usługa w Javie, która pada, z tego magazynu nie korzysta. certdoctor zadaje każdemu znalezionemu magazynowi to samo pytanie o ten sam łańcuch, a odpowiedź zwykle brzmi: nie zgadzają się."
  - question: Czy zmienia cokolwiek na mojej maszynie?
    answer: "Nie. Czyta, łączy się tam, gdzie go skierujesz, i zapisuje jeden raport, jeśli poprosisz o niego przez `--out`. Polecenia, które wypisuje, są do uruchomienia przez ciebie, po przeczytaniu. Szczegóły na stronie [bezpieczeństwo i prywatność](/security/)."
  - question: Czy wymaga uprawnień administratora?
    answer: "Nie. Działa jako ten, kto go uruchomił, a raport zapisuje, z jakimi uprawnieniami działał. Wypisana naprawa mówi, kiedy jej uruchomienie wymaga uprawnień administratora albo roota."
  - question: Czy powie mi, że firma przechwytuje mój ruch?
    answer: "Mówi, kto podpisał certyfikat i ile magazynów na twojej maszynie ufa temu urzędowi, a nazywa produkt do inspekcji, gdy certyfikat mówi o nim tak, jak publikuje to producent. Z jednego połączenia proxy z inspekcją i własny urząd certyfikacji firmy wyglądają tak samo, więc nigdy nikogo nie oskarża na podstawie domysłu. Jak to czytać, mówi strona [inspekcja TLS](/guides/tls-inspection-corporate-proxy/)."
  - question: Czy potrafi powiedzieć, że winny jest serwer?
    answer: "Tak. Serwer, który nie wysyła certyfikatu pośredniego, certyfikat, który nie obejmuje nazwy, i certyfikat po terminie ważności są wskazane jako fakty o serwerze, z dowodami do wklejenia w zgłoszenie."
  - question: Czy działa w kontenerze Docker?
    answer: "Tak. Skopiuj statyczną binarkę na Linuksa do kontenera i uruchom ją tam, a raport opisze kontener, a nie hosta. Jak, pokazuje strona [w kontenerze](/docs/containers/)."
  - question: Czy mogę go użyć w CI?
    answer: "Tak. Każde zakończenie ma własny kod wyjścia, a `--json` zapisuje raport sprawdzony ze schematem. Krok pokazuje strona [użycie w CI](/docs/ci/)."
  - question: Czy raport można bezpiecznie udostępnić?
    answer: "Najpierw go przeczytaj. Raport zawiera wewnętrzne nazwy hostów, ścieżki i nazwy użytkowników, a `--redact` je maskuje. Poświadczenia są maskowane zawsze. Maskowanie to filtr, a nie gwarancja."
  - question: Czy jest darmowy? Czy mogę go używać w pracy?
    answer: "Tak i tak. Jest na licencji GPL-3.0 i nic nie kosztuje. Raporty, które tworzysz, należą do ciebie."
  - question: Na jakich systemach działa?
    answer: "Wiersz poleceń działa na Windowsie i Linuksie na x64 i Arm oraz na macOS na Apple silicon. Okno działa na Windowsie i Linuksie na x64 oraz na macOS na Apple silicon. Każde archiwum jest na stronie [pobierz](/download/)."
  - question: Źle ocenił mój przypadek. Co teraz?
    answer: "To najbardziej przydatne zgłoszenie, jakie możesz otworzyć. Załącz raport zrobiony z `--redact --json`, napisz, jaka była poprawna odpowiedź, i wskaż środowisko, które się nie zgadzało, na [liście zgłoszeń](https://github.com/donislawdev/certdoctor/issues)."
---
