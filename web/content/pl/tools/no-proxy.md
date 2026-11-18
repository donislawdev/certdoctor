---
title: Zmienna NO_PROXY w każdym programie
linkTitle: Tester NO_PROXY
slug: no-proxy
seoTitle: "Zmienna NO_PROXY: wildcard, CIDR i localhost w programach"
description: "Jak curl, Go, Python, requests, Node.js i .NET czytają NO_PROXY: kropka na początku, gwiazdka, zakresy IP, porty i localhost, oraz tester, który to pokazuje."
lead: "NO_PROXY wymienia hosty, do których program idzie bez proxy. Każdy program czyta tę listę po swojemu, więc jedna linia może wysłać curla bezpośrednio, a Go przez proxy."
---

## Co robi NO_PROXY

`HTTPS_PROXY` i `HTTP_PROXY` wskazują proxy, którego używa program, a `NO_PROXY` - albo `no_proxy` - wymienia, rozdzielone przecinkami, hosty, do których idzie zamiast tego bezpośrednio. Czyta ją tylko program, który bierze proxy z tych zmiennych:

- curl i git, Go, `urllib` Pythona, `requests` i `pip` oraz .NET czytają ją ([curl](https://curl.se/docs/manpage.html#--noproxy), [Go](https://pkg.go.dev/golang.org/x/net/http/httpproxy), [Python](https://docs.python.org/3/library/urllib.request.html#urllib.request.getproxies), [.NET](https://learn.microsoft.com/pl-pl/dotnet/api/system.net.http.httpclient.defaultproxy)),
- Node.js czyta ją tylko wtedy, gdy ustawiono `NODE_USE_ENV_PROXY=1` albo uruchomiono go z `--use-env-proxy` ([Node.js](https://nodejs.org/api/cli.html#node_use_env_proxy1)),
- Java nie czyta jej wcale: JVM bierze wyjątki z właściwości `http.nonProxyHosts` ([właściwości sieciowe Javy](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/doc-files/net-properties.html)).

Program, któremu nie podano żadnego proxy, idzie bezpośrednio, cokolwiek mówi lista.

## Jak ją ustawić

Na Linuksie i macOS, dla powłoki i programów, które z niej uruchomisz:

```
export NO_PROXY=localhost,127.0.0.1,.example.com
```

W PowerShell, na tę sesję:

```
$env:NO_PROXY = "localhost,127.0.0.1,.example.com"
```

Na Windowsie, dla twojego konta na stałe - program, który już działa, zostaje przy wartości, z którą wystartował ([setx](https://learn.microsoft.com/pl-pl/windows-server/administration/windows-commands/setx)):

```
setx NO_PROXY "localhost,127.0.0.1,.example.com"
```

## Co każdy program robi z każdym wpisem

Każdy wiersz to jeden wpis i jeden adres, a każda komórka to to, co robi dany program - idzie **bezpośrednio** albo **przez proxy**. Odpowiedzi pochodzą z testera NO_PROXY w Cert Doctorze {{< version >}}, który stosuje reguły każdego programu tak, jak zapisano je w jego kodzie źródłowym, i który sprawdzono na samych programach. Gdy program zmieniał swoje reguły, komórka wymienia wydania, które idą w każdą stronę.

{{< noproxy-table >}}

## Kropka na początku: .example.com

`.example.com` obejmuje każdą nazwę pod `example.com`, w każdym programie. To, czy obejmuje też samo `example.com`, już się różni: curl, .NET, Python, `requests` i `http` Node.js mówią tak, Go mówi nie, a `fetch` Node.js zmieniał odpowiedź między wydaniami. Żeby objąć obie w każdym programie, wpisz obie: `example.com,.example.com`.

Bez kropki `example.com` obejmuje samo `example.com` wszędzie, a nazwy pod nim w curlu, Go, Pythonie i `requests` - ale nie w .NET ani w `http` Node.js.

## Gwiazdka: *.example.com i *

`*.example.com` jest wzorcem tylko w Go i Node.js. curl, .NET, Python i `requests` nie czytają gwiazdki jako symbolu wieloznacznego, więc wysyłają `api.example.com` przez proxy. Kropka na początku, `.example.com`, robi w każdym programie to, co zwykle ma się na myśli, pisząc gwiazdkę.

Sama `*`, jako cała wartość, wyłącza proxy dla każdego hosta w każdym programie oprócz .NET, który tak jej nie czyta. Gwiazdka gdziekolwiek indziej, jak w `10.*`, nie obejmuje niczego w żadnym z nich.

## Zakresy IP i CIDR: 10.0.0.0/8

Zakres w postaci CIDR obejmuje adresy w nim w curlu, Go, `requests` i .NET od wydania 11. `urllib` Pythona, Node.js oraz .NET 10 i starsze nie czytają zakresów, więc dla nich `10.0.0.0/8` nie obejmuje żadnego adresu - wpisz każdy adres, do którego te programy się łączą.

## localhost, 127.0.0.1 i ::1

`localhost` i `127.0.0.1` to nie ten sam wpis: każdy obejmuje tylko siebie. Wyjątkiem jest Go - nigdy nie wysyła `localhost` ani adresu pętli zwrotnej do proxy, cokolwiek mówi lista, a nawet gdy listy nie ma. Każdy inny program wysyła żądanie do `localhost` przez proxy, chyba że lista go wymienia.

Adres pętli zwrotnej IPv6 zapisuje się na dwa sposoby, a programy nie zgadzają się, który czytają: `::1` obejmuje `[::1]` w curlu, `requests` i `http` Node.js, a `[::1]` w .NET i Pythonie. Dla usługi lokalnej wpisz każdą postać, której używasz: `localhost,127.0.0.1,::1,[::1]`.

## Porty: example.com:8443

Wpis z portem obejmuje ten host tylko na tym porcie, w Go, Pythonie, `requests` i Node.js. curl i .NET nie dopasowują wpisu z portem, więc wysyłają `example.com:8443` przez proxy.

## Sprawdź własną listę

```
certdoctor tool noproxy
```

Wklej listę, naciśnij Enter, potem adres i Enter. Adres to URL albo host z portem, a bez schematu jest czytany jako `https://`. `NO_PROXY=` przed listą jest zdejmowane. Pusta lista też jest pytaniem: pokazuje, co robi każdy program, gdy `NO_PROXY` jest puste albo nieustawione.

Prosto ze zmiennej, na Linuksie i macOS:

```
printf '%s\n%s\n' "$NO_PROXY" https://api.example.com | certdoctor tool noproxy
```

Prawdziwy przebieg z 2026-11-18, dla `.example.com,localhost` i `https://example.com/`:

```
certdoctor 0.3.0   tool noproxy - NO_PROXY tester
judged at 2026-11-18T16:18:27Z

CHECKS
  ! WARN  The programs disagree about example.com: 5 of the 7 go to it directly, 1 through the proxy
          and for 1 it depends on the release.

ADDRESS
  Scheme  https
  Host    example.com
  Port    443          the https default - the address names none

DIRECTLY, WITHOUT THE PROXY
  curl and git            entry ".example.com"  8.23.0
  .NET                    entry ".example.com"  10 and earlier
  .NET                    entry ".example.com"  11 and later
  Python urllib           entry ".example.com"  3.10 and later
  ...

THROUGH THE PROXY
  Go             no entry applies  1.27
  Node.js fetch  no entry applies  22.21 and later 22, 24.0 to 24.14.0, only with
                                   NODE_USE_ENV_PROXY=1
```

Tester z niczym się nie łączy i nie czyta środowiska: lista i adres są tymi, które mu podasz. Żeby zobaczyć, którego proxy każdy program na tym komputerze naprawdę używa dla danego URL-a - ze zmiennych, z ustawień systemu i ze skryptu PAC - uruchom diagnozę, `certdoctor https://api.example.com/` ([proxy i PAC](/docs/proxy-and-pac/)).

## W oknie

Otwórz **Tools** na pasku okna, wybierz **NO_PROXY tester**, wklej listę i adres i naciśnij **Test**.

## Przełączniki

{{< tool-options "noproxy" >}}

`certdoctor tool noproxy --help` wypisuje to samo w terminalu.

## Kody wyjścia

{{< tool-exit-codes >}}
