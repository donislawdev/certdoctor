---
title: The NO_PROXY variable in each program
linkTitle: NO_PROXY tester
seoTitle: "NO_PROXY environment variable: wildcard, CIDR, localhost"
description: "How curl, Go, Python, requests, Node.js and .NET read NO_PROXY: leading dots, wildcards, IP ranges, ports and localhost, and a tester that shows each answer."
lead: "NO_PROXY lists the hosts a program reaches without the proxy. Every program reads the list its own way, so one line can send curl direct and Go through the proxy."
---

## What NO_PROXY does

`HTTPS_PROXY` and `HTTP_PROXY` name the proxy a program uses, and `NO_PROXY` - or `no_proxy` - lists the hosts it reaches directly instead, separated by commas. Only a program that takes its proxy from these variables reads it:

- curl and git, Go, Python's `urllib`, `requests` and `pip`, and .NET read it ([curl](https://curl.se/docs/manpage.html#--noproxy), [Go](https://pkg.go.dev/golang.org/x/net/http/httpproxy), [Python](https://docs.python.org/3/library/urllib.request.html#urllib.request.getproxies), [.NET](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httpclient.defaultproxy)),
- Node.js reads it only when `NODE_USE_ENV_PROXY=1` is set or it is started with `--use-env-proxy` ([Node.js](https://nodejs.org/api/cli.html#node_use_env_proxy1)),
- Java does not read it at all: a JVM takes its exceptions from the `http.nonProxyHosts` property ([Java networking properties](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/doc-files/net-properties.html)).

A program given no proxy goes directly whatever the list says.

## How to set it

On Linux and macOS, for the shell and the programs it starts:

```
export NO_PROXY=localhost,127.0.0.1,.example.com
```

In PowerShell, for this session:

```
$env:NO_PROXY = "localhost,127.0.0.1,.example.com"
```

On Windows, for your account from now on - a program already running keeps the value it started with ([setx](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/setx)):

```
setx NO_PROXY "localhost,127.0.0.1,.example.com"
```

## What each program does with each entry

Every row is one entry and one address, and every cell is what that program does - go **direct**, or through the **proxy**. The answers are those of the NO_PROXY tester in Cert Doctor {{< version >}}, which follows each program's rules as its source code has them and was checked against the programs themselves. Where a program changed its rules, the cell names the releases that go each way.

{{< noproxy-table >}}

## Leading dot: .example.com

`.example.com` covers every name under `example.com`, in every program. Whether it also covers `example.com` itself differs: curl, .NET, Python, `requests` and Node.js `http` say yes, Go says no, and Node.js `fetch` changed its answer between releases. To cover both in every program, list both: `example.com,.example.com`.

Without the dot, `example.com` covers `example.com` itself everywhere, and the names under it in curl, Go, Python and `requests` - but not in .NET or Node.js `http`.

## Wildcard: *.example.com and *

`*.example.com` is a pattern only in Go and Node.js. curl, .NET, Python and `requests` do not read the star as a wildcard, so they send `api.example.com` through the proxy. A leading dot, `.example.com`, does in every program what most people mean by the star.

`*` on its own, as the whole value, turns the proxy off for every host in every program but .NET, which does not read it that way. A star anywhere else, like `10.*`, covers nothing in any of them.

## IP ranges and CIDR: 10.0.0.0/8

A range in CIDR form covers the addresses in it in curl, Go, `requests` and .NET from release 11 on. Python's `urllib`, Node.js and .NET 10 and earlier do not read ranges, so for them `10.0.0.0/8` covers no address at all - list each address those programs reach.

## localhost, 127.0.0.1 and ::1

`localhost` and `127.0.0.1` are not the same entry: each covers only itself. Go is the exception - it never sends `localhost` or a loopback address to a proxy, whatever the list says, and even when there is no list. Every other program sends a request for `localhost` to the proxy unless the list names it.

The IPv6 loopback is written two ways, and the programs disagree on which: `::1` covers `[::1]` in curl, `requests` and Node.js `http`, and `[::1]` covers it in .NET and Python. For a local service, list every form you use: `localhost,127.0.0.1,::1,[::1]`.

## Ports: example.com:8443

An entry with a port covers that host on that port only, in Go, Python, `requests` and Node.js. curl and .NET do not match an entry that carries a port, so they send `example.com:8443` through the proxy.

## Test your own list

```
certdoctor tool noproxy
```

Paste the list, press Enter, then the address and Enter. The address is a URL, or a host with its port, and without a scheme it is read as `https://`. `NO_PROXY=` in front of the list is taken off. An empty list is a question too: it shows what each program does when `NO_PROXY` is empty or not set.

From the variable itself, on Linux and macOS:

```
printf '%s\n%s\n' "$NO_PROXY" https://api.example.com | certdoctor tool noproxy
```

A real run on 2026-11-18, for `.example.com,localhost` and `https://example.com/`:

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

The tester connects to nothing and reads no environment: the list and the address are the ones you give it. To see the proxy each program on this machine really uses for a URL - from the variables, the system settings and a PAC script - run the diagnosis, `certdoctor https://api.example.com/` ([proxy and PAC](/docs/proxy-and-pac/)).

## In the window

Open **Tools** on the window's bar, choose **NO_PROXY tester**, paste the list and the address, and press **Test**.

## Options

{{< tool-options "noproxy" >}}

`certdoctor tool noproxy --help` prints the same in the terminal.

## Exit codes

{{< tool-exit-codes >}}
