---
title: Proxy and PAC script
seoTitle: Which proxy does this URL use? Proxy and PAC diagnosis
description: "How Cert Doctor finds which proxy a URL really goes through: environment variables, Windows Internet and WinHTTP settings, the PAC script, and 407 checks."
lead: "On one machine the proxy is decided in several places at once, and different programs listen to different ones."
---

## Where the proxy is decided

The proxy layer, `L2`, reads every place that can name a proxy and shows them side by side:

- **the environment variables** - `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY` and `NO_PROXY`, each in both spellings, which command-line tools and most runtimes follow,
- **the Windows Internet Settings** - what Edge, Chrome and .NET programs follow, including the address of a PAC script,
- **the WinHTTP settings** - what Windows services follow, which are set apart from the ones above and often differ from them.

When these disagree, the report says which program follows which, so a browser that connects and a service that does not stop being a mystery.

## The PAC script

A proxy auto-configuration script is a small JavaScript program that decides, URL by URL, which proxy to use. Many companies send one host past the proxy everything else goes through, and the only way to know what a script does for your URL is to run it.

Cert Doctor fetches the script your machine names and runs it in a sandbox to see where it sends this URL. The answer is reported for the script itself, not for the setting that named it, so two settings naming two scripts that disagree are both shown.

A script that answers nothing usable is reported as `UNKNOWN`, never as a direct connection: guessing "no proxy" would send you looking in the wrong place.

## A PAC script your machine does not name

`--pac-url` asks about a script by its address, whether or not anything on the machine names it. On Linux, where there is no system-wide PAC setting, this is the way to ask:

```
certdoctor https://api.example.com/ --pac-url http://wpad.example.com/proxy.pac
```

## Does the proxy want credentials

When a proxy applies, Cert Doctor asks it whether it accepts the connection without credentials. A proxy that answers `407 Proxy Authentication Required` is named, with the authentication schemes it offers. [407 Proxy Authentication Required](/errors/407-proxy-authentication-required/) says what to do about it.

## Passwords in proxy addresses

A proxy address can carry a user name and a password, as in `http://user:secret@proxy:8080`. The password is cut off where the address is read, so it never reaches a report or a log, with or without `--redact`.
