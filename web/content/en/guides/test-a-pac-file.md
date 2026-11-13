---
title: Test a PAC file
seoTitle: Test a PAC file - which proxy does it pick for a URL
description: "Find which proxy a PAC script picks for a URL, run the script your machine uses or any script by its address, and compare it with the other proxy settings."
lead: "A PAC script decides, URL by URL, which proxy to use. The only way to know what it does for your URL is to run it."
---

## What a PAC script is

A proxy auto-configuration file is a JavaScript function, `FindProxyForURL(url, host)`, that returns `DIRECT` or a list of proxies for each URL ([MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Proxy_servers_and_tunneling/Proxy_Auto-Configuration_PAC_file)). Companies use one to send internal hosts around the proxy and everything else through it. Browsers and many Windows programs follow the script the machine names. Command-line tools usually do not, and read proxy variables instead - one reason the browser and a script disagree.

## Run the script your machine uses

```
certdoctor https://api.example.com/
```

`L2` finds the script your machine names, fetches it, runs it in a sandbox for this URL, and shows its answer next to every other place that names a proxy: the environment variables, the Windows Internet Settings and the WinHTTP settings. When they disagree, you see which program follows which.

## Run any script by its address

```
certdoctor https://api.example.com/ --pac-url http://wpad.example.com/proxy.pac
```

`--pac-url` asks about a script whether or not anything on the machine names it. On Linux, where there is no system-wide PAC setting, it is the way to ask. Run it once per URL you care about: a script often sends different hosts different ways.

## What the answer means

- **A proxy** - this URL goes through it. Cert Doctor then asks the proxy whether it wants credentials, and names a [407](/errors/407-proxy-authentication-required/).
- **`DIRECT`** - this URL goes straight to the server.
- **No usable answer** - reported as `UNKNOWN` with the reason, never as `DIRECT`, because guessing "no proxy" would send you looking in the wrong place.
