---
title: 407 Proxy Authentication Required
codeTitle: true
seoTitle: "407 Proxy Authentication Required: which proxy, why"
description: "407 Proxy Authentication Required in curl, git, npm, pip and Java: find which proxy your URL really goes through and which credentials it wants."
lead: "A proxy stands between you and the server, and it wants to know who is asking. First find out which proxy, and what it accepts."
messages:
  - from: curl, git
    text: "CONNECT tunnel failed, response 407"
  - from: Java
    text: "Unable to tunnel through proxy. Proxy returns \"HTTP/1.1 407 Proxy Authentication Required\""
  - from: npm, pip
    text: "407 Proxy Authentication Required"
---

## What it means

The program sent its request through a proxy, and the proxy refused to pass it on without credentials. The server was never reached, so this says nothing about the server or its certificate.

## Common causes

- **The program uses a proxy you did not expect.** A variable such as `HTTPS_PROXY` or a PAC script sends this URL through a proxy that a browser passes with your Windows sign-in, and this program cannot.
- **The proxy wants a sign-in the program cannot give.** Many company proxies accept Negotiate or NTLM, which a browser does with your Windows account and a command-line tool usually does not.
- **Credentials in the proxy address are wrong or out of date.**

## Find which proxy, and what it wants

```
certdoctor https://the-url-that-fails/
```

`L2` shows every place on the machine that names a proxy - the environment variables, the Windows Internet Settings, the WinHTTP settings and the PAC script - and which one applies to this URL. Then Cert Doctor asks that proxy whether it accepts the connection without credentials, and when it answers `407`, the report names the authentication schemes it offers.

Passwords written into proxy addresses never reach the report: they are cut off where the address is read.

## Fix it

- If the URL should not go through the proxy at all, add its host to `NO_PROXY` for that program, or ask whoever owns the PAC script.
- If the proxy accepts Basic authentication, the program can carry a user name and password in its proxy address.
- If it offers only Negotiate or NTLM, ask whether the proxy can let that program through without a sign-in, or use a program that can sign in with those schemes.

[Proxy and PAC script](/docs/proxy-and-pac/) says more about how the proxy is decided.
