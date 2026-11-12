---
title: unable to get local issuer certificate
codeTitle: true
seoTitle: "unable to get local issuer certificate: the fix"
description: "SSL certificate problem: unable to get local issuer certificate in curl, git, Python, pip and Node: what it means and how to fix the right trust store."
lead: "The program found no authority it trusts to vouch for the server's certificate. The fix is in that program's own list, and each program keeps a different one."
messages:
  - from: curl
    text: "curl: (60) SSL certificate problem: unable to get local issuer certificate"
  - from: git
    text: "fatal: unable to access 'https://...': SSL certificate problem: unable to get local issuer certificate"
  - from: Python, pip
    text: "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate"
  - from: Node.js
    text: "Error: unable to get local issuer certificate (UNABLE_TO_GET_ISSUER_CERT_LOCALLY)"
---

## What it means

The program received the server's certificate and looked for the certificate of whoever issued it - first among what the server sent, then in its local trust store. It found neither. "Local" means this program's own list of authorities, which is not necessarily the one your browser uses.

The message comes from OpenSSL and the libraries built like it, which is why curl, git, Python, pip and Node.js all print it.

## Common causes

- **A company root missing from this program's list.** A TLS inspection proxy or your company's own authority signs the connection, and IT added its root to the system store. curl on Windows may trust it, while Git for Windows, Python and Node.js read lists of their own that do not have it.
- **The server does not send its intermediate certificate.** A browser hides this by remembering the intermediate from another site. Every other client fails. [Missing intermediate certificate](/errors/missing-intermediate-certificate/) covers it.
- **An outdated or replaced CA bundle.** A program pointed at another file, through `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE` or `GIT_SSL_CAINFO`, trusts that file and nothing else.

## Find which one is yours

```
certdoctor https://the-url-that-fails/
```

`L0` shows which of those variables are set. `L4` shows whether the server sent its whole chain. The trust matrix shows every git, curl, Python, pip and node on the machine, which list each one reads, which of them refuse, and the command that adds the root to each.

If the verdict says the server did not send the issuer of its certificate, the fix belongs on the server, and certdoctor says so: *"this is a fact about the server rather than about this machine."*

## Fix it

Add the root to the list the failing program reads, with the command its row prints:

- git - [Git and SSL certificates](/guides/git-ssl-certificate/)
- curl - [curl and its CA bundle](/guides/curl-ca-bundle/)
- Python and pip - [Python and pip certificates](/guides/python-pip-certificates/)
- Node.js and npm - [NODE_EXTRA_CA_CERTS](/guides/node-extra-ca-certs/)

If the root is your company's, [TLS inspection](/guides/tls-inspection-corporate-proxy/) says how to get the right certificate.

## What not to do

`git config http.sslVerify false`, `curl -k`, `verify=False` and `NODE_TLS_REJECT_UNAUTHORIZED=0` make the error go away by accepting any certificate from anyone. They hide the problem rather than fix it, and they stay set long after everybody has forgotten why.
