---
title: Python and pip certificates
seoTitle: "pip and Python CERTIFICATE_VERIFY_FAILED: the right fix"
description: "Fix pip and Python CERTIFICATE_VERIFY_FAILED: which list each Python and pip trusts, certifi, truststore from pip 24.2, REQUESTS_CA_BUNDLE, PIP_CERT."
lead: "Python's `ssl` module, `requests` and pip can each trust a different list. Find the one the failing program reads before you change anything."
---

## Which list Python reads

Python's `ssl` module trusts what its OpenSSL was set up to read. On Linux that is usually the distribution's bundle, on Windows it is the Windows certificate store, which Python reads each time a program makes a default TLS context ([ssl documentation](https://docs.python.org/3/library/ssl.html#ssl.SSLContext.load_default_certs)). `SSL_CERT_FILE` points it at another file.

## Which list pip reads

pip has its own rule ([pip documentation](https://pip.pypa.io/en/stable/topics/https-certificates/)):

- **from pip 24.2**, pip uses `truststore`, which asks the operating system's own store - a company root IT put in the Windows store reaches pip,
- **before 24.2**, or with `--use-deprecated=legacy-certs`, pip trusts one file: the `certifi` bundle it ships, or the file named by `PIP_CERT`, its `cert` setting or `REQUESTS_CA_BUNDLE`.

A file named that way replaces certifi's list rather than adding to it.

## See what each Python and pip trusts

```
certdoctor https://pypi.org/
```

Every Python on PATH gets a `python` row, judged by the list its `ssl` module trusts, and every Python's pip gets a `pip` row, judged by pip's own rule: `truststore` or `certifi`, and the file named for it. `L0` shows whether `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` or `PIP_CERT` is set.

## Add the root

The command depends on the row:

- **Python on Windows**: this account's Windows store, `certutil -user -addstore Root "<certificate.pem>"`. Windows asks you to confirm, and every Python started afterwards reads it.
- **Python or pip reading a file**: an append of the root to that file, as the row prints it. Every program reading the same file trusts the certificate too, and the tool that maintains the file - `update-ca-certificates`, `update-ca-trust` - can rewrite it and drop the append. [The Linux CA bundle](/guides/linux-ca-bundle/) says how to make it last.
- **pip on certifi alone, with nothing named**: no command, and the row says why - naming a file would replace certifi's list. A pip from 24.2 on reads the system's store instead.

## Python 3.13

Python 3.13 also refuses certificates that break OpenSSL's strict rules. When the row names a rule rather than an unknown authority, [Python 3.13 certificate verify failed](/errors/python-3-13-strict-certificate-checks/) applies.

## What not to do

`verify=False` in `requests` and `--trusted-host` in pip skip verification for those connections. They hide the problem rather than fix it.
