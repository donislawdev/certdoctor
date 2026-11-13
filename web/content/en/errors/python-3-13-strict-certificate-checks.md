---
title: Python 3.13 certificate verify failed
seoTitle: "Python 3.13: Basic Constraints not marked critical, fix"
description: "Python 3.13 fails with Missing Authority Key Identifier or Basic Constraints of CA cert not marked critical. Which certificate breaks which rule."
lead: "Python 3.13 turned on OpenSSL's strict checks. A company or inspection root that older Pythons accepted can now be refused for how it was made."
messages:
  - from: Python 3.13
    text: "certificate verify failed: Basic Constraints of CA cert not marked critical"
  - from: Python 3.13
    text: "certificate verify failed: Missing Authority Key Identifier"
---

## What it means

From Python 3.13, the default TLS context sets OpenSSL's `VERIFY_X509_STRICT` flag ([Python documentation](https://docs.python.org/3/library/ssl.html#ssl.create_default_context)). With it, OpenSSL refuses certificates that break the rules of the standard even when the chain leads to a trusted root: a CA certificate whose Basic Constraints extension is not marked critical, a certificate without an Authority Key Identifier, and similar.

Public authorities issue certificates that pass. Certificates made by hand, by an old internal authority or by some TLS inspection products may not, so the same URL works in Python 3.12 and fails in 3.13.

## Find which certificate breaks which rule

```
certdoctor https://the-url-that-fails/
```

Every Python on PATH has its own row in the trust matrix. On a Python whose OpenSSL is version 3, Cert Doctor applies the same strict rules to the chain OpenSSL would build, and the row names the certificate and the rule it breaks, instead of a bare refusal. The other rows show whether the same root is trusted by everything else, which is usually the case.

## Fix it

The lasting fix is a certificate that follows the rules: whoever runs the authority reissues it with Basic Constraints marked critical and an Authority Key Identifier. For a company root or an inspection product, that is a request to IT or to the vendor, and the row in the report is the evidence.

Adding the root to Python's trust store does not help when the root is already trusted: the refusal is about how the certificate was made, not about whom Python trusts.

In your own code, while the certificate is being reissued, a context can drop the strict flag for that connection only:

```python
import ssl
context = ssl.create_default_context()
context.verify_flags &= ~ssl.VERIFY_X509_STRICT
```

This keeps every other check, including the chain and the name.
