---
title: PKIX path building failed
codeTitle: true
seoTitle: "PKIX path building failed: causes and the fix"
description: "Java's PKIX path building failed and unable to find valid certification path to requested target: why one JDK refuses, and the keytool command that fixes it."
lead: "Java could not build a chain from the server's certificate to an authority in its own `cacerts`. The question is which Java, and why its `cacerts` lacks what the system has."
messages:
  - from: Java
    text: "javax.net.ssl.SSLHandshakeException: PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target"
  - from: Maven, Gradle
    text: "PKIX path building failed: unable to find valid certification path to requested target"
---

## What it means

Every Java installation carries its own list of trusted authorities, the `cacerts` file in its `lib/security` folder. Java reads that file, not the Windows certificate store, and a JDK you unpacked yourself does not follow the Linux CA bundle either. When the server's chain does not lead to an authority in that file, Java refuses the connection with this message. Maven, Gradle, Jenkins, IntelliJ and every other program running on that JDK show it in their own words around it.

## Common causes

- **A company root that never reached Java.** Your company or its TLS inspection proxy signs connections with its own authority, which IT added to the system store. Browsers and curl trust it, and the JDK does not.
- **The wrong JDK was fixed.** A machine often has several JDKs and JREs - one for the IDE, one for the build, one bundled with a tool. The certificate went into one `cacerts`, and the program that fails runs on another.
- **A JDK update brought a fresh `cacerts`.** A newer build does not carry certificates you added to the old one.
- **The server does not send its intermediate certificate.** Then no client can build the chain without help, and the fault is the server's. [Missing intermediate certificate](/errors/missing-intermediate-certificate/) covers it.

## Find which one is yours

```
certdoctor https://the-url-that-fails/
```

The trust matrix has one row for every JDK and JRE certdoctor finds, each with its own `cacerts`. It shows which of them refuse the chain while the system store accepts it, who signed the certificate, and, for each refusing JDK, the exact `keytool` command with that installation's paths:

```
      java C:\Program Files\OpenJDK\jdk-21.0.2 does NOT trust the presented chain (106
        anchors)  detected
        run: "C:\Program Files\OpenJDK\jdk-21.0.2\bin\keytool" -importcert -trustcacerts -keystore "C:\Program Files\OpenJDK\jdk-21.0.2\lib\security\cacerts" -storepass changeit -alias "<alias>" -file "<certificate.pem>"
```

If the verdict instead says the server did not send the issuer of its certificate, the fix belongs on the server.

## Fix it

Import the missing root into the `cacerts` of the JDK that fails, with that JDK's own `keytool`, as the row prints it. Replace `<alias>` with a name for the entry and `<certificate.pem>` with the file holding the root. [Add a certificate to Java cacerts](/guides/java-cacerts-keytool/) goes through it, including where to get the certificate.

Then run certdoctor again: the row turns to trusted, and the other JDKs show whether they need the same.

## What not to do

Do not turn off certificate checks in the application or set a trust manager that accepts everything. That makes the error go away by accepting any certificate from anyone, including one an attacker presents.
