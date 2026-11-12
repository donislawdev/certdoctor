---
title: Add a certificate to Java cacerts with keytool
linkTitle: Java cacerts and keytool
seoTitle: "Java cacerts: import a certificate with keytool"
description: "Import a company root into Java cacerts with keytool, find every JDK and JRE on the machine, and see which still refuse, with the command for each."
lead: "Every JDK and JRE has its own `cacerts`. The one that matters is the one the failing program runs on, and a machine usually has more than one."
---

## Where Java keeps its list

Each Java installation has a `cacerts` file in its `lib/security` folder - `C:\Program Files\OpenJDK\jdk-21.0.2\lib\security\cacerts`, `/usr/lib/jvm/java-21-openjdk/lib/security/cacerts` - and trusts the authorities in it. Its default password is `changeit`, which is published, not a secret. A program that fails with [PKIX path building failed](/errors/pkix-path-building-failed/) is missing an authority in the `cacerts` of the Java it runs on.

## Find every Java on the machine

```
certdoctor https://the-url-that-fails/
```

The trust matrix has one `java` row for every JDK and JRE it finds, each with its own `cacerts` and the number of anchors in it. The rows that refuse carry the command for that installation:

```
      java C:\Program Files\OpenJDK\jdk-21.0.2 does NOT trust the presented chain (106
        anchors)  detected
        needs elevated rights: this store is outside this account's own files, so it belongs to
                               every account on the machine
        run: "C:\Program Files\OpenJDK\jdk-21.0.2\bin\keytool" -importcert -trustcacerts -keystore "C:\Program Files\OpenJDK\jdk-21.0.2\lib\security\cacerts" -storepass changeit -alias "<alias>" -file "<certificate.pem>"
        replace first: <alias>, <certificate.pem>
```

## Import the certificate

The command uses the `keytool` of the same installation as the `cacerts` it changes, so a newer or older `keytool` does not rewrite the file in its own format. Before you run it:

1. Save the root certificate to a file. [TLS inspection](/guides/tls-inspection-corporate-proxy/) says how to get it.
2. Replace `<certificate.pem>` with that file's full path and `<alias>` with a name for the entry, such as `company-root`.
3. Run it in a terminal with administrator rights when the row says it needs them, as it does for a JDK under `Program Files` or `/usr/lib/jvm`.

On Windows the command is written for the Command Prompt (`cmd.exe`). In PowerShell, put `&` and a space in front of it.

`keytool -importcert` adds one entry and leaves the rest of the file as it was ([keytool documentation](https://docs.oracle.com/en/java/javase/21/docs/specs/man/keytool.html)). Run certdoctor again afterwards: the row turns to trusted.

## When it comes back

A JDK update installs a new `cacerts` and does not carry your certificate across, and every row says so. After an update, run certdoctor again and import into the new installation.

## Other JDKs that need it too

The matrix lists every Java it finds, so you see at once which other installations - the IDE's bundled runtime, an old JRE a tool still uses - need the same import.
