---
title: Reading a report
seoTitle: Reading a certdoctor report - verdict, layers, statuses
description: "What each part of a certdoctor report means: the verdict sentence, the exit code, the six layers, the trust matrix rows and the commands they carry."
lead: "The cause first, the numbers after it, the evidence below, and the notes at the end."
---

## The first lines

```
certdoctor 0.1.0   https://untrusted-root.badssl.com/
2026-11-12T08:15:13Z   windows/amd64   privilege: elevated   took 20.46s
```

The version of the tool and the URL, then when the run was made, on which system, with which rights and how long it took. The rights matter because some stores look different to an administrator and to an ordinary account.

## The verdict

```
x CN=BadSSL Untrusted Root Certificate Authority,O=BadSSL,L=San Francisco,ST=California,C=US signed
  this certificate, and none of the 10 store(s) assessed here holds an anchor for it. 1 of 6
  diagnostic layers could not be assessed.
exit 4 DIAGNOSIS
```

One sentence naming the cause, in the words of the layer that decided it. That layer is not always the first red one: a name that does not resolve is the cause even when every later layer fails too, and a server that did not send its intermediate certificate is named as the server's fault even though every store refuses the chain. The numbers come after the sentence, then the [exit code](/docs/exit-codes/) and its name.

## The layers

Below the verdict, every layer has one line with its status and a summary, followed by the evidence:

```
  + PASS     L0  Context          read 25 environment variables that decide trust and proxying
  + PASS     L3  TCP              1 of 1 address(es) accepted a connection
  x FAIL     L5  Trust matrix     15 of 17 store(s) do not trust the presented chain, and 2 could
                                  not be assessed
```

[The layers](/docs/layers/) says what each one checks. A status is one of four:

{{< statuses >}}

An `UNKNOWN` always carries its reason. A store that could not be read, a probe that did not understand what it saw and a layer that ran out of time all say so, and none of them counts as a pass.

## A row of the trust matrix

```
      java C:\Program Files\OpenJDK\jdk-21.0.2 does NOT trust the presented chain (106
        anchors)  detected
        needs elevated rights: this store is outside this account's own files, so it belongs to
                               every account on the machine
        run: "C:\Program Files\OpenJDK\jdk-21.0.2\bin\keytool" -importcert -trustcacerts -keystore "C:\Program Files\OpenJDK\jdk-21.0.2\lib\security\cacerts" -storepass changeit -alias "<alias>" -file "<certificate.pem>"
        replace first: <alias>, <certificate.pem>
```

Each row is one store: which program, which installation, whether it trusts the chain and how many anchors it holds. A row that refuses can carry:

- `run:` - the command that adds the certificate to that store, with this machine's paths in it,
- `replace first:` - what you put in before running it, such as the file you saved the certificate to,
- `needs elevated rights:` - why the command needs administrator or root rights, when it does,
- `note:` - what else to know, such as which other programs read the same store.

[The trust matrix](/docs/trust-matrix/) says which stores are asked and which command each one gets.

## Width and line breaks

The report is laid out 100 columns wide. Sentences wrap at their spaces. A command, a fingerprint, a certificate's name and a value read off the machine are never broken, because a command broken over two lines would be pasted as two. A line that runs past the edge is one meant to be copied whole.

## The notes

The report ends with notes saying what was not looked at in this run and why, so a missing row never reads as a store that agreed.
