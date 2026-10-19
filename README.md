# certdoctor 🩺 - find out why this machine cannot connect to that URL, and what to run to fix it
<p align="center">
  <b>Follow me:</b>
  &nbsp
  <a href="https://discord.gg/bDTu8HX"><img src="https://cdn.simpleicons.org/discord/5865F2" alt="Discord" height="26" align="absmiddle"></a>
  &nbsp
  <a href="https://facebook.com/donislawdev"><img src="https://cdn.simpleicons.org/facebook/0866FF" alt="Facebook" height="26" align="absmiddle"></a>
  &nbsp
  <a href="https://x.com/donislawdev"><picture><source media="(prefers-color-scheme: dark)" srcset="https://cdn.simpleicons.org/x/FFFFFF"><img src="https://cdn.simpleicons.org/x/000000" alt="X (Twitter)" height="26" align="absmiddle"></picture></a>
  &nbsp
  <a href="https://bsky.app/profile/donislawdev.bsky.social"><img src="https://cdn.simpleicons.org/bluesky/0285FF" alt="Bluesky" height="26" align="absmiddle"></a>
  &nbsp
 <a href="https://store.steampowered.com/developer/DonislawDev"><picture><source media="(prefers-color-scheme: dark)" srcset="https://cdn.simpleicons.org/steam/FFFFFF"><img src="https://cdn.simpleicons.org/steam/000000" alt="Steam" height="26" align="absmiddle"></picture></a>
</p>

[![CI](https://github.com/donislawdev/certdoctor/actions/workflows/ci.yml/badge.svg)](https://github.com/donislawdev/certdoctor/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/donislawdev/certdoctor?sort=semver)](https://github.com/donislawdev/certdoctor/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/donislawdev/certdoctor/total)](https://github.com/donislawdev/certdoctor/releases)
[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
![Platform: Windows](https://img.shields.io/badge/platform-Windows-0078D6)
![Platform: Linux](https://img.shields.io/badge/platform-Linux-FCC624)
![Platform: macOS](https://img.shields.io/badge/platform-macOS-000000)
[![Website](https://img.shields.io/badge/website-certdoctor.donislawdev.com-e4573f)](https://certdoctor.donislawdev.com/)

**certdoctor** is a command-line tool for QA engineers, helpdesk and DevOps - for anyone who has
read `PKIX path building failed` or `unable to get local issuer certificate` on a corporate laptop,
behind a proxy, or inside a container that cannot do what the host does without trouble. Point it at
the URL that fails. It walks the whole path in one run - DNS, proxy and PAC script, TCP, TLS - and
then does the part no other tool does: it asks **each trust store on the machine**, one by one,
whether it trusts what the server presented, and prints the command that would fix each store that
does not, with the real paths from your machine in it. `curl -v` and `openssl s_client` answer for
one program. certdoctor answers for the Windows store, every Java installation, every `git` and every
`curl` it finds - and tells you whether the fault is on this machine at all.

⭐ **If it ended a "works on my machine" argument, leave a star.** That is how the next person
staring at `PKIX path building failed` finds out it exists.

**What it can do**

- **Say whose problem it is** - this machine, or the server. A server that does not send its
  intermediate certificate is named as the server's fault, with the evidence to paste into a ticket.
- **One row per trust store, not per runtime** - the Windows store as your account sees it and as
  services see it, the Linux CA bundle, every JDK and JRE separately, every `git` and `curl` it
  finds. On the machine it was built on, one run reads thirteen stores.
- **Print the command that fixes each store** - `certutil`, `keytool` with the real `cacerts` path of
  that JDK, an append to git's own bundle - and say when it needs administrator rights. It prints
  them. It never runs them.
- **Notice TLS inspection without accusing anyone** - who signed the certificate, how many stores on
  this machine know that authority, and the product's name when it is one certdoctor recognises.
- **Read your proxy settings the way your programs do** - the environment variables, the Windows
  Internet Settings that Edge, Chrome and .NET follow, and the WinHTTP settings that services follow,
  side by side. It runs your PAC script in a sandbox to see where your URL really goes, and asks the
  proxy whether it wants credentials.
- **Look at DNS twice** - every configured resolver asked directly, and the system resolver, with the
  difference classified: split horizon, a leak past a VPN, a name that resolves nowhere.
- **Try every address** - a TCP connection to each address the name resolves to, and the full
  certificate chain from each one, with fingerprints and validity dates.
- **Write a report for the ticket** - terminal, Markdown, one self-contained HTML page, or JSON with a
  schema for CI. `--redact` masks host names, paths and user names. Credentials are masked always.
- **Change nothing and call nobody** - the only file it writes is the report, at the path you name.
  It connects only where you pointed it: no telemetry, no update check.
- **Ship as one static binary** - nothing to install next to it, and it runs as it is inside Alpine
  and Ubuntu images.

<!-- The GIF of a real run goes here. It is recorded from the binary by the recorder kept with the
project, once the terminal report fits a terminal. -->

<!-- The star GIF goes here, recorded on this repository once it is public. -->

---

## Try it on a broken site

[badssl.com](https://badssl.com/) keeps deliberately broken HTTPS sites for exactly this. Three of
them, with the first sentence certdoctor prints at the top of each report:

```
certdoctor https://incomplete-chain.badssl.com/
```

> The server presented 1 certificate(s) and did not send the issuer of the first one, so nothing can
> build a path to a root - this is a fact about the server rather than about this machine.

```
certdoctor https://untrusted-root.badssl.com/
```

> CN=BadSSL Untrusted Root Certificate Authority,O=BadSSL,L=San Francisco,ST=California,C=US signed
> this certificate, and no store on this machine holds an anchor for it.

```
certdoctor https://expired.badssl.com/
```

> 13 of 13 store(s) do not trust the presented chain - a certificate in the path is past its
> validity.

The second one is where the trust matrix earns its place. Every store refuses, and every store that
can be given the root carries the command that would add it there, with this machine's paths in it.
curl built on Schannel judges by this account's Windows store, so its rows point at that store's
command rather than carrying one of their own. An excerpt from a Windows machine, with the column
padding taken out:

```
system-store LocalMachine does NOT trust the presented chain (90 anchors)
  needs elevated rights: the LocalMachine store is read by every account and every service on this machine, so changing it needs administrator rights
  run: certutil -addstore Root "<certificate.pem>"
  replace first: <certificate.pem>
git C:\Program Files\Git\mingw64\bin\git.exe does NOT trust the presented chain (121 anchors)
  needs elevated rights: this store is outside this account's own files, so it belongs to every account on the machine
  run: cmd /c copy /b "C:\Program Files\Git\mingw64\etc\ssl\certs\ca-bundle.crt"+"<certificate.pem>" "C:\Program Files\Git\mingw64\etc\ssl\certs\ca-bundle.crt"
java C:\Program Files\OpenJDK\jdk-21.0.2 does NOT trust the presented chain (106 anchors)
  needs elevated rights: this store is outside this account's own files, so it belongs to every account on the machine
  run: "C:\Program Files\OpenJDK\jdk-21.0.2\bin\keytool" -importcert -trustcacerts -keystore "C:\Program Files\OpenJDK\jdk-21.0.2\lib\security\cacerts" -storepass changeit -alias "<alias>" -file "<certificate.pem>"
```

**Do not run those for badssl.com.** That root is untrusted on purpose, and trusting it would make
every store on your machine accept a certificate nobody vouches for. The commands are there for the
day the refused root is your own company's.

---

## Download and run

**Download a binary.** Take the archive for your system from the
[releases page](https://github.com/donislawdev/certdoctor/releases/latest), unpack it and run
`certdoctor`. It is one file with nothing to install. The Windows and macOS binaries are signed, and
every release carries `SHA256SUMS`.

**With Go installed** (1.27.2 or newer):

```
go install github.com/donislawdev/certdoctor/cmd/certdoctor@latest
```

**From source:**

```
git clone https://github.com/donislawdev/certdoctor
cd certdoctor
CGO_ENABLED=0 go build ./cmd/certdoctor
```

`CGO_ENABLED=0` gives the same static binary the releases carry, the one that runs in an Alpine
image as it is.

**Inside a container**, copy the Linux binary in and run it there - the report then describes the
container, not the host:

```
docker cp certdoctor my-container:/tmp/certdoctor
docker exec my-container /tmp/certdoctor https://api.example.com/
```

---

## Two minutes with it

```bash
# The question this tool exists for: why does this URL fail here?
certdoctor https://api.example.com/

# A report to attach to a ticket, with host names, paths and user names masked
certdoctor https://api.example.com/ --redact --format md --out report.md

# One HTML page with no script in it and nothing fetched from anywhere
certdoctor https://api.example.com/ --format html --out report.html

# JSON for a pipeline, validated against its schema before it is printed
certdoctor https://api.example.com/ --json > report.json

# Ask about a PAC script your machine does not name, which is the only way to ask on Linux
certdoctor https://api.example.com/ --pac-url http://wpad.example.com/proxy.pac
```

The report opens with **one sentence naming the cause** in the words of the layer that decided it.
The numbers come after that sentence, then every layer with its evidence, then the notes saying what
was not looked at. Every flag is in `certdoctor --help`.

<details>
<summary><strong>Table of contents</strong></summary>

- [Symptoms](#symptoms)
- [Why this exists](#why-this-exists)
- [What it checks, layer by layer](#what-it-checks-layer-by-layer)
- [What makes it different](#what-makes-it-different)
- [Using it in CI](#using-it-in-ci)
- [Honest limits](#honest-limits)
- [What it will never do](#what-it-will-never-do)
- [Your report contains internal data](#your-report-contains-internal-data)
- [Questions](#questions)
- [Found a case it gets wrong?](#found-a-case-it-gets-wrong)
- [License](#license)

</details>

---

## Symptoms

If you searched for one of these, you are in the right place. certdoctor is built to tell you
**which** of the many possible causes is yours:

```
PKIX path building failed
unable to find valid certification path to requested target
certificate verify failed: unable to get local issuer certificate
SELF_SIGNED_CERT_IN_CHAIN
SSL certificate problem: self signed certificate in certificate chain
x509: certificate signed by unknown authority
407 Proxy Authentication Required
```

They are the same complaint in the words of different runtimes, and each runtime keeps its own idea
of whom to trust. The browser works. `curl` works. The application does not. That is not a paradox -
it is several trust stores disagreeing.

| You saw | Usually from | What certdoctor asks |
|---|---|---|
| `PKIX path building failed`, `unable to find valid certification path` | Java | every JDK and JRE on the machine, each `cacerts` as its own row |
| `SSL certificate problem: ...` | `curl`, and `git` over HTTPS | every `git` and `curl` it finds, and which store each of them reads |
| `x509: certificate signed by unknown authority` | programs written in Go | the platform store - the Windows store, or the Linux CA bundle |
| `407 Proxy Authentication Required` | anything going through a proxy | which proxy applies to this URL, and whether it wants credentials |
| `certificate verify failed: unable to get local issuer certificate` | Python, `pip` | **coming next** - the Python and `pip` rows are being built |
| `SELF_SIGNED_CERT_IN_CHAIN` | Node.js, `npm` | **coming next** - the Node.js and `npm` rows are being built |

---

## Why this exists

A new laptop, a new network, a new VPN or a new container image, and a connection that worked
yesterday fails with one of the messages above. The fix is usually one command. Finding which command
takes an afternoon, because:

- **every runtime has its own trust store.** Java keeps one `cacerts` per installation, and a typical
  developer machine has several JDKs, of which somebody fixed one. Git for Windows carries its own
  bundle. `curl` built with Schannel reads the Windows store and ignores the bundle beside it.
- **the proxy is decided in several places at once.** Environment variables, the Windows settings a
  browser follows and the different ones a service follows, and a PAC script that sends one host past
  the proxy everything else goes through.
- **the network sees two different worlds.** On a VPN one resolver answers with an internal address
  and another with a public one.
- **nobody can tell whose fault it is.** A server that forgot its intermediate certificate works in
  a browser that cached the intermediate from some other site and fails everywhere else.

The knowledge exists - in dozens of "every cause of `PKIX path building failed`" articles. What did
not exist was a tool that checks every cause on the machine in front of you and gives a verdict.

---

## What it checks, layer by layer

| Layer | Question it answers | Example of what it finds |
|---|---|---|
| `L0` Context | which of the 23 environment variables that decide trust and proxying are set | `HTTPS_PROXY` set while `https_proxy` is not - programs disagree about which one counts |
| `L1` Name resolution | what each resolver says, and what your system says | the two views sharing no address at all - what split horizon DNS looks like |
| `L2` Proxy | which proxy this URL really goes through, and who decided that | a PAC script sending this host direct while every setting names a proxy |
| `L3` TCP | which of the resolved addresses accept a connection | refused, unreachable and timed out told apart, per address |
| `L4` TLS | what the server presented, and whether that chain is complete | a server that did not send its intermediate certificate |
| `L5` Trust matrix | which trust stores on this machine accept that chain | one JDK refusing a root that another JDK and the Windows store accept |

**The handshake is completed without verifying it**, on purpose. A chain that fails verification
leaves you with no certificates to look at, and here the evidence is the product.

**The Windows store is asked with every network retrieval switched off.** The address Windows would
fetch a missing certificate from is written into that certificate by the server you are diagnosing,
and certdoctor connects only where you pointed it. It tells a public root Windows has simply not
downloaded yet from an authority nobody installed by reading this machine's own copy of Microsoft's
root program list.

**A store that cannot be read says so, with the reason, and never counts as a pass.** A probe that
does not understand what it saw reports `UNKNOWN`. There are exactly four statuses - `PASS`, `WARN`,
`FAIL`, `UNKNOWN` - and `UNKNOWN` always carries why.

---

## What makes it different

Other tools look at the certificate. certdoctor looks at **the machine in front of you** and at which
of its runtimes accept that certificate.

It does not compete with these, and links to them on purpose:

- [certigo](https://github.com/square/certigo) - inspects and explains certificates
- [testssl.sh](https://testssl.sh) - audits the TLS configuration of a server
- [tlstools](https://github.com/frdmn/tlstools) - certificate utilities

When the trouble is the server, they tell you more about the server than certdoctor does. When the
trouble is that one runtime on your machine disagrees with another, they cannot see it at all.

---

## Using it in CI

Every ending has its own exit code, and `--json` writes a report validated against its schema before
anything is printed:

| Code | Name | Meaning |
|---|---|---|
| `0` | OK | everything that mattered was assessed and passed |
| `1` | RUNTIME | certdoctor itself failed |
| `2` | USAGE | bad invocation syntax or an unknown flag |
| `3` | CONFIG | flags are valid on their own but contradictory or unsatisfiable |
| `4` | DIAGNOSIS | the run succeeded and found at least one failure |
| `5` | INCONCLUSIVE | no failure, but at least one thing could not be assessed |
| `6` | IO | the report could not be written |
| `130` | INTERRUPTED | interrupted by the user |
| `143` | TERMINATED | terminated by the system |

A `WARN` alone does not fail a build. `certdoctor --version` prints the version of the tool and of
every schema it emits, so a log from six months ago still says what produced it.

```yaml
- name: can the build agent reach the registry
  run: certdoctor https://registry.example.com/ --redact --json --out certdoctor.json
```

---

## Honest limits

A tool that quietly fails to look at something is worse than one that says what it cannot do.

- **The trust matrix knows four families today** - the platform store on Windows and Linux, Java,
  `git` and `curl`. Node.js with `npm` and Python with `pip` come next, then OpenSSL, .NET and
  PowerShell, Docker, Maven and Gradle, and apt. A family it does not know is not asked, and the
  report lists the families it asked - so a missing row means nobody looked, never that nothing is
  there.
- **On macOS the system keychain is not read yet**, so the platform store has no row there.
- **Container diagnosis is not built.** `--in`, `--image` and `--compare` are accepted and refused
  with a reason. Until they work, copy the binary into the container and run it there.
- **Proxy auto-discovery (WPAD) is not performed.** On a machine where it is switched on, the proxy
  layer says it could not establish which proxy applies, rather than claiming there is none - so a
  healthy target there ends with exit code 5, not 0.
- **It names an inspection product only when the certificate says so in a way the vendor
  publishes** - today mitmproxy and Cisco Umbrella. Anything else is reported as an authority local to
  this machine, held by some of its stores, with the issuer and the fingerprint. From one connection,
  an inspecting proxy and your own company's certificate authority look identical, and telling
  somebody "you are being intercepted" when they are not is harm, not a cosmetic mistake.
- **No revocation checks.** OCSP and CRL would mean connecting somewhere you did not point it at.
- **Linux has been measured in containers**, not on a desktop distribution.
- **This is a 0.x release.** The JSON schema will keep moving until 1.0.0, and the report says so in
  its notes.

---

## What it will never do

**certdoctor diagnoses. It does not repair.**

It never writes to a trust store, never edits a configuration file, and never runs the commands it
generates. It prints them for you to read and run yourself. This is a deliberate limit, not a missing
feature - a diagnostic tool that quietly modifies trust stores is a tool nobody should grant
administrator rights to.

It also connects only to what you pointed it at - the target URL, the addresses it resolves to, your
configured resolvers and proxies, and the PAC file your machine names. There is no telemetry, no
update check and no reporting of any kind.

---

## Your report contains internal data

The report includes internal host names, file system paths and user names, because that is what makes
it useful in a ticket. `--redact` masks them.

Credentials are different: proxy user info, authorization headers and cookies are **always** masked,
with or without `--redact`, because a masking that depends on a flag is one forgotten flag away from a
leak.

**Read a report before you paste it somewhere.** Masking is a filter, not a guarantee.

---

## Questions

### Does it change anything on my machine?

No. It reads, connects where you pointed it, and writes one report if you ask for one with `--out`.
The commands it prints are for you to run, after reading them.

### Why not just `openssl s_client` or `curl -v`?

Both answer for themselves. `openssl s_client` tells you what OpenSSL's store thinks, and the Java
service that fails does not use that store. certdoctor asks every store it can find the same
question about the same chain, and the answer is usually that they disagree.

### Will it tell me my company is intercepting my traffic?

Only when the certificate names a product it recognises. Otherwise it says who signed the certificate
and how many stores on your machine trust that authority - which is exactly what your own company's
certificate authority looks like too.

### Does it need administrator rights?

No. It runs as whoever started it, and the report records which rights it ran with, because what a
store looks like can depend on them. A printed fix says when running it needs administrator or root
rights.

### Is it free? Can I use it at work?

Yes to both. It is GPL-3.0 and costs nothing. The reports you generate belong to you.

---

## Found a case it gets wrong?

That is the most useful issue you can open. Attach the report made with `--redact --json`, say what
the right answer was, and name the runtime that disagreed. The
[issue tracker](https://github.com/donislawdev/certdoctor/issues) is open. Security problems go
through [SECURITY.md](SECURITY.md) instead.

---

## License

Copyright (C) 2026 DonislawDev. The project is built with an AI-assisted workflow.

Released under the GNU General Public License, version 3. The full text is in [LICENSE](LICENSE), and
`certdoctor --license` prints it from the binary.

Reports and any other output you generate with certdoctor belong to you and are not derivative works
of this program.

---

If it saves you an afternoon, a star helps the next person find it - and you can
[support the project](https://donislawdev.com/support/).

<sub>Keywords: PKIX path building failed · unable to find valid certification path to requested target ·
certificate verify failed unable to get local issuer certificate · x509 certificate signed by unknown
authority · SSL certificate problem self signed certificate in certificate chain · corporate proxy
certificate error · TLS inspection troubleshooting · keytool import certificate into cacerts · which
JDK cacerts · git SSL certificate problem Windows · PAC file test · 407 Proxy Authentication
Required</sub>
