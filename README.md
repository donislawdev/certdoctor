# certdoctor

**Why does this machine - or this container - fail to connect to that URL?**

certdoctor walks the whole path in one command - DNS, proxy and PAC, TCP, TLS - and then does the part no other tool does: it checks the trust store of **every runtime it finds on the machine**, one by one, and tells you which ones are broken and exactly what to run to fix each.

---

## Status: early development. Six layers of eight do anything.

**There is a `certdoctor` command, it prints a complete report, and two of its eight rows say they could not assess anything.** You get the real artefact - a one sentence verdict, a row for each of the eight layers, and the notes saying what was held back. The verdict counts the layers it could not assess, and the run exits with the code that means exactly that.

That is the point rather than an accident. `UNKNOWN` is the correct status for "not built yet", so there is no moment in this program's life at which it claims to have checked something it has not.

**`L0`, the context layer**, reports twenty-three environment variables that decide what this machine trusts and what it proxies - both spellings of each proxy variable separately, because they are not the same variable everywhere - saying of each whether it is set, set to nothing, or absent. Credentials are removed from the values on the way out, always, whether or not you pass `--redact`.

**`L1`, name resolution, is the first thing certdoctor does that leaves its own process.** It reads the resolvers this machine is configured to use - from the registry and the IP helper API on Windows, from `/etc/resolv.conf` elsewhere - then asks each of them separately for `A` and for `AAAA`, and reports one row per answer. `NXDOMAIN`, `SERVFAIL` and `NODATA` are told apart and reported as themselves, which is why it asks the resolvers directly rather than using the resolver built into Go: that one collapses "the name does not exist" and "resolving it failed" into a single message, and those send you to two different places. A query that got nothing back says why, in a field of its own, rather than pretending to a response code.

**Point it at an address rather than a name and it asks no DNS question at all** - it says there was nothing to resolve and hands the address to the layers below, which is what you meant by typing one. **A name with a non-ASCII character in it is converted to its `xn--` form before anything is asked about it**, so international domain names work rather than producing a confident `NXDOMAIN` about a site that is up. The report shows what you typed and every row of this layer shows the converted name, because that is the one that went out. A name written with combining marks is refused with a reason instead of being converted into a valid-looking name for a different domain.

That is one of two views. The other asks your system the same question, the way any other program on your machine would, and the report says which resolver actually did the work - your platform's, or the one built into certdoctor standing in for it. **The difference between the two views is classified rather than tested for equality**, because they differ constantly for reasons that are nobody's fault: your platform filters out record types certdoctor asked for by name, and certdoctor never reads your `hosts` file. Three of the seven kinds of difference are worth a verdict: the views sharing no address at all, which is what split horizon DNS and a leak past a VPN look like, and the two ways a name can resolve nowhere - nobody answered at all, or somebody answered and no address came back from either view.

**`L2` reads every place your machine keeps proxy settings, and tells you where they disagree.** One row per PLACE rather than per program, because several programs read one place and one program reads two: on Windows that is the current user's Internet Settings, which Edge, Chrome and .NET follow, and the machine's default WinHTTP configuration, which services follow; on every system it is also the proxy environment variables this process was started with. Set a proxy in the Windows settings and those two views disagree about whether a proxy exists at all - measured - so Edge goes through it and a service goes direct, with nothing on the machine misconfigured. That run reports `WARN` and names the class of the disagreement.

**It also fetches the automatic configuration script and runs it, which is the fault this product exists for.** A proxy is configured, every place says so, and the script sends one name straight past it - anybody reading only the configuration would tell you the opposite of what happens. The report shows which entry the script names for your URL and every entry it listed, the script's own answer verbatim, and the names it asked a resolver about while deciding. A script that will not parse, times out, or runs past a limit gets `UNKNOWN` with a reason - never a silent fall back to direct, which is the behaviour this program exists to interrupt. `--pac-url` asks about a script your machine does not name - on Linux there is no place to read one from, so that flag is the only way to ask the question there at all.

**And it asks the proxy whether it wants credentials**, without offering any. Only a `407` answers that question: a proxy refusing a `CONNECT` to a port it does not consider safe returns `403` while wanting no credentials at all - measured - so everything except a `407` leaves the verdict alone and says why. What is missing is automatic discovery: certdoctor does not perform WPAD, and on a machine where it is switched on the layer says so rather than claiming there is no proxy.

**`L3` opens a TCP connection to every address the name resolved to, side by side rather than one after another**, and reports a row per address with what happened and how long it took. Refused, unreachable, timed out and connected are told apart, because they send you to four different places. **The rows come back in the order the addresses were resolved in, never in the order the attempts finished**, so two reports from the same machine line up row for row. Eight at a time is a ceiling rather than a tuning knob - how many addresses a name has is decided by whoever answers the query, and that is not a decision to hand to a stranger.

**`L4` completes a TLS handshake with every address that accepted a connection** and shows what each server presented: the negotiated version, the cipher by its IANA number with the name beside it, the name sent in SNI, what ALPN agreed, whether the server asked you for a client certificate, and the full chain with issuers, validity, the names each certificate is actually for, and SHA-256 fingerprints. **The chain is printed once and every other address carries the comparison instead** - the same certificate, or a different one. A different one is the only signal this program has for something sitting on one route and not another.

**Its verdict is structural and touches no trust store at all.** It answers "did the issuer of this certificate actually arrive" - the commonest real misconfiguration there is, and one that is invisible from a browser that cached the missing intermediate from some other site. Whether this machine trusts anything is the next layer's question. That separation is also why the handshake is completed without verifying it: a chain that fails verification leaves you with no certificates to look at, and here the evidence is the product.

**`L5` is the part no other tool does - one row per trust store, never one per runtime.** On the machine this was developed on that is thirteen rows, measured 2026-10-14: the Windows store asked twice - as this account sees it and as a service running as the machine sees it - seven Java trust stores across five JDK installations and two JREs in both bitnesses, two `git` binaries in `PATH` reading different stores, and two `curl` binaries which report that they read the platform's store rather than one of their own, so they point at the Windows rows instead of answering for them. Each row carries the real path on this machine where the store is a file, how many anchors it holds, what selects it by default, and what it makes of the chain that arrived. A store certdoctor cannot read says so with a reason and is never counted as a failure.

**The Windows store is asked with every network retrieval switched off**, because the address Windows would fetch a missing certificate from is written into that certificate by the server you are diagnosing - and certdoctor connects only to what you pointed it at. The price is one ambiguity: a public root Windows has simply not downloaded yet looks exactly like an authority nobody installed. certdoctor tells the two apart with this machine's own copy of Microsoft's root program list, and when that list cannot settle it - missing, or not brought up to date for thirty days - the row says `UNKNOWN` and why, never `FAIL`. macOS does not have this row yet.

**On Linux the platform store is a file, and the row reads the one Go itself reads** - the first CA bundle on Go's own list, which is also where OpenSSL's default bundle led in every measured image that carried OpenSSL. The row is named after the distribution, such as `system-store debian` or `system-store alpine`. `SSL_CERT_FILE` and `SSL_CERT_DIR` point programs away from that store, so they are reported with the other variables rather than followed. A container with no CA bundle at all - `ubuntu:24.04` and `debian:trixie-slim` as shipped - gets `UNKNOWN` saying so, and a certificate copied by hand into `/etc/ssl/certs` without reaching the bundle gets `UNKNOWN` saying that some programs here trust the chain and some do not. This was measured in containers, not on a Linux machine.

**The matrix opens with one line saying who signed the certificate and how much of this machine has heard of them.** It answers with a count of stores - all of them, some of them, or none - and `some_stores` is exactly why one tool on your machine works and another does not. **It is a count and never an accusation.** A TLS-inspecting proxy produces that answer and so does your own organisation's certificate authority on an internal service that is working as intended, and from a single connection those two are identical in every field this program has. Both were built on a test bench and measured. The issuer and the fingerprint travel with the line so that somebody who can tell them apart has what they need.

**A store that refuses carries the command that would repair it**, with the real path from your machine in it - or, for the Windows store, the `certutil` line that adds to it, and for the Linux store a line appending to the distribution's bundle, with a note that `update-ca-certificates` and `update-ca-trust` rebuild that file and drop what was appended - and only where your machine is the thing to change. It adds to the store that runtime already reads rather than pointing it somewhere else, and it says before you run it if it needs administrator or root rights.

What the repository holds besides that is the whole path from the command line to the exit code: argument parsing, the orchestrator and its time budget, the terminal renderer, `--format md` for a report you paste into a ticket, `--format html` for one page you attach to a mail - no script in it and nothing fetched from anywhere - `--json` with a schema and a validator that runs before anything is printed, a test that holds all four surfaces to the same facts, `--out` with an atomic write, and the credential masking. Under that sits the foundation - the status vocabulary, the exit code table, the appearance dictionary, and the guards that police all three - plus CI and a Docker test bench that knows the right answer because it made the answer up.

**What is missing is `L6` and `L7`.** Nothing reports what being inside a container changes, and no automatic proxy discovery is performed. **There has been no release, so there is still nothing to install** - but six layers of eight is a real diagnosis for a real class of failures: a name that resolves nowhere, an address that will not accept a connection, a proxy your machine names in one place and not another, a script that routes one host past the proxy everything else goes through, a server that withheld its intermediate, and a runtime on this machine that does not trust what a server presented.

Everything below describes what certdoctor is being built to do. Some of it exists today and the paragraphs above say which. This section will be removed when the first release ships.

---

## Symptoms

If you searched for one of these, you are in the right place. certdoctor is built to tell you **which** of the many possible causes is yours:

```
PKIX path building failed
unable to find valid certification path to requested target
certificate verify failed: unable to get local issuer certificate
SELF_SIGNED_CERT_IN_CHAIN
SSL certificate problem: self signed certificate in certificate chain
x509: certificate signed by unknown authority
407 Proxy Authentication Required
```

The frustrating part of these errors is that they are all the same message from different runtimes, and each runtime keeps its own idea of who to trust. The browser works. `curl` works. The application does not. That is not a paradox - it is seven trust stores disagreeing.

## The point of the tool: the trust matrix

Other tools look at the certificate. certdoctor looks at **which runtimes on this machine trust it**.

```
RUNTIME              TRUST STORE                                          RESULT
system store         Windows Root store                                   PASS
curl                 Windows Root store (Schannel backend)                PASS
git                  C:\Program Files\Git\mingw64\...\ca-bundle.crt       FAIL
java  jdk-21.0.2     C:\Program Files\OpenJDK\jdk-21.0.2\...\cacerts      FAIL
java  jdk-25         C:\Program Files\OpenJDK\jdk-25\lib\security\cacerts PASS
node                 bundled CAs                                          FAIL
python               (could not assess - reason: unrecognized output)     UNKNOWN
```

Every `FAIL` comes with a ready command carrying the **real paths from this machine**, not a template. Every `UNKNOWN` says why it could not be assessed. **A probe that does not understand what it saw never reports `PASS`.**

## What it will never do

**certdoctor diagnoses. It does not repair.**

It never writes to a trust store, never edits a configuration file, and never runs the commands it generates. It prints them for you to read and run yourself. This is a deliberate limit, not a missing feature - a diagnostic tool that quietly modifies trust stores is a tool nobody should grant administrator rights to.

It also connects only to what you pointed it at - the target URL, the addresses it resolves to, your configured resolvers and proxies, and the PAC file your machine names. There is no telemetry, no update check and no reporting of any kind.

## Your report contains internal data

The report includes internal host names, file system paths and user names, because that is what makes it useful in a ticket. `--redact` masks them.

Credentials are different: proxy user info, authorization headers and cookies are **always** masked, with or without `--redact`, because a masking that depends on a flag is one forgotten flag away from a leak.

**Read a report before you paste it somewhere.** Masking is a filter, not a guarantee.

## Neighbours

certdoctor does not compete with these, and links to them on purpose:

- [certigo](https://github.com/square/certigo) - inspects and explains certificates
- [testssl.sh](https://testssl.sh) - audits the TLS configuration of a server
- [tlstools](https://github.com/frdmn/tlstools) - certificate utilities

They look at the certificate. certdoctor looks at **the machine in front of you** and at which of its runtimes accept that certificate.

## License

GPL-3.0. The full text is in [LICENSE](LICENSE).

Reports and any other output you generate with certdoctor belong to you and are not derivative works of this program.
