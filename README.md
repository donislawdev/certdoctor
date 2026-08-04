# certdoctor

**Why does this machine - or this container - fail to connect to that URL?**

certdoctor walks the whole path in one command - DNS, proxy and PAC, TCP, TLS - and then does the part no other tool does: it checks the trust store of **every runtime it finds on the machine**, one by one, and tells you which ones are broken and exactly what to run to fix each.

---

## Status: early development. One layer of eight does anything.

**There is a `certdoctor` command, it prints a complete report, and seven of its eight rows say they could not assess anything.** You get the real artefact - a one sentence verdict, a row for each of the eight layers, and the notes saying what was held back. The verdict counts the layers it could not assess, and the run exits with the code that means exactly that.

That is the point rather than an accident. `UNKNOWN` is the correct status for "not built yet", so there is no moment in this program's life at which it claims to have checked something it has not.

**The one layer that does work is `L0`, the context layer.** It reports twenty-one environment variables that decide what this machine trusts and what it proxies - both spellings of each proxy variable separately, because they are not the same variable everywhere - saying of each whether it is set, set to nothing, or absent. Credentials are removed from the values on the way out, always, whether or not you pass `--redact`.

What the repository holds besides that is the whole path from the command line to the exit code: argument parsing, the orchestrator and its time budget, the terminal renderer, `--json` with a schema and a validator that runs before anything is printed, `--out` with an atomic write, and the credential masking. Under that sits the foundation - the status vocabulary, the exit code table, the appearance dictionary, and the guards that police all three - plus CI.

**What is missing is the other seven layers.** Nothing resolves a name, opens a socket, reads a certificate or looks inside a trust store. **There is still nothing useful to install and nothing useful to run.**

Everything below describes what certdoctor is being built to do, not what it does today. This section will be removed when the first release ships. Until then, treat every capability on this page as a plan.

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
