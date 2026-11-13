# Security policy

## Reporting a vulnerability

**Use GitHub's private vulnerability reporting** on this repository: the **Security** tab, then **Report a vulnerability**. That channel is private and is the one to use.

**Please do not open a public issue for a security problem.** A public report tells everyone about the flaw before there is anything to update to.

## What is in scope

Cert Doctor reads a machine's network and trust configuration and produces a report. The things worth reporting are the ones that break one of these promises:

- **It never writes.** Any path by which Cert Doctor modifies a trust store, a configuration file or anything else other than a report at a path you named explicitly.
- **It connects only where you pointed it.** Any connection to a host not derived from your input - the target URL, its resolved addresses, your configured resolvers and proxies, or the PAC file your machine names.
- **Credentials never reach the report.** Proxy user info, authorization headers, tokens and cookies must be masked whether or not `--redact` is used.
- **A PAC file cannot escape its sandbox.** PAC evaluation runs untrusted JavaScript from your network. Any file system access, any network access outside our own resolver hook, or any way past the time and memory limits.
- **Unknown never becomes PASS.** Any input that makes a probe report success when it did not actually verify trust.

Command injection, path traversal on the report path, and crashes on hostile input are all in scope.

## What is not in scope

These are deliberate limits, written down so you do not spend time on them:

- **A compromised machine can lie to Cert Doctor.** It reads what the system and other tools tell it. It is a diagnostic, not an intrusion detection tool.
- **A malicious PAC file can return a false answer.** The sandbox stops a PAC file from *doing* anything. It does not make it tell the truth.
- **The report contains internal host names and paths by design.** That is its purpose. `--redact` reduces it. Credentials are a separate matter and are always masked - that part is in scope.
- **Cert Doctor is not a security boundary** for anything, and does not judge whether TLS inspection on your network is legitimate. It reports that it is happening and shows the evidence.

## Supported versions

**Only the latest release receives fixes.** A fix ships as a new release, and the one before it is not patched - there are no backports and no long-term line. Please check that a problem still happens on the latest release before reporting it, and against `main` if you build from source.

Before 1.0.0 a release may also change the shape of `--json`, so a pipeline that parses it should read [CHANGELOG.md](CHANGELOG.md) before it updates.

## What to expect

**This is a one-person project.** There is no on-call rotation and no guaranteed response time. Reports are read and answered, but it may take days rather than hours.

Saying this plainly is more useful than promising a schedule that would not be kept.
