# Technical changelog

Everything a user would **not** notice by running the program - structure, guards, CI, architectural decisions, measurements, and what was deliberately left out. User-visible changes go to [CHANGELOG.md](CHANGELOG.md) instead.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Entries are grouped by kind of change, not by date.** Git already knows when something happened, and a fact should live in one place.

> **Where the detailed rationale lives.** Planning documents, the decision register and per-probe research are kept **outside this repository** and are not part of any clone. This file is therefore the only record inside the repository of what was measured and why - keep it self-contained and do not link out to anything that is not tracked here.

## [Unreleased]

### Added

- Repository initialized. GPL-3.0 license text, README, security policy and both changelogs.
- `.gitignore` written **before** the repository existed, so that the untracked planning documents were never at risk of a first commit picking them up. It carries two warnings in the file itself - one that removing an entry publishes internal notes rather than merely adding files, and one that the testbed's expected verdicts are guard fixtures and must **not** be swept up by a pattern for generated files.

### Changed

- **Language stack: Go.** Chosen over Rust for three reasons, two of which were then measured rather than assumed. Full write-up is in the decision register outside this repository.

### Security

- Threat model written before any code. The notable part is what is **deliberately not** defended against: a compromised machine can lie to the tool, and a malicious PAC file can return a false answer. The PAC sandbox constrains what a PAC file can *do*, not whether it tells the truth.

### Measurements

Recorded here because the sessions that produced them no longer exist, and because two of the three overturned the prediction written down before the run.

- **PAC helper functions.** All twelve helpers from the PAC specification work under a pure-Go JavaScript engine, and each distinguishes a true case from a false one, so none is a stub returning a constant. **As predicted.**
- **A ready-made PAC library was rejected** after reading its source. Its native function table is unexported, so a controlled `dnsResolve` cannot be injected without forking, and its own `dnsResolve` calls the resolver directly from inside the sandbox. It also returns the first address of an unordered list, which makes the same PAC rule capable of yielding different answers between runs. Unmaintained since 2021. **Decision: use the engine directly and implement the twelve helpers ourselves.**
- **Minimum TLS version.** All four versions from TLS 1.0 to 1.3 complete a handshake when configured explicitly, with no debug switches. **This overturned the prediction** that 1.0 and 1.1 would be refused, and it removes the need for an `openssl s_client` fallback on protocol-version grounds. Not yet answered: whether a real legacy server offering only old cipher suites is reachable, which is a different question from protocol version.
- **Resolver divergence.** On Windows the built-in and system resolvers disagreed on **five out of five** names tested: the built-in one returns AAAA records the system one filters out, and it failed to resolve `localhost` at all because it queried DNS instead of reading the hosts file. In a static Linux container the same binary showed **zero** divergence, because without cgo both paths collapse onto the same resolver. **Consequence for the product: both views are correct and mean different things, so the DNS layer reports both and labels them.** In a container the system view has to be derived from configuration rather than measured, and must be labelled as derived.
- **The race detector requires cgo.** `go test -race` works with `CGO_ENABLED=1` and refuses outright with `CGO_ENABLED=0`. The release binary must be built with cgo disabled to stay static. These are two build configurations, not a conflict - but setting `CGO_ENABLED=0` globally in CI would remove race detection from the whole pipeline.

### Deliberately not done

- **No code.** The stack decision is not permission to start writing, and this is a deliberate ordering.
- **Nothing pushed.** Creating a repository is not permission to publish it.
- **No measurements on Linux or macOS** beyond a single container run. Every runtime trust-store finding recorded so far is from one Windows machine and is not a claim about any other.
- **No real interception certificate has been seen.** Detection of TLS inspection currently rests on vendor documentation, not on a sample. This is the largest gap in evidence in the project and only the testbed closes it.
