# Technical changelog

Everything a user would **not** notice by running the program - structure, guards, CI, architectural decisions, measurements, and what was deliberately left out. User-visible changes go to [CHANGELOG.md](CHANGELOG.md) instead.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Entries are grouped by kind of change, not by date.** Git already knows when something happened, and a fact should live in one place.

> **Where the detailed rationale lives.** Planning documents, the decision register and per-probe research are kept **outside this repository** and are not part of any clone. This file is therefore the only record inside the repository of what was measured and why - keep it self-contained and do not link out to anything that is not tracked here.

## [Unreleased]

### Added

- Repository initialized. GPL-3.0 license text, README, security policy and both changelogs.
- `.gitignore` written **before** the repository existed, so that the untracked planning documents were never at risk of a first commit picking them up. It carries two warnings in the file itself - one that removing an entry publishes internal notes rather than merely adding files, and one that the testbed's expected verdicts are guard fixtures and must **not** be swept up by a pattern for generated files.
- **Status vocabulary** in `internal/core/status`: exactly four statuses and five reasons for `UNKNOWN`, both closed lists and both public contracts. The zero value of a status is deliberately invalid, so a forgotten assignment fails a check instead of reading as a pass.
- **Exit code registry** in `internal/core/exitcode`: the complete table of nine, frozen from the first version because adding a code after release would change what somebody else's pipeline sees with no change on their side. A warning on its own keeps the exit code at success.
- **Appearance dictionary** in `internal/adapter/render`: the single place allowed to contain an escape sequence or a glyph. Colours are the four basic terminal colours rather than fixed shades, so a light background, a dark background and a high-contrast setting are handled by the reader's own terminal theme instead of by our guess. The zero value of both the colour mode and the glyph mode is the safe one, so a forgotten assignment degrades to plain ASCII rather than writing control sequences into a log.
- **Three structural guards** in `internal/guard`, standing before the code they police: import direction between layers, literal appearance outside the dictionary, and containment of concurrency primitives. Each one has a canary - a fixture with planted violations that the scanner must find - because on a tree this small all three would otherwise pass while blind. A fourth test checks that the scanner read the module at all.
- **Entry point** `cmd/certdoctor`. It diagnoses nothing yet and says so on the log channel, writes zero bytes to the report channel and ends with the code meaning "could not assess". It exists so the release build produces an artefact whose static linking can be checked.
- **CI workflow** with two build configurations. Tests run with cgo enabled, and the race detector runs on Linux where the image is known to carry a C compiler. The release build runs with cgo disabled and then proves the result is static from two independent signals: what the linker produced, and the build setting recorded in the binary. Actions are pinned to commit digests rather than moving tags.

### Added

- **A guard on filesystem writes**, which is the first executable slice of the promise on the first line of the README: certdoctor diagnoses and never repairs. Production code calling anything that creates, modifies or deletes a file is a finding, and the allowlist is empty. Tests are held to a narrower rule - a test that writes must take a temporary directory - because a test suite is the likeliest source of litter in a working tree, and `.gitignore` is a second line of defence rather than the first. What it does not see is written next to it: a write through a handle passed in as a parameter, and anything reached through `os/exec`.
- **Sideways imports between packages of the same layer are now reported.** The direction rule could not see them: two adapters importing each other points neither up nor down, while being "the core does not know the interface" broken one floor down. The exception list is empty and lives in the test, so making such an edge without declaring it is visible.
- **A dependency gate in CI.** The module list is compared against `tools/expected-modules.txt`, which currently holds one line. A dependency rarely arrives by decision - it arrives as somebody else's transitive import, in a diff that looks like it only touched `go.sum`. Until now the rule requiring a justification and a licence check for every new dependency was enforced by nothing.

### Changed

- **The Go version is pinned rather than treated as a minimum.** certdoctor's verdicts rest on `crypto/x509` and `crypto/tls`: what chains verify, which TLS versions negotiate, what a verification failure is called. Those change between releases - one such behaviour was measured during the stack probes and overturned the prediction written before it. A release built on a different toolchain can therefore reach a different verdict about the same machine, and nothing in the report would say so.
- **Waiting for a context to be cancelled no longer counts as concurrency.** Every probe carries a context with a deadline, because a subprocess outliving the run is a leak the user sees in their task manager - so every probe will contain a receive from `ctx.Done()`. Counting those would have fired the containment guard on the first probe ever written, and the only way out would have been adding files to the allowlist, dissolving the rule at the moment it starts to matter. The exemption is narrow: a call to a method named `Done` taking no arguments, and a select whose every clause is such a receive or a `default`. A select mixing cancellation with a real channel is still reported, and so is the real channel inside it. Both edges are covered, because an exemption too narrow and an exemption too wide fail in opposite directions.
- **The guards' tree loader was split into three named steps** - walking, deciding what to descend into, and parsing one file. It was the longest function in the module at 54 lines against a median of 6, which is what the new size report was written to surface. The split also created the seam that made two previously unguarded behaviours testable: skipping a directory that carries its own `go.mod`, and refusing to step silently over a file that will not parse. The first of those was invisible here - the only nested module in this tree sits under a directory that was already skipped by name, so that branch had never once run.

### Fixed

- **The README claimed there was no code.** It said the repository held only documents and that there was nothing to run, which stopped being true the moment the entry point existed. The status section now says what the command actually does, which is nothing, and says it in those words.
- **`.gitignore` excluded the program's entry point.** The unanchored pattern `certdoctor`, meant for a build artefact, also matched the directory `cmd/certdoctor/`, so the main package would never have been committed and a fresh clone would have had nothing to build. Found with `git check-ignore` while adding that directory. Both binary names are now anchored to the repository root and the file carries a warning saying why they must stay that way.

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

- **No diagnostics.** The first slice of work deliberately produces nothing useful: it is structure and the guards that police it. Guards written afterwards would find the rules already broken and would be something to repair rather than something that protects.
- **The CI workflow has never run.** It only runs after a push, and pushing is a separate decision. What was checked locally is the same set of commands, plus a build made both ways to confirm that the recorded cgo setting really does tell the two configurations apart.
- **The race detector does not run on Windows in CI.** Whether that runner image exposes a C compiler on PATH was not verified, and a job failing for reasons unrelated to the change teaches people to ignore CI. The Windows job runs the suite without it.
- **Three guards skip test files.** A test has to be able to write the expected glyph, label or goroutine out in full to have something to compare against. Rendering code disguised as a test would pass all three.
- **Nothing pushed.** Creating a repository is not permission to publish it.
- **No measurements on Linux or macOS** beyond a single container run. Every runtime trust-store finding recorded so far is from one Windows machine and is not a claim about any other.
- **No real interception certificate has been seen.** Detection of TLS inspection currently rests on vendor documentation, not on a sample. This is the largest gap in evidence in the project and only the testbed closes it.
