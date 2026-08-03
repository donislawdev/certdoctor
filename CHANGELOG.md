# Changelog

All notable changes to certdoctor that a user would notice when running the program.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file records only what a person would notice by running the program. Internal structure, guards, CI and measurements are kept in a separate technical changelog that is not part of this repository, so nothing here should be read as the whole story of a change.

## [Unreleased]

Nothing diagnosable yet, and there has been no release.

`certdoctor <url>` now produces a whole report, and every line of it says that nothing was assessed. All eight diagnostic layers report `UNKNOWN` with a reason and the words "not implemented", the verdict reads "Nothing could be assessed yet.", and the run ends with `5 INCONCLUSIVE`. There is nothing useful to learn from it. What exists is the path a real answer will travel, built before any answer, so that there is no point at which this program claims to have checked something it has not.

### Added

- **The full flag surface**, all of it accepted and all of it in `--help`. Options whose capability is not built yet are refused with a reason and `3 CONFIG` rather than being ignored: `--format md`, `--format html`, `--in`, `--image` and `--compare`. `--redact` is accepted and says in the report that it changed nothing, because there is nothing to mask yet.
- **`--json`**, carrying `schema_version` as its first field. The document is checked against its own declared schema before it is printed, so a report that does not match the published contract is an internal failure rather than something a pipeline has to discover.
- **`--out <path>`** writes the report to a file instead of standard output. The file appears under a temporary name beside its destination and is renamed into place only once the bytes are on disk, so an interrupted run leaves no file that looks complete. A single dash means standard output, which is the default.
- **`--version`** reports the tool version, the report schema version, the Go version and the platform - one stable key per line. When the same input produces a different answer in six months, a CI log holding this block is the only trace of what moved.
- **`--license`** prints the licence text carried inside the binary, for the benefit of somebody holding an executable and no repository.
- **`--no-color`**, and `NO_COLOR` in the environment honoured the way its convention specifies: present and non-empty. Colour and glyphs are used only when the report is going to a terminal, and never when it is redirected to a file. On Windows the console's output code page decides whether the marker is a glyph or its ASCII substitute, so a console that would render the glyph as rubbish gets plain text instead.
- **`--timeout` and `--probe-timeout`**, in seconds, zero meaning no limit. When the overall budget runs out the remaining layers are reported as skipped, with a reason, rather than quietly missing.

- **[contract] `layers[].findings` in `--json`, and a place for findings on the terminal page.** Nothing produces one yet, so today every layer reports `null` there. That is not the same as an empty list and the difference is deliberate: `null` means this layer never looked, and `[]` will mean it looked and there was nothing to report. A consumer counting rows would otherwise read a layer that has not been written as a clean bill of health. Adding the field raises the minor version of the report schema when there is a release to raise it in.

- **The report says which privilege level it was taken at.** `run.privilege_level` used to read `unknown` on every machine because nothing established it. It now reports `elevated` or `user`, read from the process token on Windows and from the effective user id elsewhere. When the operating system does not answer, the level stays `unknown` and the report says so in its notes rather than guessing - certdoctor run as an administrator sees trust stores and runtime installations that an ordinary user cannot, so two reports taken at different levels are different documents rather than one being less complete.

### Changed

- **The URL needs an explicit `http://` or `https://` scheme.** Guessing one would have to cope with `localhost:8080`, which reads as a scheme and an opaque part, and a tool that quietly diagnoses a different address than the one it was asked about is worse than one that asks for a clearer question.
- **The report shows the target as its origin only** - scheme, host and port. A path, a query string or user info is dropped and the report says so. The masking that would let more of the URL be printed safely is not built yet, and a URL can itself carry a token or a session identifier.
- **The host in the target is reported in lower case.** Names in DNS are case insensitive, so `EXAMPLE.COM` and `example.com` are one machine, and reporting them as typed made one machine look like two when reports were compared. A path and a query string are case sensitive and are left exactly as they were.
- **An unknown switch is named in the error message.** It used to consume nothing, so the argument behind it became the URL and the real URL was reported as an unexpected extra argument - the message pointed at the only correct part of the command line.
- **`--timeout` and `--probe-timeout` refuse a value below a millisecond.** Anything smaller rounded down to zero, and zero is how you ask for no limit at all, so the strictest budget you could type produced a run with no budget. Zero still means no limit.
- **`--json` together with an explicit `--format terminal` is refused** rather than quietly producing JSON. `--json` on its own is unchanged.
- **Two of `--help`, `--version` and `--license` at once are refused** rather than one of them being answered and the rest dropped without a word.
- **Writing a report to a path says so on the log channel**, with the path and the size. A successful `--out` used to produce nothing on either channel, so a typo in the path looked exactly like a report that had been written.
- **Colour is switched off on a console that does not interpret escape sequences.** A Windows console without virtual terminal processing printed them literally, which made the report look corrupted rather than coloured.
- **`started_at` carries sub-second precision.** Two runs inside the same second used to carry the same timestamp, which made a pair of saved reports impossible to put in order.
- **A number written with a comma is answered with the dot it needs.** `--timeout 1,5` used to produce `invalid value "1,5" for flag -timeout: parse error` - a switch named with one dash where the rest of this program uses two, and nothing at all about the comma. It now says what to write instead.
- **A device as the destination is refused with an answer.** `--out /dev/null` and `--out NUL` used to fail with a message about a temporary file nobody had asked for. A report is written under a temporary name and renamed into place, which cannot be done to a device, and the message now says so and points at `-` for standard output.
