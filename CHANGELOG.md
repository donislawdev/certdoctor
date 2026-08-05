# Changelog

All notable changes to certdoctor that a user would notice when running the program.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file records only what a person would notice by running the program. Internal structure, guards, CI and measurements are kept in a separate technical changelog that is not part of this repository, so nothing here should be read as the whole story of a change.

## [Unreleased]

Barely diagnosable yet, and there has been no release.

`certdoctor <url>` produces a whole report. One of its eight diagnostic layers now says something about your machine; the other seven report `UNKNOWN` with a reason and the words "not implemented". The verdict counts them - "7 of 8 diagnostic layers could not be assessed." - and the run ends with `5 INCONCLUSIVE`. What exists is the path a real answer will travel, built before any answer, so that there is no point at which this program claims to have checked something it has not.

### Added

- **`L0` reports the environment this machine is configured with.** Twenty-three variables that decide what gets trusted and what gets proxied - the proxy variables, `SSL_CERT_FILE` and `SSL_CERT_DIR`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `NODE_TLS_REJECT_UNAUTHORIZED`, `JAVA_TOOL_OPTIONS`, `GIT_SSL_CAINFO` and `GIT_SSL_CAPATH`, `PIP_CERT`, `AWS_CA_BUNDLE`, and two that hint at a container. Each is reported as set, set to nothing, or not set. Those are three different answers, not two: an empty `HTTPS_PROXY` switches proxying off in some tools while an absent one sends them looking elsewhere.

  **Two of the twenty-three are there because they decide whether the others do anything.** `CURL_SSL_BACKEND` set to `schannel` makes `CURL_CA_BUNDLE` inert, so a report showing the bundle without showing the backend states a fact and implies an effect that may not exist. `NODE_USE_ENV_PROXY` is what makes Node read the proxy variables at all, so without it "`HTTPS_PROXY` is set" is a true row that says nothing about whether the Node process you are chasing ever saw it.

  **Both spellings of every proxy variable get their own row and are never merged.** `HTTP_PROXY` and `http_proxy` are not two spellings of one thing. curl honours the http one in lower case only, deliberately, so that a `Proxy:` header arriving in a CGI request cannot become a proxy setting. On Linux they are separate variables; on Windows the environment is case insensitive and they are one. A row that merged them would be true and misleading at once.

  **Credentials are removed from the values before anything is printed**, with or without `--redact`, and the report says that a value carried them - "your proxy URL has a password in it" is half the answer to a 407 and can be said without saying the password. The layer says what is set and nothing about whether it is wise: judging trust belongs to the layer that examines trust stores, and calling a setting dangerous here would put that verdict at the top of the report with no evidence under it.

  `L0` reports `PASS` when it could read the environment and `UNKNOWN` with a reason when it could not. It never reports `WARN` or `FAIL`.

- **The full flag surface**, all of it accepted and all of it in `--help`. Options whose capability is not built yet are refused with a reason and `3 CONFIG` rather than being ignored: `--format md`, `--format html`, `--in`, `--image` and `--compare`.
- **`--json`**, carrying `schema_version` as its first field. The document is checked against its own declared schema before it is printed, so a report that does not match the published contract is an internal failure rather than something a pipeline has to discover.
- **`--out <path>`** writes the report to a file instead of standard output. The file appears under a temporary name beside its destination and is renamed into place only once the bytes are on disk, so an interrupted run leaves no file that looks complete. A single dash means standard output, which is the default.
- **`--version`** reports the tool version, the report schema version, the Go version and the platform - one stable key per line. When the same input produces a different answer in six months, a CI log holding this block is the only trace of what moved.
- **`--license`** prints the licence text carried inside the binary, for the benefit of somebody holding an executable and no repository.
- **`--no-color`**, and `NO_COLOR` in the environment honoured the way its convention specifies: present and non-empty. Colour and glyphs are used only when the report is going to a terminal, and never when it is redirected to a file. On Windows the console's output code page decides whether the marker is a glyph or its ASCII substitute, so a console that would render the glyph as rubbish gets plain text instead.
- **`--timeout` and `--probe-timeout`**, in seconds, zero meaning no limit. When the overall budget runs out the remaining layers are reported as skipped, with a reason, rather than quietly missing.

- **[contract] `layers[].findings` in `--json`, and a place for findings on the terminal page.** Nothing produces one yet, so today every layer reports `null` there. That is not the same as an empty list and the difference is deliberate: `null` means this layer never looked, and `[]` will mean it looked and there was nothing to report. A consumer counting rows would otherwise read a layer that has not been written as a clean bill of health. Adding the field raises the minor version of the report schema when there is a release to raise it in.

- **[contract] A second kind of finding, `name_resolution`, exists in the document.** Nothing produces one yet, so today every finding carries `"name_resolution": null` beside its body and the key is the only visible change. When the layer that resolves names is written, a finding of this kind will carry the name, which of the two views it came through, which resolver answered, the record type asked for, the response code, the addresses and how long it took.

  **Two views, not one, and neither is the "right" one.** What this system resolves a name to and what is actually in DNS are different answers on most machines, both correct, and a diagnosis needs both. The view that was measured the way your runtime would ask it cannot report a resolver, a record type or a response code, because the operating system does not tell anyone those - so those fields stay null there rather than being filled in with something plausible.

  🔴 **The schema version deliberately did not move for this.** Adding a field raises the minor version, and the rule stands - but nothing has been released, `1.0` has never left the repository, and a consumer holding output for years does not exist yet. On the first release the declared version will be made to match the shape the document actually has. A pipeline reading this today should ignore keys it does not know, which is what the contract asks of it anyway.

- **The report says which privilege level it was taken at.** `run.privilege_level` used to read `unknown` on every machine because nothing established it. It now reports `elevated` or `user`, read from the process token on Windows and from the effective user id elsewhere. When the operating system does not answer, the level stays `unknown` and the report says so in its notes rather than guessing - certdoctor run as an administrator sees trust stores and runtime installations that an ordinary user cannot, so two reports taken at different levels are different documents rather than one being less complete.

### Changed

- **The verdict counts the layers it could not assess instead of saying nothing was assessed.** It used to read "Nothing could be assessed yet.", which was true while every layer was a stub and became false the day one of them was not. It now reads "7 of 8 diagnostic layers could not be assessed." The exit code is unchanged: a run with anything unassessed still ends `5 INCONCLUSIVE`, because one layer passing does not make a run conclusive.
- **The note saying no layer was implemented is gone.** It announced something that has now partly arrived, and a note kept past that point teaches people that notes are boilerplate - after which the one that matters goes unread with the rest. What it said is now counted from the rows themselves rather than asserted.

- **The URL needs an explicit `http://` or `https://` scheme.** Guessing one would have to cope with `localhost:8080`, which reads as a scheme and an opaque part, and a tool that quietly diagnoses a different address than the one it was asked about is worse than one that asks for a clearer question.
- **[contract] The target is now masked rather than cut back to its origin.** The report used to show scheme, host and port and drop everything else. It now shows the whole URL with the dangerous parts taken out BY POSITION: user info is replaced, every query parameter keeps its name and loses its value, the path becomes a single marker, and the fragment is dropped. The report still says something was removed.

  The parameter names surviving is the point. "Your URL carries a token" is half a diagnosis and can be said without saying the token, and cutting back to the origin threw that half away. The path is not inspected for which segments look like identifiers, because that needs a threshold on length or entropy that nobody has measured, and a leaked session identifier cannot be withdrawn while a lost path costs one sentence.

- **`--redact` does something.** It was accepted and the report said, honestly, that it had changed nothing. It now masks host names in the report, including the target's, replacing each with a stable pseudonym such as `[host-1]` so that two mentions of one machine still read as one machine. Credentials are removed either way, with or without the flag.

- **The value of a setting whose NAME says it is a secret is removed in full.** Previously only values with a recognisable shape were caught - user info inside a URL, an authorization header. A variable simply called something like `PROXY_PASSWORD` would have gone into the report as it stood. The name is read in segments, so `NODE_TLS_REJECT_UNAUTHORIZED` keeps its value: it merely contains the word "auth", and that value is the finding.
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
