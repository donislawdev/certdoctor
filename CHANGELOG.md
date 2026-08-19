# Changelog

All notable changes to certdoctor that a user would notice when running the program.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file records only what a person would notice by running the program. Internal structure, guards, CI and measurements are kept in a separate technical changelog that is not part of this repository, so nothing here should be read as the whole story of a change.

## [Unreleased]

Barely diagnosable yet, and there has been no release.

`certdoctor <url>` produces a whole report. Five of its eight diagnostic layers now say something about your machine - context, name resolution, TCP, TLS and the trust matrix - and the other three report `UNKNOWN` with a reason and the words "not implemented". The verdict counts them and the run ends with `5 INCONCLUSIVE`, or with `4 DIAGNOSIS` on something certdoctor can actually diagnose. What exists is the path a real answer travels, built before any answer, so that there is no point at which this program claims to have checked something it has not.

### Changed

- **`L3` now tries the addresses side by side instead of one after another**, up to eight at a time. On a name behind several addresses this means one address sitting behind a silently dropping firewall no longer eats the time the working ones needed - the others are already being tried beside it. Two things follow that you may notice: attempts are quicker on names with several addresses, and each attempt may now use the whole of what is left of the run's budget rather than a share of it divided between them.

  **The rows still come back in the order the addresses were resolved in**, never in the order the attempts happened to finish, so two reports from the same machine line up row for row.

  **Eight at a time is a ceiling rather than a tuning knob.** How many addresses a name resolves to is decided by whoever answers the DNS query, and without a cap they would be deciding how many connections this machine opens at once - which is not a decision to hand to a stranger, least of all on a network where something is watching for that shape.

### Added

- **A row of the trust matrix that does not trust the chain now carries the command that would repair it**, with the real path from your machine in it rather than a specimen path.

  **A command appears only where your machine is actually the thing to change.** Three conditions have to hold together: the server sent a complete chain, the store refused because it holds nothing that signed it, and the store is a file certdoctor could open and name. A server that forgot to send its intermediate turns every row on your machine red, and there is nothing to fix in any of those stores - so no command is offered, and the sentence says the fault is the server's.

  **Every command adds to the store that runtime already reads.** None of them points a runtime at a different bundle. Redirecting would grant the trust you asked for and quietly take away every other trust that runtime had, and you would find out days later on a different site.

  **A command that needs administrator or root rights says so before you run it**, on the line above the command rather than below it. What certdoctor cannot know - the certificate to import, and the alias it should take in a Java keystore - is listed as something to replace rather than guessed at.

  **Each row also says which way it refused.** An unknown authority, an expired certificate, one that is not valid yet, or a reason certdoctor does not classify. Only the first is repaired by importing anything - a certificate that has not started being valid is usually this machine's clock, and no import moves a clock.

  **`--json` grows `trust_failure` and `fix` on each row, and `schema_version` goes to `1.8`.** Both are `null` where there is nothing to say, which is every row of a healthy matrix.

- **`L5` reports what every runtime it can find on this machine makes of the certificate chain - one row per trust store, never one per runtime.** This is the part of certdoctor that no other tool does.

  **One row per store is the whole point.** On the machine this was measured on there are six Java trust stores from four JDK installations and two JREs, two `curl` binaries in `PATH`, and a `git` that reads a different store than the `curl` shipped beside it in the same installation. A single row saying "java" would have had to pick one of the six.

  **Each row carries the real path to the store, how many anchors it holds, and what selects that instance** - `JAVA_HOME`, `PATH`, or nothing at all, which is ordinary for a runtime an application launches by absolute path.

  **A store certdoctor cannot read is `UNKNOWN` with a reason, never a failure to trust.** A `curl` built on Schannel reads the platform store, so this layer says which probe answers for it instead of quietly answering itself. A keystore that will not open with the default password is a fact about the keystore, not about trust.

  **A runtime that is not installed is not a status.** It sits outside the matrix with a note, because "there is no Java here" is not a fact about trust.

- **`L4` completes a TLS handshake with every address that accepted a connection, and shows the full chain the server presented.**

  **The chain is shown once and the other addresses say whether they presented the same certificate.** A different certificate from one address of the same name is a finding rather than a footnote - it is the only signal this program has for a middlebox sitting on one route.

  **Each certificate shows its subject, its issuer, the names it is valid for, its validity dates and its full SHA-256 fingerprint.** The names come from `subjectAltName`, which is the field a modern client actually matches on - a certificate valid for `example.com` and `*.example.com` says so, instead of leaving you to guess from the common name.

  **The layer says whether the server sent enough to build a path**, which is the single commonest real misconfiguration there is and the one that is invisible from a browser that cached the missing certificate somewhere else. That verdict is reached from the presented bytes alone and consults no trust store, so it is a statement about the server rather than about your machine - and the sentence says so.

  **Under `--redact` the subject, the issuer and the names become pseudonyms and the fingerprint does not.** The fingerprint is the evidence you came for and it identifies nobody.

- **`L3` opens a connection to every address the name resolved to, and says what happened to each one.** This is the first thing certdoctor establishes about connecting rather than about naming. Refused, timed out, reset, no route - four different answers that a browser folds into "cannot connect", and they send you to four different places. Each row carries the address, the port and how long the attempt took.

  **One row per address, never folded together.** A name behind four addresses where one is unreachable is the "hangs for thirty seconds, then works" fault, and a single summary row would report it as either working or broken - both wrong.

  **Some addresses failing is not a warning.** If anything answers, the layer passes and the sentence says how many of how many, and across which families - because a machine without IPv6 has every IPv6 address fail on every run against every name, and a warning there would fire constantly on a working machine. If nothing answers at all, that is a failure.

  **An address that was never tried says so** rather than claiming a timeout: running out of budget is a fact about certdoctor, and a timeout is a fact about your network.

  **A name that resolved nowhere leaves this layer with nothing to do**, and it reports exactly that instead of failing a second time for a fault the previous layer already reported.

- **`L1` answers what a name resolves to, asking the resolvers this machine is configured to use.** This is the first thing certdoctor does that leaves your own process. It reads the resolvers out of the registry and the IP helper API on Windows, and out of `/etc/resolv.conf` elsewhere, then asks each of them separately for `A` and for `AAAA` - and reports one row per answer rather than one row per name, because a resolver that answers for one record type and not the other is the whole "hangs for thirty seconds, then works" class of problem.

  **Each row says which resolver answered, what it answered, and how long it took.** `NXDOMAIN`, `SERVFAIL` and `NODATA` are told apart and reported as themselves. That distinction is the reason this layer asks the resolvers directly instead of using the one built into Go: the standard resolver collapses "the name does not exist" and "resolving it failed" into a single message, and those two send you to two different places.

  **A query that got no answer says why, in its own field, rather than pretending to a response code.** Nothing came back in time, the reply could not be read, the address was not one this run was allowed to reach, or there was not enough time left to ask at all - the last one because a slow network can use up the layer's budget, and a report with fewer rows would read as a machine with fewer resolvers.

  **This is one of the two views this layer reports.** It is certdoctor's own query to a named resolver, so it is what is actually in DNS. The other one is below.

- **`L1` also asks your system the same question, the way any other program on your machine would ask it, and says which resolver actually did the work.** The row is marked `detected` when your platform resolved the name itself and `derived` when the resolver built into certdoctor stood in for it - and that is decided by what happened during the run rather than by which operating system you are on. A `derived` row also says whether your system would have looked in your `hosts` file, because certdoctor's own view never does under any configuration, and that single fact explains most of the differences you will see between the two.

  **A machine that lists no resolver of its own is still asked.** An empty `/etc/resolv.conf` does not mean names do not resolve - your platform falls back to a resolver on loopback, and certdoctor now reports what that one answered instead of saying there was nobody to ask.

- **The two views are compared, and the difference is classified rather than tested for equality.** They agree, one holds everything the other does and more, they overlap partly, only one of them found an address at all, they share no address, neither found one but somebody said so, or neither of them got any answer. **Three of those carry a verdict:** no address in common is a `WARN`, because split horizon DNS and a leak past a VPN both look exactly like that, and a name that resolves no way at all is a `FAIL` - whether that is because nobody replied or because everybody replied "no such name". The rest are named and left alone; the most common of them is your platform filtering out `AAAA` records that certdoctor asked for by name, which is a fact about the tool rather than about your network.

  The comparison uses every resolver's answer together rather than picking one, and compares them as sets, so a name behind a load balancer that returns its addresses in a different order each time is not reported as a difference.

- **`--redact` now also replaces the addresses of your resolvers**, as `[resolver-1]`, `[resolver-2]` and so on. The addresses a name resolved to stay visible, because those are the answer you came for. A resolver address is not an answer - it is what the machines inside your network are called, and `--redact` is the flag you reach for when you are about to paste a report into a ticket.

- **A slow or silent resolver no longer answers on behalf of the whole layer.** Each query gets a share of the time that is left rather than all of it, so one resolver that never replies cannot use up the budget and leave the working ones unasked. If queries were dropped anyway, the layer says how many, including on a run that otherwise succeeded.

### Changed

- **`schema_version` is now `1.5`.** It stood at `1.0` while fields were added, on the grounds that nothing was released and nobody was reading the document. It moved five times while `L1` was being built: once for a field that says a query got no answer at all, once for the class of the difference between the two views, once for a new reason, once for a new class of difference, and once because two of those classes changed what they MEAN. **The last two move the version even though no field changed shape**, because the class is a closed list a consumer branches on, and the schema itself would accept the change without a word. **Nothing is released, so this is the cheapest these changes will ever be** - and the report now says so itself, in a note, until the first release. A consumer that ignores fields it does not know needs no change.
- **`UNKNOWN` has two new reasons, and both exist because the older ones would have been a lie.** `nothing_to_check` says the layer ran correctly and there was nothing on this machine for it to look at. `transport_error` says every attempt to ask failed on the wire - a cable, a firewall, a network with no route. Both used to come out as `probe_error`, which says this program broke, and sent you to look at certdoctor when the answer was somewhere else. `probe_error` now has one meaning left: this run stopped itself.

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

- **`--redact` masks the target host wherever it appears, not only inside a URL.** It replaced a host sitting in a URL before, and now also replaces the target's name standing on its own in a field. Nothing produces a bare host name yet, so today this changes no output.

  **Not masked, deliberately: addresses.** A target given as a bare IP is therefore not concealed. A host name certdoctor was not told about is left alone.

- **Control characters in a value are shown as `\u001b`, not acted on.** A value read off your machine - a proxy variable, a path - can contain bytes that a terminal treats as instructions: colour, cursor movement, hidden text. Those bytes now appear as text instead of taking effect, so a value cannot repaint a row of the report or make a failure read as a pass. `--no-color` never covered this, because it switches off the colour certdoctor adds rather than the colour a value carries.

  They are made visible rather than deleted: the report shows what is really in your environment.

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
- **A name that resolves nowhere is reported as a failure instead of as agreement.** Asking about a name that does not exist produced `PASS` and the sentence "both views resolved this name to the same addresses" - about a name neither view had resolved. Both views had answered, both answers were empty, and two empty answers compared as equal. The two views agreeing that there is no such name is now its own class of difference and ends the run with the diagnosis exit code, which is what somebody who mistyped a URL needs to see.
- **A layer's `WARN` or `FAIL` now reaches the report at all.** Any layer answering either one was rejected on its way out and rewritten as `UNKNOWN` with `probe_error`, with a note saying the layer had broken its contract - because a verdict was required to carry a reason from the list that explains why something could NOT be assessed, and a layer that assessed something has no honest value to put there. Nothing on this machine could produce a warning or a failure until now, so no report published before this said one; from here they arrive intact, with the exit code that follows from them.
- **A name whose resolver answers SERVFAIL is reported as a failure, not as a success.** Asking about a name whose DNS server is broken produced `PASS`, under the sentence "one view resolved this name and the other did not" - and neither view had resolved it. One of them had received an answer, which is not the same as having found an address: `NXDOMAIN`, `NODATA` and `SERVFAIL` all arrive promptly and carry no address at all. The comparison of the two views now asks whether each one **found an address**, which also fixes the mirror case: a view holding addresses beside a view that answered and found none is now reported as one view resolving the name, rather than as one view containing the other.

  Found by a testbed that knows the right answer, because the expected verdict was written from its configuration before certdoctor was ever pointed at it.
- **A row no longer says a name was "resolved to 0 addresses".** When your system finds no address for a name, the row reporting it now says so in those words instead of describing the lookup as a resolution that produced nothing. The verdict above it already said the right thing; this is the line underneath, which is the one that gets pasted into a ticket.
