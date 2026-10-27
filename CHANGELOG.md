# Changelog

All notable changes to certdoctor that a user would notice when running the program.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file records only what a person would notice by running the program. Internal structure, guards, CI and measurements are kept in a separate technical changelog that is not part of this repository, so nothing here should be read as the whole story of a change.

## [Unreleased]

Barely diagnosable yet, and there has been no release.

### Changed - an append command waits for a line break, and keytool says which shell it is for

- **A store file that does not end with a line break gets no append
  command.** The command joins bytes and nothing else, so the certificate's
  first line would have continued the file's last line, and neither the
  certificate ending there nor the one added would have been read - the
  store would have lost a certificate rather than gained one. The row now
  says why it has no command and what to do: end the file with a line break
  and run certdoctor again. This covers every row whose command appends to a
  file - curl, git, python reading a file, the Linux system store, and node
  adding to the file NODE_EXTRA_CA_CERTS names. Where certdoctor could not
  read the end of that file, it offers no command either, and says so.
- **The keytool command on Windows says it is for the Command Prompt.** It
  begins with the path to keytool in quotes, which cmd.exe runs and
  PowerShell prints as text. Its note now says so, and that PowerShell runs
  the same line with & and a space put before it.

### Changed - who signed a certificate is said as a count, and a wrong name comes first

- **The sentence about who signed a certificate counts the stores
  certdoctor assessed, and speaks for no other.** It used to say "no store
  on this machine" and "a browser included", and on Linux a browser reads a
  store of its own that certdoctor does not. A signer some stores hold and
  others do not was called "an authority local to this machine", and an old
  Java missing a public root splits the stores in exactly the same way. The
  sentence now says how many of the stores assessed here hold an anchor for
  the signer and how many do not.
- **A certificate for another name is the cause on the top line, even when
  only some stores hold its signer.** Adding that signer to the other stores
  would not make the name fit. A signer whose name is a TLS inspection
  product still comes first, because the certificate then came from that
  product and not from the server.
- **The top line that blames the server for a missing issuer counts stores
  the way the signer's sentence does**, one for each file they read, so the
  two never give one phrase two numbers. A store that refused the chain for
  its dates, its revocation or a rule no longer counts as one that built no
  path. It built one and judged it, so the server is not blamed then.

### Changed - addresses that present different chains are a warning

- **When the addresses of one name present different chains, the TLS layer
  warns.** It used to compare the first certificate alone and pass, so one
  certificate under two different intermediates read as the same answer, and
  a second address with another certificate changed only a sentence. The
  whole chain is compared now, in its order. A row whose certificate is the
  first address's says when its chain is not.
- **The trust matrix says which chain it judged.** It judges the first
  address's, and when other addresses presented another one its sentence
  says how many did. A matrix for each chain is planned for after 0.1.0.

### Changed - a chain without its issuer is a warning, and stores decide who is to blame

- **A server that does not send the issuer of its certificate makes the
  TLS layer warn rather than fail.** The bytes cannot tell a missing
  intermediate from a root the server is allowed to leave out, and a
  certificate signed straight by a company root is ordinary. Every store
  holding that root builds a path, and such a run used to end on a failure
  that blamed the server. The layer now says that only a client already
  holding the issuer can build a path.
- **The top line still blames the server when no store it assessed built
  a path**, and now says how many stores were asked. When one did, the
  stores that refused are the cause, as for any other chain.
- **Whether the issuer arrived is decided by its key, not only by its
  name.** A certificate carrying the issuer's name with another key - an
  issuer re-issued, sent in its old form - was taken for the issuer.

### Fixed - four small things about files, machines and DNS answers

- **On Linux, two binaries whose names differ only by case are two rows.**
  certdoctor folded case when it told files apart, as Windows does, so one of
  them was hidden. Windows and macOS still fold it, as their usual
  filesystems do.
- **A Java or git row names the machine its binary was built for.** It is
  read from the binary itself - x86, x64 or arm64 - and left empty when the
  binary does not say. It used to be read off the path, which called every
  install outside "Program Files (x86)" x64, an ARM Mac's included.
- **A DNS answer that carries records and no question is not believed.**
  Nothing tied its records to the name that was asked, so a forged answer
  only had to guess the query's identifier. A resolver's refusal with no
  question and no records is still read.
- **A header value followed by a long run of blanks is masked quickly.** The
  time it took grew with the square of the run.

### Changed - regular expressions in an automatic configuration script

- **A PAC file's regular expressions are evaluated by a newer engine.** Two
  of its fixes concern searches that skipped a valid match, so a script whose
  expression should have matched could have been read as sending the URL
  another way.

### Changed - a proxy that cannot be reached is a failure, not a pass

- **A proxy this URL goes through that refuses the connection now fails the
  proxy layer.** Only a demand for credentials used to change its answer, so
  a machine whose only proxy was down could end on "everything passed". A
  proxy that stays silent for the time certdoctor allows makes the layer
  unknown with the reason `timeout`. Any HTTP answer other than 407 is still
  read as before.
- **The top line says when what failed was the direct route and a proxy
  applies to the URL.** certdoctor resolves, connects and shakes hands
  directly, so a name only the proxy resolves, or a firewall that lets only
  the proxy out, fails those steps while a program set to use the proxy gets
  through. The cause is still named, now with that said beside it.
- **Two automatic configuration scripts that send one URL two ways are a
  warning.** The first script read used to decide the sentence and the layer
  passed, so the order in which certdoctor read the places chose which
  configuration the report described.

### Fixed - reading files and starting programs cannot hold a run

- **A path that is not a regular file is refused before it is read.** A pipe
  nobody writes to, a terminal or a directory named by a variable such as
  `SSL_CERT_FILE`, or found on PATH, could hold the run for ever - a limit on
  bytes does not stop a read that never starts.
- **A huge directory is refused while it is being listed**, rather than read
  in full, sorted and then turned down.
- **A Java store whose listing was cut short is not judged.** Only the first
  part of it used to be read, so a root past the cut showed as missing and the
  row advised importing a certificate the store already held.
- **git's include files are limited in number as well as in depth.** A shallow
  configuration including the same files many times was read over and over.
- **On Linux and macOS, a program started through a wrapper is stopped with
  it.** When certdoctor's time for a runtime ran out, a shim that started the
  real runtime as its own child left that child running.

### Fixed - three things about asking a proxy

- **A proxy reached over TLS is no longer asked in plain text.** An
  `https://` entry, or a script's `HTTPS` keyword, used to get the same
  plain request as any other proxy, which such a proxy reads as a broken TLS
  greeting - the run then waited out its time on an answer that could not
  come. Its row now says it was not asked and why, as a SOCKS proxy's does.
- **A proxy answering at once is not kept waiting for its error page.** The
  answer was read from the head, and then the connection was held open while
  the rest of the page arrived, until the time ran out.
- **The line for a proxy setting says what its exception list says.** It used
  to read "a proxy applies" over a `no_proxy` that sends the URL past it. It
  now says the list excuses the URL, or that programs reading the list
  differently disagree about it.

### Fixed - a PAC script's answer is believed only when it can be

- **An answer made only of entries a client cannot follow no longer passes.**
  Unknown keywords, or `PROXY` with no address after it, used to settle the
  proxy layer - and `PROXY` alone was even reported as sending the URL past
  every proxy. Such an entry is now skipped, as a client skips it, and an
  answer with nothing left says so and leaves the layer undetermined.
- **An answer that rested on a resolver that did not answer is not taken as
  the route.** A script asking `dnsResolve` and choosing `DIRECT` when it gets
  nothing back was given the same nothing for a resolver that timed out, and
  its answer was reported as settled. The row now says a resolver gave no
  usable answer.
- **A script cannot hold the run past its time any more.** `shExpMatch` over
  very long strings ran in native code the time limit could not stop, an
  answer of millions of entries was read in full, and an evaluation that
  started late in the proxy layer got its whole time again. Long matches now
  stop at the time limit, an answer longer than 16 KiB or with more than 64
  entries is refused as too large, and the layer's own deadline and an
  interrupted run stop the script.

### Fixed - `--redact` no longer throws away a report with a command in it

- **A report whose remediation command holds a placeholder spelled like a name
  being masked is printed.** With a host or a name called `certificate.pem` or
  `alias`, masking reached into `<certificate.pem>` or `<alias>`, the command no
  longer held the placeholder it named, and certdoctor refused to print the
  report at all. The placeholders now stay as they are and only the text around
  them is masked.

### Changed - a refusal the Go library may have made is not pinned on a store

- **certdoctor is built with Go 1.27.3**, which refuses every chain through one
  of eight intermediate certificates, whatever store is asked (GO-2026-6809).
  certdoctor judges other programs' stores with that library, and those
  programs do not refuse the eight on their own. So a row whose chain or store
  holds one of them, and which would read as refused for a reason other than an
  unknown authority or a date, now says it could not be assessed, and why.

### Added - Python is judged by the list its ssl module trusts

- **Every Python interpreter that `python`, `python3`, `pip` or `pip3` on PATH
  leads to gets a row** - one row per interpreter, however many names reach it.
  A virtual environment is a row of its own, and `selected_by` names the
  commands that reach each interpreter first. Each is asked once, with a fixed
  script and no network, for the certificates its default context holds, and
  the chain is judged by the rule that interpreter's own flags set: from Python
  3.13 every certificate on its list ends a chain, before that only a
  self-signed one does.
- **The hashed certificate directory counts.** Python does not list it, and on
  Fedora it is all Python reads, so certdoctor reads the files OpenSSL would
  open there - `SSL_CERT_DIR` when it is set, the default directory when not.
- **A row that refuses gets a command.** On Linux it appends the certificate to
  the file Python reads, spelled as the platform store's row spells it when it
  is the same file. On Windows it is `certutil -user -addstore Root`, the store
  Python's list comes from. A Python reading only the hashed directory gets no
  command.
- **Python 3.13 and newer is held to OpenSSL's strict rules**, as it holds the
  chain itself. A chain that breaks one - an intermediate that does not name the
  key that signed it, a certificate authority whose basic constraints are not
  marked critical, and the other rules of `VERIFY_X509_STRICT` - is refused
  with `trust_failure` `nonconforming_certificate`, and the row's summary names
  the certificate and the rule. No command comes with it, because adding a
  certificate to a store does not reissue one. The rules are OpenSSL 3's, so a
  Python built with another OpenSSL is left unassessed where it would trust. A
  refusal is still reported as one.
- **[contract] The schema version is now 2.3.** `trust_failure` has a sixth
  value, `nonconforming_certificate`. Nothing is removed.
- **The interpreter runs none of your code.** It is started with `-I -S -B`, so
  `PYTHONPATH`, `.pth` files and `sitecustomize` are not read and no bytecode is
  written, and without `SSLKEYLOGFILE` and `OPENSSL_CONF`.
- **A Python started through an app alias in `WindowsApps` is found too.** The
  alias is started with the same script and the interpreter says which one it
  is, so it shares a row with that interpreter wherever else PATH reaches it.
  The stand-in that offers to install Python from the Microsoft Store is never
  started, and neither is an alias of pip - both still take the command name,
  since typing it reaches them first. Measured with the Python install manager,
  not with Python from the Microsoft Store.

### Changed - a curl row it cannot assess says what that curl reads

- **curl on GnuTLS, wolfSSL, mbedTLS or rustls** no longer says it reads the
  platform's store and that the `system-store` row answers for it. Those
  libraries read the CA file curl hands them - the one `CURL_CA_BUNDLE`,
  `SSL_CERT_FILE` or `SSL_CERT_DIR` names, or the one the build was made with -
  and the row now says so. curl on NSS or Secure Transport, two backends curl
  has removed, says which release removed it. All of these rows stay
  unassessed.
- **curl on Windows reading a CA file**, with none of those variables set,
  says it looks for a `curl-ca-bundle.crt` first - beside itself, in the
  directory it runs in, in Windows's own directories and along `PATH` - where it
  used to say only that it reads its build-time default.

### Fixed - a curl certdoctor starts no longer creates a key log file

- **curl is started without `SSLKEYLOGFILE` and `OPENSSL_CONF`.** A curl built on
  OpenSSL opens the file `SSLKEYLOGFILE` names as soon as it starts, so asking it
  for its version created that file - a write certdoctor promises never to make.
  The configuration `OPENSSL_CONF` names is loaded at the same moment and can
  load a module into curl, so it is left out too. curl on Schannel, which is
  every curl on a stock Windows, created no file before either.

### Added - node is judged by the list it trusts

- **Every `node` on PATH gets a row.** Each is asked once, with a fixed script
  and no network, for the certificates it trusts: the list compiled into that
  binary, widened by the file `NODE_EXTRA_CA_CERTS` names and, when
  `NODE_USE_SYSTEM_CA=1` or `--use-system-ca` turns it on, by the platform's
  certificates as Node reads them. The row names which of those variables made
  a difference.
- **Only a self-signed certificate on that list ends a chain**, because that is
  what Node does - an intermediate alone in `NODE_EXTRA_CA_CERTS` does not make
  the server trusted, and the row no longer says it does.
- **node is started without `NODE_OPTIONS`**, without the variables that make
  it write files, and without `OPENSSL_CONF`, so neither a `--require` there nor
  a module an OpenSSL configuration names runs inside the process certdoctor
  starts. The certificate switches in `NODE_OPTIONS` are still read, the way
  Node reads them, and passed on.
- **A command where node refuses:** `setx NODE_USE_SYSTEM_CA 1` on Windows or
  `export NODE_USE_SYSTEM_CA=1` elsewhere when the certificates this system
  trusts would close the chain, the variable is not set and that node reads it.
  Otherwise `setx NODE_EXTRA_CA_CERTS` or `export NODE_EXTRA_CA_CERTS` when that
  variable is not set, and an append to the file it names when node read
  certificates from it. A variable that is already set is never changed or
  pointed at another file, because that would take away whatever it gave.
- **A node built by a Linux distribution** trusts OpenSSL's store rather than
  its own list. When it came with Debian, Ubuntu, Alpine, RHEL, CentOS, Rocky
  or AlmaLinux and nothing points OpenSSL elsewhere, its row judges by
  `system-store <distribution>` and carries that row's answer, like curl and
  git - the file OpenSSL reads by default there is the one that row judges.
  `SSL_CERT_FILE`, `SSL_CERT_DIR` or `NODE_EXTRA_CA_CERTS`, a node with an
  OpenSSL of its own, and Fedora, whose OpenSSL does not read that file, each
  leave the row unassessed with its own reason. With `--use-bundled-ca` such a
  node trusts its compiled-in list again and is judged by it.
- **`--use-openssl-ca` followed by `--no-use-openssl-ca`** leaves node on
  OpenSSL's store, because the second does not take the first back. The row
  used to judge the compiled-in list there and could refuse a chain node
  trusts - it now says node trusts OpenSSL's store.
- **`L0` reads `NODE_USE_SYSTEM_CA` and `NODE_OPTIONS`**, which makes 25
  variables.
- **[contract] The schema version is now 2.2.** `store_form` has a third value,
  `builtin` - a list compiled into the program, with an empty `store_path`.
  A node row whose node trusts OpenSSL's store carries `system` instead.
  Nothing is removed.

### Changed - curl and git on Linux take the answer of the system store

- **curl and git that came with the distribution, naming no CA file, now get
  a verdict.** They read the bundle the distribution built them with, and that
  is the file the `system-store` row already judges - so their rows say they
  judge by `system-store <distribution>` and carry that row's answer, where
  they used to say only that the file was compiled in. The command printed for
  the `system-store` row is the one that fixes all three.
- **It happens only when it is known to be true:** the binary belongs to the
  distribution's own package (dpkg, apk, or `rpm -qf`), the distribution is one
  whose recipe for libcurl names the file - Debian, Ubuntu, Alpine, RHEL,
  CentOS, Rocky Linux, AlmaLinux and Fedora - that file is the one the
  `system-store` row read, and nothing curl or git honours names another file.
  When one of those does not hold, the row says which.
- **A named `http.sslBackend` never defers**, and neither does a build outside
  a package - a curl copied into `/usr/local/bin` stays without a verdict.

### Fixed - git is judged by the configuration it actually reads

- **`~/.gitconfig` wins over `~/.config/git/config`.** git reads the second
  one first, so where both set the same key the row now judges the value git
  uses - it used to judge the other one.
- **git's other configuration channels are followed:** `GIT_CONFIG_GLOBAL`,
  `GIT_CONFIG_SYSTEM`, `GIT_CONFIG_NOSYSTEM`, `XDG_CONFIG_HOME`, the
  `GIT_CONFIG_COUNT` pairs, and on Windows the home directory git computes from
  `HOMEDRIVE` and `HOMEPATH` before `USERPROFILE`.
- **The configuration is read the way git reads it** - a key on its section's
  line, a comment after a value, quoted values and escapes, an `[include]`
  applied where it stands, `~/` and `:(optional)` in a path. A file git stops
  on - a syntax error, a CA path with no value, includes nested past ten -
  leaves the row without a verdict, where it used to read as setting nothing.
- **What this program does not follow is named instead of skipped:** an
  `[includeIf]` or an `[http "<url>"]` section that sets `http.sslBackend`,
  `http.sslCAInfo`, `http.sslCAPath` or `http.sslVerify`, and
  `GIT_CONFIG_PARAMETERS`.
- **An empty `http.sslCAInfo` or `http.sslCAPath` is reported as set and
  empty**, as an empty `GIT_SSL_CAINFO` already was, rather than as nothing
  named.

### Fixed - curl and git are judged by the file they actually read

- **git follows `GIT_SSL_CAINFO` and `GIT_SSL_CAPATH`.** git reads them after
  its configuration, so a row judged by `http.sslCAInfo` while `GIT_SSL_CAINFO`
  pointed elsewhere spoke about a file git did not read - and offered to add
  the certificate to it. The row now reads the file the variable names, and a
  directory named by `GIT_SSL_CAPATH` or `http.sslCAPath` leaves the row
  without a verdict and says why.
- **git with certificate checks switched off is not judged by any store.**
  `GIT_SSL_NO_VERIFY`, set to anything at all, or `http.sslVerify` set to false
  makes git accept any certificate, and the row now says so.
- **curl follows `SSL_CERT_FILE` and `SSL_CERT_DIR`** as well as
  `CURL_CA_BUNDLE`, in curl's own order: `CURL_CA_BUNDLE` wins, a file named by
  `SSL_CERT_FILE` is read the same way, and a directory named by
  `SSL_CERT_DIR` leaves the row without a verdict.
- **A curl that reads a CA file looks for its configuration file too**, in the
  places curl itself looks on that platform, and a row that finds one names it
  and is not assessed.
- **On Linux, a refusal by the named file is checked against
  `/etc/ssl/certs`.** curl and git as Debian, Ubuntu and Alpine build them read
  that directory as well as the file they are given, so when a certificate
  there completes the chain the row says the answer depends on how the tool was
  built, instead of a refusal that may be false.
- **On Linux, git that names no TLS backend is judged by the file
  `GIT_SSL_CAINFO` or `http.sslCAInfo` names**, where it used to say it could
  not be assessed.

### Changed - the terminal report fits a window 100 columns wide

- **Long sentences wrap.** A layer's rows were padded to its longest one, so a
  single long sentence in the trust matrix made every row of it hundreds of
  characters wide. Rows are now padded into columns only when the whole layer
  fits in 100 columns, and otherwise each row is written as text, wrapped
  under itself.
- **What is meant to be copied is never broken.** A repair command, a
  fingerprint, a certificate's name, a value read off the machine and each
  entry of a list stay whole on one line, even when that line runs past 100
  columns - a command broken in two would be pasted as two. Lists wrap between
  their entries.
- Only the terminal report changed. `--json`, `--format md`, `--format html`
  and the exit codes are as they were.

### Changed - curl on Schannel is judged by this account's Windows store

- **[contract] curl built on Schannel now gets an answer.** Its rows said on
  every Windows run that they could not be assessed, which turned an ordinary
  run into a warning. Schannel judges with the store of the account running
  curl, so each such row now carries the answer of the `system-store
  CurrentUser` row, and a new member of the row, `defers_to`, names that row.
  The line saying how widely this machine holds the signer counts that store
  once, not once per curl.
- **[contract] curl on Schannel refuses a server certificate that names nowhere
  to check whether it was revoked**, even when the store trusts the chain, and
  the row now says so with a new `trust_failure` value, `no_revocation_info`,
  and that `--ssl-revoke-best-effort` lets curl connect. No store command
  repairs it, so the row carries none.
- **A curl configuration file stops that answer.** A `.curlrc` can point curl at
  a CA file of its own or turn revocation checks off, and certdoctor does not
  read it, so a row that finds one names the file and says it could not be
  assessed.
- **[contract] The schema version is now 2.1.** One member and one value are
  added, nothing is removed.

### Fixed - a curl built with several TLS backends is read by the one it uses

- curl prints every backend it did not select in brackets, and a build such as
  `OpenSSL/3.5.7 (Schannel)` was read as Schannel. The selected backend is now
  the one outside the brackets.

### Changed - the report carries six layers, so a healthy target can end with exit code 0

- **[contract] L6 (containers) and L7 (report) are no longer in the report.**
  Both stood in every run as `UNKNOWN` "not implemented", so a run against a
  healthy target never ended with exit code 0. The report and `--json` carry
  `L0` to `L5`, the verdict counts "of 6", and a note says that diagnosis from
  inside a container is not built yet. To look inside a container, run
  certdoctor there.
- **[contract] The schema version is now 2.0.** `layers` carries six entries
  where it carried eight. That is a removal, which the schema's own rule counts
  as a major change.

### Changed - a machine with no proxy anywhere passes the proxy layer

- **[contract] No proxy, no automatic configuration script and no automatic
  discovery is now an answer.** On such a machine - the ordinary Linux machine
  or container - the proxy layer reported `UNKNOWN` with the reason
  `nothing_to_check`, one of the reasons a healthy target never ended with
  exit code 0. It now passes and says that a program following these
  settings reaches the URL directly. When one of the places this machine keeps
  proxy settings in could not be read, the layer stays `UNKNOWN`, now with the
  reason `undetermined`, because the unread place may be the one naming a
  proxy. Automatic proxy discovery switched on still leaves the layer
  `UNKNOWN`, since this run does not perform it.

### Fixed - a certificate issued for another name fails the TLS layer

- **[contract] A server presenting a certificate for a different name passed
  as healthy.** On `wrong.host.badssl.com` the report read "Everything
  assessed passed", while every client refuses that server whatever it trusts.
  The TLS layer now fails when the certificate's names do not cover the host in
  the URL, the sentence at the top says which names it does cover, and the run
  ends with exit code 4. A certificate with no subjectAltName at all, naming
  the host only in its common name, is a warning instead: current rules forbid
  that, and some older clients still accept it.
- **[contract] `name_covered` in `--json`**, on every `tls_handshake` row whose
  address presented a certificate: `true`, `false`, or `null` where no
  certificate arrived. A name present only in the common name is `false`, and
  the TLS layer's status - a warning rather than a failure - tells the two
  apart. The schema version is now 1.16.

### Fixed - a self-signed server certificate is no longer reported as a missing issuer

- **A server presenting a certificate that signed itself was told it had not
  sent the issuer** - so the report sent you to the server's administrator for
  a certificate that does not exist. Most self-signed server certificates say
  they are not an authority, and that is what confused the check. The TLS
  layer now passes such a chain as complete, and the sentence at the top says
  that the certificate "signed this certificate itself" and whether any store
  on the machine holds it. A certificate that only names itself as its issuer,
  without its own signature, is not described that way.

### Fixed - Java is found where its own container image puts it

- **In the official `eclipse-temurin` images Java lives in `/opt/java/openjdk`,
  and the trust matrix had no Java row there at all**, while saying Java had
  been looked for. Every `java` on `PATH` now leads to its installation, so the
  row appears, with the `keytool` command for that store. An installation
  reached both through `PATH` and under `/usr/lib/jvm` is still one row.
  `JAVA_HOME` still only says which installation it points at, and never adds
  one.

### Fixed - one binary reached through two directories is one row

- **On Debian, Ubuntu and other distributions where `/bin` is a link to
  `/usr/bin`, every `git` and `curl` appeared twice** in the trust matrix, once
  for each directory on `PATH`. Each binary is now one row, named the way
  `PATH` reaches it first. Two different binaries are still two rows.

### Fixed - `--help` no longer says that nothing is built

- **The help page ended with a section claiming that no diagnostic layer was
  implemented** and that `--redact` had nothing to mask. Neither has been true
  for a long time, and the section is gone. An option that is accepted and not
  built yet, such as `--in`, still says so when you use it.

### Changed - a passing run says when the platform's store could not judge the chain

- **The sentence at the top no longer reads as a clean pass on a machine with
  no CA bundle.** When nothing failed but a row for the platform's own store
  could not judge the chain, the sentence reads "Everything assessed passed,
  but" followed by that row's own words - on `ubuntu:24.04`, that there is no
  CA bundle and which package installs it. A certificate copied by hand into
  `/etc/ssl/certs` is said the same way. Other runtimes that could not be
  assessed are still only counted, a proxy demanding credentials keeps the one
  "but" when both apply, and the exit code is unchanged.

### Added - the Linux trust store has a row of its own

- **On Linux the trust matrix now asks the platform's store too.** There it is
  a file, and the row reads the one Go itself reads - the first CA bundle on
  Go's own list. The row is named after the distribution, such as
  `system-store debian`, and carries the path and how many roots it holds.
  `SSL_CERT_FILE` and `SSL_CERT_DIR` are not followed by this row - they point
  programs away from the platform's store, and they are reported with the
  other variables.

- **A machine with no CA bundle says so.** `ubuntu:24.04` and
  `debian:trixie-slim` ship without one, and the row is `UNKNOWN` with a
  sentence naming the package that installs it, never `FAIL`.

- **A certificate copied by hand into `/etc/ssl/certs` is noticed.** When the
  bundle refuses a chain and a certificate in that directory would close it,
  the row is `UNKNOWN` and says that programs reading the directory trust the
  chain and programs reading only the bundle do not.

- **A refusing Linux row carries a command** - `cat '<certificate.pem>' >>`
  followed by the bundle's real path, marked as needing root. It appends and
  nothing else. Its note says that `update-ca-certificates` and
  `update-ca-trust` rebuild the bundle and drop what was appended, and where a
  copy survives the rebuild. Like every other command, it only appears where
  the chain was complete or another store on this machine closed it.

### Added - the Windows trust store has rows of its own

- **The trust matrix now asks the Windows store itself, twice.** One row says
  what a program running as this account would make of the chain, the other
  what a service running as the machine would. A root added to this account's
  store alone is the shape of "the browser works and the service does not",
  and one row could not show it. Each row carries how many roots that store
  holds. macOS does not have these rows yet.

- **No network is used to answer.** Windows would normally fetch a missing
  certificate from an address written into the certificate by the server - so
  certdoctor asks with that switched off. A root Microsoft publishes and this
  machine has not downloaded yet then looks like an authority nobody
  installed. certdoctor tells them apart with this machine's own copy of
  Microsoft's root program list. Where the list names the issuer, where the
  certificate names an address to fetch the issuer from, or where the list is
  missing or has not been brought up to date for thirty days, the row is
  `UNKNOWN` with that reason - never `FAIL`.

- **A refusing Windows row carries a command.** `certutil -addstore Root
  "<certificate.pem>"` for the machine's store, marked as needing
  administrator rights, and `certutil -user -addstore Root "<certificate.pem>"`
  for this account's store, which needs none and makes Windows ask for
  confirmation. Like every other command, it only appears where the chain was
  complete or another store on this machine closed it.

- **The trust matrix grows by two rows on Windows**, so its counts change - on
  the machine this was developed on, "9 of 11 store(s)" became "11 of 13" for
  the same site. Exit codes are unchanged, and no field of `--json` was added
  or renamed. A `trust_store` row may now carry a `fix` while its
  `store_form` is `system` - only when its `runtime` is `system-store`.

### Changed - an http:// target is no longer handed a TLS handshake

- **An http:// target gets no TLS handshake and no trust matrix, and the
  report says why.** The TLS layer used to send a ClientHello to the plain HTTP
  port and report "none of the 1 address(es) completed a TLS handshake" as a
  failure - which the first line of the report then named as the cause. There
  was nothing to complete. The TLS layer and the trust matrix now both answer
  `UNKNOWN` with the reason `nothing_to_check`, and the TLS row says what to
  type instead: "the target was given as an http:// address, which does not
  use TLS, so no handshake was attempted - give the https:// address to
  diagnose TLS".

- **The scheme decides, not the port.** `http://host:443/` is a target without
  TLS, because a client following that URL speaks plain HTTP to port 443.
  `https://host:80/` is still a TLS target, and its failure is still reported.

- **What this changes for a script.** A run against an http:// target where
  nothing else fails now ends with `5 INCONCLUSIVE` instead of `4 DIAGNOSIS`.
  TLS was not assessed, and `5` is the code that keeps "could not assess" from
  ever reading as `0`. The table of exit codes is unchanged.

### Changed - the verdict at the top names the cause instead of counting red rows

- **The first line now says what is wrong, in the words of the layer that
  established it.** A name that does not resolve reads "Neither view found an
  address for this name ..."; a server that forgot its intermediate reads "The
  server presented 1 certificate(s) and did not send the issuer of the first one
  ... a fact about the server rather than about this machine"; a certificate
  signed by an authority this machine holds in some stores and not in others
  reads "<issuer> signed this certificate and is an authority local to this
  machine - 1 store(s) here hold it and 1 do not. Without it: git." Until now
  the line read "Failures in 2 of 8 diagnostic layers", which was true and sent
  every reader scrolling.

- **The layer that decides is not simply the first red one.** A middlebox
  re-signing traffic presents a chain without its issuer exactly as a server
  that forgot its intermediate does, so the TLS layer fails identically for
  both. What separates them is the trust matrix: the middlebox's signer is an
  authority this machine holds in some stores, the forgetful server's issuer is
  held by nobody. So a local authority split across stores is named before a
  structural TLS failure, and a chain nobody can complete is blamed on the
  server even when every row of the trust matrix is red.

- **The counts are still there, after the cause.** "Failures in N of M" when
  more than one layer failed, "Warnings in N of M" when there is a warning, "N
  of M diagnostic layers could not be assessed" when something was not - so
  nothing the counting sentence used to say is lost, and one thing it used to
  drop is back: a warning standing next to unassessed layers was previously
  left off the top line.

- **A passing run behind a proxy that wants credentials says so on the first
  line.** certdoctor connects directly and passes; a runtime that goes through
  the proxy without credentials stops at its 407. "Everything assessed passed,
  but the proxy this URL goes through demands credentials ..." is that
  difference, said where it is read.

- **Under `--redact` the first line carries the masked names, never the raw
  ones.** The verdict is built from the rows after masking, and the report's
  own validator recomputes it from those rows and compares.

- The two settled sentences - "Nothing could be assessed yet." and "Everything
  that mattered was assessed and passed." - are unchanged. `--json` keeps
  `schema_version` `1.15`: no key changed, the text in `verdict.sentence` did.

### Fixed - a PAC file that trips one of certdoctor's own helpers no longer prints an internal Go symbol

- The message used to end "... will not guess an answer at
  github.com/donislawdev/certdoctor/internal/adapter/pac.Sandbox.timeHelper.func1
  (native)" and, worse, lost the one thing you could act on - where in YOUR
  file the call stands. It now reads "... will not guess an answer at
  FindProxyForURL (<eval>:1:58)". A script's own errors keep their own words
  and position, as before, minus a program counter that meant nothing to
  anybody outside the engine.

### Added - `--format html` writes the report as one page you can attach to a mail

- **The whole report as a single file, and nothing in it reaches out.** The
  stylesheet is inline; there are no images, no fonts and no scripts. A report is
  something you forward, so a page that fetched a font would announce every
  opening of it to somebody else - from a program whose first promise is that the
  set of places it connects to is finite and named.

- **Three things the page can do that a terminal and a pasted document cannot.**
  The certificate chain folds away when there is more than one certificate and
  stays open when there is only one, so the evidence is present without being in
  the way. Each layer that found something has an anchor, and the overview links
  to it - but only where there is somewhere to go, so no link is dead. The
  remediation command sits in a block that selects in a single click.

- **There is no copy button, and that is deliberate.** A real one needs the
  clipboard API, which would mean this page carries executable code into the
  inbox of whoever reads a report about TLS interception. Selecting the command
  in one click is the weaker affordance, and the file stays inert.

- **Text from the machine being diagnosed cannot change what the page does.**
  Host names, certificate subjects and store paths are somebody else's text, and
  on this surface markup is behaviour. Every such value is escaped, and none of
  them ever reaches an HTML attribute - so the page cannot be steered even by a
  value that was escaped incorrectly.

- **`--format html --out -` writes the page to standard output**, the same as the
  other formats, so redirecting it into a file works the way a command line
  expects. Writing it to a path with `--out` still says on standard error where
  the file went, and puts nothing on the pipe.

- **The report says the same things wherever you read it.** The test that holds
  the terminal, the markdown report and the machine readable document to the same
  facts now covers this page too, one finding kind at a time.

### Added - `--format md` writes the report as markdown, to paste into a ticket

- **The whole report, in a form that survives being pasted.** The layer overview
  is a table you can scan, each finding is a list entry with its evidence
  underneath, and the remediation command is in a fenced block so it copies in
  one gesture. It carries the same facts as the terminal - the certificate chain
  with whole fingerprints, the names a PAC file asked a resolver about, and every
  note about what a row does not settle.

- **It does not change with where it is going.** The terminal report drops colour
  when it is written to a file, because colour is for a console. This format has
  no such switch and cannot grow one, so a report mailed as an attachment and the
  same report pasted out of a pipe are the same document. (Two separate runs still
  differ where they should - they measured different things, at different moments.)

- **Text from the machine being diagnosed cannot change what the page does.**
  A report is pasted into places that render markdown as HTML, and a host name or
  a certificate subject is somebody else's text. Those are escaped, so a value
  spelled like a link stays a value.

### Fixed - a PAC file that asks what day or time it is was reported as broken

- 🔴 **`weekdayRange`, `dateRange` and `timeRange` now answer.** These are ordinary
  functions from the PAC specification - the ones a company uses to send traffic
  through a proxy during office hours - and until now a file calling any of them
  was reported as `UNKNOWN`, with the reason certdoctor uses for a file that will
  not parse and a sentence saying the PAC file failed. The file was fine. The
  clock behind those three functions had never been connected.

- **An answer that depended on the clock now says so.** A file routing office
  hours through a proxy and evenings direct gives one answer in the morning and a
  different one at night, and both are correct - so the row says this is the
  answer for the moment the run was taken. A report pasted into a ticket on
  Monday may be describing a Saturday route, and now it tells you that. This is
  a note, not a refusal: the answer is genuine for its moment.

  The note appears whether the file used those three functions or read the clock
  through JavaScript's own `Date`, because it is about the answer having a date
  on it rather than about how the file asked.

### Added - certdoctor fetches the proxy auto-configuration script and tells you where it sends this URL

- 🔴 **A PAC script is fetched, run in a sandbox, and reported: which entry it names for your URL, and every entry it listed.** This is the fault this product exists for. A proxy is configured on the machine, the environment says so, the system settings say so, and anybody reading either would tell you the request goes through it - and then the script sends that one name straight out. Nothing else tells you so.

- 🔴 **`--pac-url <url>` asks about a script your machine does not name.** Only Windows keeps a script address where every program reads it, so on Linux and macOS there is nothing for this layer to find. Point the flag at an address somebody handed you and certdoctor answers the question you actually have: where does this file send this URL. A script named by the flag and one named by your machine are one row when they are the same file.

- **A script that will not parse, times out, recurses past the stack, allocates past the ceiling or is larger than this run accepts gets `UNKNOWN` with a reason, never an exception and never a pass.** A file returning `null` is reported as no answer rather than as `DIRECT`: browsers treat those the same and route you silently, which is the behaviour this program exists to interrupt.

- **The script's own answer is shown verbatim, and the entries it named are shown separately with a keyword this program does not recognise carried rather than dropped.** A directive quietly discarded would let a report say a client goes direct when the file actually named something certdoctor failed to read.

- **The row says what it does not settle**: that the file decided with `Math.random`, so this is one of the answers a client could get rather than the only one; that it asked a question this run had nobody to ask; or that its address carried a password, which was dropped and not sent.

- **certdoctor will not fetch a script over anything but `http` and `https`, and will not follow a redirect.** A `file:` address can be a UNC path on Windows, which is a connection to a host you never named; a redirect is a second address this run derived from nothing. Both are refused with a sentence saying so, rather than followed quietly.

### Added - certdoctor now reads every place your machine keeps proxy settings, and says where they disagree

- 🔴 **The proxy layer reports one row per PLACE, not per program.** On Windows that is the current user's Internet Settings - which Edge, Chrome and .NET follow - and the machine's default WinHTTP configuration, which services follow. On every system it is also the proxy environment variables this process was started with. Several programs read one place and one program can read two, so a report organised by program would repeat itself and still miss the thing you came for.

- 🔴 **It tells you when two of those places disagree, which is the case this layer exists for.** Measured on Windows: set a proxy in the Windows settings and Internet Settings returns it in full while the WinHTTP view still reports no proxy at all. Edge and .NET go through the proxy, a service goes direct, and nothing on that machine is misconfigured. That run now reports `WARN` and names the class of the disagreement.

- 🔴 **One `NO_PROXY` gets more than one answer, because the runtimes on your machine read it differently.** curl excuses a host under a bare suffix; .NET documents that it does not - `NO_PROXY=example.com` will not match `www.example.com` there. The row shows each reading separately, so "is this host excluded from the proxy" is answered per runtime rather than once and wrongly.

- **A proxy URL with a password in it is reported as carrying credentials, and the password is never shown** - with or without `--redact`, on any surface. That is not a new promise; it is that promise reaching a new field.

- **A Windows exception list containing a URL rather than a server name gets a caveat quoting Microsoft**, who documents such an entry as invalidating the whole list. The list is still shown as your machine holds it, because that behaviour has not been measured here - but if your exceptions have quietly stopped working, this is the first place to look.

### Changed - the proxy layer says `UNKNOWN` where it cannot see the whole picture, and says why

- 🔴 **A machine with automatic proxy detection switched on gets `UNKNOWN`, not "no proxy".** Windows has that setting on by default, certdoctor does not yet perform the discovery, and a proxy found that way would not appear in this report. The row says exactly that. The same applies to a machine pointing at an automatic configuration script: naming a script is not proof anything uses it, and certdoctor does not yet fetch one.

- **The exit code is unchanged.** This layer previously said "not implemented", which was already `UNKNOWN`, so a run that ended `5 INCONCLUSIVE` still does.

- 🔴 **A machine pointing at a script is no longer stuck at `UNKNOWN` - the script is now read.** A machine with automatic proxy DETECTION on still is, and that half has not moved: certdoctor does not perform that discovery, so a proxy found that way would not appear here. Windows has that setting on by default, so on an ordinary Windows machine the row still says so.

- **`UNKNOWN` carries one more reason: `limit_exceeded`**, for a ceiling certdoctor itself sets. It is deliberately not `timeout`: a script stopped for allocating did not run out of time, and one refused for its size was never started. Time keeps `timeout`; every other ceiling of ours is this.

- **Under `--redact` a script's address becomes a pseudonym, the proxies it names become pseudonyms, and its verbatim answer is withheld entirely** - somebody else's sentence with a bare address inside it, which no masking rule can recognise. The entries are still listed with their addresses replaced, so what you act on survives.

- **`--json` carries `schema_version` `1.13`**, with three new finding bodies - `proxy_stack`, `stack_divergence` and `pac_script` - and nothing removed or renamed. If you branch on a class of divergence, read the key it arrived under: the document now holds two different closed lists that both contain `one_sided`, one about addresses for a name and one about places that hold proxy settings.

- **Under `--redact` the proxy address becomes a pseudonym like every other host name, and the exception list is withheld entirely.** Its entries are wildcards and suffixes, so no rule can recognise them as names to replace - withholding is the only honest option. Which runtimes skip the proxy for your target is still shown, because that is the part you act on.


`certdoctor <url>` produces a whole report. Six of its eight diagnostic layers now say something about your machine - context, name resolution, proxy, TCP, TLS and the trust matrix - and the other two report `UNKNOWN` with a reason and the words "not implemented". The verdict counts them and the run ends with `5 INCONCLUSIVE`, or with `4 DIAGNOSIS` on something certdoctor can actually diagnose. What exists is the path a real answer travels, built before any answer, so that there is no point at which this program claims to have checked something it has not.

### Fixed - a report that survives a broken probe, a document that stops inventing, and a resolver list that matches your machine

- 🔴 **One trust probe falling over no longer costs you the whole report.** The trust matrix asked its probes in a plain loop, so a panic anywhere inside one - parsing PEM out of `keytool`, an INI file somebody else wrote, a certificate handed to Go's own X.509 code - ended the run with no report at all, after every layer had finished and every store had been read. Such a probe now becomes one row saying it could not run and naming what went wrong, and the other rows are printed. The layers that connect and hand shake have worked this way since August; this one did not.

- **A server that completes a handshake and presents no certificate is described as that.** Its row used to say it "presented the same certificate as the first address" - about a certificate that does not exist and an address that was never chosen - and the layer's own sentence said the server "did not send the issuer of the first one", there being no first one. Both now say a handshake completed and no certificate was presented. The verdict is unchanged and still `FAIL`: a server that authenticates itself with nothing leaves every trust store on your machine with nothing to judge.

- 🔴 **`--json` no longer replaces a byte with a substitution character and says nothing.** A store path, a certificate subject or a value out of somebody's configuration can hold a byte that is not text. The terminal report printed it as `\xNN`, saying what is really there; the machine readable document silently swapped it for `U+FFFD`. The same run produced two documents disagreeing about one value, and the one a pipeline believes was the one inventing. Both now say `\xNN`.

  Characters that JSON can carry - control characters, bidirectional overrides - are still carried as themselves, because a program decoding the document gets back the value that was on the machine. Only a byte that is not text at all cannot make that trip.

- **A stray datagram no longer costs a real DNS answer.** Certdoctor read exactly one packet per query, so a late reply to an earlier question - or one somebody else sent - produced a row saying your resolver had answered a different question, while the real answer was still arriving. It now keeps reading until the deadline for the answer to the question it asked, and a resolver that only ever sends mismatched packets is reported as a timeout with a count of what did arrive instead. A reply that carries certdoctor's own identifier and answers something else is still reported as exactly that: it means the resolver is misbehaving, and nothing better is coming.

- 🔴 **On Linux and macOS at most three resolvers are asked, and the report says when your list was longer.** This is what your machine's own resolver does - Go stops at three and so does glibc - so asking a fourth compared certdoctor's own view against a system view that could never have seen it, and reported a disagreement certdoctor had manufactured. A repeated address is now consulted once rather than twice. Whenever anything is left out, a note names the file and says how many lines and why; silence here would read exactly like a machine configured with three.

  On Windows nothing changed: the list comes from the registry and from the network stack, no such limit exists there, and cutting it to three would hide resolvers your machine really uses.

- **Two notes about things that did not change.** The minimum TLS version certdoctor will negotiate is now stated in its own code rather than taken from whatever the Go library defaults to. It is TLS 1.2, which is what you already had, so no server answers differently today - it means a future toolchain cannot change a verdict on its own. A server speaking only TLS 1.0 or 1.1 is still reported as one that did not complete a handshake, without saying that certdoctor is the side that declined; saying so properly means trying again at a lower floor, which is a new behaviour rather than a constant.

### Fixed - a second Ctrl-C now works, and a closed pipe no longer kills the run without a word

- **Pressing Ctrl-C twice ends the run.** The first one still takes the ordinary path: the run stops, says `interrupted before the run finished`, and ends with `130 INTERRUPTED`. Every interrupt after that used to be swallowed - measured, three of them left the process running - so if anything ever failed to stop, `kill` was the only way out. A second interrupt now ends the run at once, says so, and still uses `130`.

  The second one is an emergency exit: nothing is cleaned up and no report is produced, which is what it says. That is the same cost any signal-ended run pays, and the alternative was a run that could not be stopped.

- **`certdoctor --json | head` no longer dies with a status of 141.** On Linux and macOS, writing to a pipe whose reader has gone kills the process outright - measured, a one megabyte document ended the run with 141, which is not in this program's table of exit codes and arrives with no message. It now comes back as `6 IO` with a sentence saying the report could not be written, so you can tell you saw part of a diagnosis rather than all of it.

  You have probably never seen this: a report smaller than the pipe buffer is handed over before the reader can be missed, and today's `--json` report is about half that size. The margin shrinks as your trust matrix grows. On Windows this never happened and nothing changed.

- **A note about a temporary file, added rather than a change.** `--out` writes to a temporary file beside your destination and renames it, and it removes that file whenever the write fails. If certdoctor is killed by a signal in the moment between the two, a `.certdoctor-report-*` file is left behind. The window is one write, and cleaning up from a signal handler brings problems of its own.

### Fixed - a mistyped URL is now named as a mistyped URL, and an error message no longer prints your password

- **A URL with a port and no host name is refused where you can still see the typo.** `https://:8080`, `https://user@:80` and `http://:` used to run, produce a name resolution layer that broke its own contract, and end with `5 INCONCLUSIVE` - a sentence saying **certdoctor** is defective about something you mistyped. They now end with `2 USAGE` and a message saying a host name is missing.

- **A name no resolver could be asked about is refused the same way.** `https://a..b`, `https://.` and a name with a label over 63 bytes used to end with `4 DIAGNOSIS` and a red name resolution layer - a verdict about **your DNS** for a name that never went on the wire, because certdoctor could not encode it. Worse, every row of that layer named one of your resolvers by address and said a reply had arrived from it that could not be read. No query had left and no reply had come.

  A name with a trailing dot is absolute and still works, which is the case that stops this from being "refuse anything unusual".

- 🔴 **An error message no longer prints credentials from your URL.** Measured on this binary: `certdoctor "https://bob:hunter2@example.com:99999"` printed the password on standard error - where CI logs come from - while the same run masked the same URL correctly inside the report. Four messages did it, two of them twice in one line, and one of those second copies came from inside Go's own parse error. Every message certdoctor writes to standard error now goes through the same credential floor the report uses, and it does so in one place rather than at each message.

  A URL with nothing to hide still appears in its own message, or you could not tell which argument was wrong.

- **What this changes for a script.** Three families of mistyped input that used to end with `4` or `5` now end with `2 USAGE`. The table of exit codes is unchanged - what changed is which input earns which code, the same way a port outside 1-65535 already did.

### Fixed - certdoctor no longer blames somebody else's program for its own time limit, and no longer says a store was refused when nothing was

- **A probe that certdoctor stopped itself was reported as the runtime answering "no".** With a short `--probe-timeout` you would read `the trust store could not be read: keytool exited with 1` - about a keytool that answered nothing at all, because certdoctor killed it when the budget ran out. Measured on this machine: the same run printed `context deadline exceeded` on the other rows, so one cause produced two sentences and one of them accused a program that had done nothing wrong.

  **The row now says who stopped it**: `keytool.exe was stopped before it answered: context deadline exceeded`. Telling the two apart is not simple, which is why it was wrong: a killed child reports exit code 1 on Windows - the same number a program that ran and refused would report - and -1 on Linux, and neither carries the deadline. The only thing that separates them on both is certdoctor's own clock.

- **A probe whose output was held open by an orphaned process could outlast the whole run.** If a runtime's binary started something else that inherited its output, certdoctor waited for end-of-file that was never coming. Measured on Windows and Linux: a 300 ms budget produced a 30 second call, and it came back **without an error**, so a hundredfold overrun looked exactly like an answer. There is now a two second bound on waiting for output after the process itself is gone, and exceeding it is reported rather than absorbed. A probe that answers normally is unaffected - measured at 9 ms and 3 ms with the bound in place.

- **The trust matrix said `access_denied` on machines where nothing was denied.** Measured in a container with git installed and no `/etc/gitconfig`, which is an ordinary Linux machine: every store came back unassessed and the layer answered *"certdoctor was not allowed to read this"*, sending you to check file permissions for a store nobody had refused. The row itself was right - git names no backend, so the bundle it reads is compiled into its libcurl - and the layer above it turned that into an accusation.

  **`--json` reports schema 1.11**, because the closed list of reasons behind `UNKNOWN` gains an eighth value, `undetermined`: the layer asked, and what came back does not settle the question. Nothing else about the document changed - no field arrives, leaves or changes meaning - but a consumer that branches on every reason now has one more case. `access_denied` is still declared and nothing produces it today; certdoctor cannot yet recognise an actual refusal, and would rather say nothing than say that.

### Fixed - git no longer disappears from the trust matrix on a machine that has no git configuration

- **A git with no configuration file used to get no row at all.** It sat outside the report next to the runtimes you do not have installed, while the binary was sitting on your PATH reading a trust store. Measured in a Debian-based container: `git 2.54.0` present at `/usr/bin/git`, `git config --list --show-origin` printing nothing, no `/etc/gitconfig`. That is an ordinary machine, not a rare one - and certdoctor was silent about it rather than saying it did not know.

  **What proves git is installed is now the binary on your PATH**, and a configuration file only says which store that binary reads. Where there is no configuration the row says so: git uses whichever libcurl it was built against, and the store that build reads is compiled into it. That is `UNKNOWN` with a reason, which is what this program owes you when it cannot tell - and the row now exists for that answer to stand in.

- **You may see more than one git row, one per git binary on your PATH.** On the machine this was written on there are two: a small launcher in `Git\cmd` and the real binary in `Git\mingw64\bin`. Both are listed because either is what a script might invoke, and on another machine two such binaries can be two different builds reading two different stores - which is the disagreement this matrix exists to show. `curl` has worked this way since the matrix arrived.

  **Rows are named by the binary now**, so a git row reads `C:\Program Files\Git\cmd\git.exe` rather than the install directory. Since the matrix has more rows on such a machine, the sentence counting them changes with it.

- **A directory named `git` or `curl` on your PATH is no longer mistaken for the program.** Opening a directory succeeds on Windows and on Linux alike, so certdoctor now requires that it can actually read a byte from the file before it will describe anything as that runtime's trust store.

- **Nothing about `--json` changed.** No field arrives, leaves or changes meaning, and the schema did not move for this change - it stood at 1.10 at the time - there are simply more `trust_store` rows on machines that were missing one.

### Added - certdoctor will now name a TLS inspection product, and only when it can show you where the name came from

- **When the certificate you were served was signed by an authority whose name matches a product certdoctor carries a source for, the report says so plainly** - "and that issuer names mitmproxy, a TLS inspection product, so this connection is being intercepted and re-signed between here and the server" - and `--json` carries `signing_authority.inspection` with the product and which part of the issuer's name matched. Everywhere else that field is `null`.

  **`null` there means "not named", never "not inspection".** The measurement certdoctor already made - who signed this, and how many of your trust stores hold an anchor for them - is unchanged, runs on every connection, and never consults the list. Your trust matrix, the commands underneath it and the layer's verdict are all decided before the list is asked anything at all.

- **The list has two entries today: mitmproxy and Cisco Umbrella.** That is short on purpose. An entry exists only where the product's own source code or the vendor's own documentation states the name their certificate is issued under, read at that source and dated. Fortinet documents the name of a certificate *object* rather than the name inside the certificate; Zscaler's, Netskope's, PortSwigger's and Telerik's own pages describe their certificates without stating it. None of them got an entry, and none of them is thereby innocent - they are unnamed.

  **The reason the list cannot be long is the same reason certdoctor never detected inspection by name in the first place.** Every one of these products lets an organisation supply its own certificate authority, and the appliance then signs with your company's name rather than the vendor's. A program that recognised inspection by name would miss exactly the environments this one is built for.

- **What certdoctor still will not do is guess.** With no name, it states what it measured and names both readings, because an intercepting middlebox and your own company's certificate authority are indistinguishable from one connection - measured, they produce the same value in every field certdoctor has. With a name, the caveat changes to say the naming rests on a name in the issuer rather than on anything measured about your network, and the fingerprint stays beside it so somebody else can check.

- **Under `--redact` the product name survives and the issuer does not.** The name came from certdoctor's own list and identifies no host, account or network of yours; the issuer is text out of somebody else's certificate and is where a host name hides.

- **`--json` reports schema 1.10.** One nullable object was added and nothing was removed or changed meaning, so anything reading 1.9 keeps working.

### Changed - a layer no longer blames your machine for certdoctor's own budget

- **A layer that did not get to finish looking now answers `UNKNOWN` instead of `FAIL`, and the run ends `5 INCONCLUSIVE` instead of `4 DIAGNOSIS`.** Measured before the change: `--probe-timeout 0.001` reported that name resolution had failed, and exited 4 - the code whose own table means "the run succeeded and found at least one failure" - on a machine that resolves the same name in 26 ms. Every row underneath said certdoctor had run out of time. The verdict was our arithmetic wearing your network's name.

  **The rule is that a verdict against the thing being examined requires that the layer asked everything it meant to ask.** If nothing succeeded and anything at all was dropped - because certdoctor ran out of its own budget, or because its own rule about where it may connect refused an address - the answer is `UNKNOWN` with a reason, and the sentence says how many were never tried and why. It applies to name resolution, to the connection attempts and to the handshakes.

  **What has NOT changed is the verdict on a layer that finished.** A name that resolves nowhere from both views is still a `FAIL` and still exits 4. So is an address that refuses a connection, and a server that will not complete a handshake. If your CI treats 4 as "certdoctor found something", that continues to mean exactly what it meant.

- **A layer that gave up partway through now says so in the notes**, not only in its own row. `budget_exceeded` is unchanged and still means what it says - that the whole run ran out of its overall time - because a layer spending its own budget is a different fact.

- **On a machine that lists no resolver of its own, name resolution stops reporting a difference between two views while holding one.** An empty `resolv.conf` is ordinary - the platform still resolves names - and certdoctor used to run its comparison against a view that had never asked anybody, print "comparing what **0** resolver(s) told us against what this system resolves the name to", and label it as both views having agreed. There is no comparison in that report any more, and the sentence names the one view there was.

  **The verdict on the name itself no longer depends on how many views there were.** If anything answered and no view found an address, that is a `FAIL` with one view exactly as it is with two - a name that resolves nowhere is a name you cannot connect to either way. If nothing answered at all, one view still leaves it `UNKNOWN`, because a single view cannot tell a name that does not exist from one it cannot see.

- **A truncated DNS answer is no longer compared against your other view.** The `TC` bit means the resolver had more to say than fitted in the reply, so the addresses in that row are part of the answer rather than all of it - and comparing part of one view against all of the other could report split-horizon DNS, which is a real fault people act on, from a packet that simply did not fit. The rows keep their addresses and keep saying the list may be short, and the layer's sentence says the comparison was skipped.

- **The trust matrix now says `timeout` when it ran out of time, instead of `access_denied`.** Reading a store means running the runtime's own tool, and when the layer's budget was spent every store came back unassessed under a reason that means "certdoctor was not allowed to read this" - an accusation about permissions nobody had refused. Each probe also gets a share of the time the layer has left rather than the first one taking all of it.

### Fixed

- **A remediation command is quoted for the shell it will be pasted into, and one that cannot be written safely is not written at all.** The path in that line comes from your own configuration - `http.sslCAInfo` in a gitconfig, `CURL_CA_BUNDLE` in the environment - and it used to be wrapped in double quotes, inside which a POSIX shell still runs what is in `$(...)`. Commands for Linux and macOS now use apostrophes, and on Windows a path carrying `%`, `"`, `$` or a backquote gets **no command**, with the row saying why: neither `cmd` nor PowerShell makes those literal, and a line certdoctor cannot write correctly is worse than no line. Both placeholders are quoted too, because the angle brackets around them are a redirection in every shell this command can land in.

- **`--out` pointing at a directory now gets an answer instead of the operating system's words.** It used to say "moving the finished report to .: rename .\.certdoctor-report-1719771881 .: Access is denied." - true, and about a temporary file you never mentioned, while suggesting a permissions problem when the actual problem is that a directory has no file name to write under. Naming a directory is an ordinary slip, especially with tab completion.

- **A server that completes a TLS handshake without presenting a certificate is no longer reported as certdoctor breaking its own contract.** Session resumption in TLS 1.3 and the anonymous cipher suites both do exactly that, and the row was refused for carrying no fingerprint - which discarded **every** row of the TLS layer along with it. The report said the layer had broken its own rules about a server that had behaved perfectly legally.

- **A failure inside certdoctor while it connects or hand shakes no longer kills the run without a report.** Those attempts run side by side and reach code certdoctor does not own, and a crash in one of them used to take the whole process down - no report at all, and an exit code from outside its own table. The layer now ends `UNKNOWN` with `probe_error`, which means what it says: the probe fell over, not your machine.

- **On Linux, a run could die the same way while name resolution was still finishing.** Nothing about your machine caused it and nothing in the report would have shown it, because there was no report. It cannot happen now.

- **An answer that arrives from somewhere else is told apart from one certdoctor cannot read.** A reply is now checked against the question that was asked - the name and the record type, letter case ignored - and not only against the query's identifier, which is sixteen bits and therefore guessable. A reply about a different question says so in its row rather than reading as a broken resolver.

- **A URL whose port is not a port is refused with a sentence saying so, instead of being reported as a defect in certdoctor.** `https://example.com:99999` used to produce "the layer broke its own contract" against the connection layer - a statement about this program - and then a claim that the name had resolved to no address, about a name that had resolved to four. It now ends immediately with a usage error naming the range.

- **A target given as an address is no longer looked up in DNS.** Asked about `https://1.1.1.1`, certdoctor used to send four queries about the literal, collect four `NXDOMAIN` rows, and report that your two views of DNS disagreed - about a machine with nothing wrong with it. Name resolution now says there was nothing to resolve, and everything below it carries on with the address you gave.

- **Two layers stopped claiming to know things they had not been told.** When the connection or the handshake layer is handed nothing, it now says whether the layer above it *looked and found none* or *established nothing at all* - two different situations that used to share one sentence, and that sentence asserted the name had resolved to no address, which neither layer can know. In particular, a run where every address refused a connection now says exactly that, instead of reporting it as an absence of information.

- **A name with a non-ASCII character in it is now converted before it goes on the wire, so international domain names work.** Asked about `https://bücher.de`, certdoctor used to put the raw characters into the DNS query and into the TLS server name, get `NXDOMAIN` from every resolver, and report a failure about a server that was working - while the same site asked about as `https://xn--bcher-kva.de` came back clean. One machine, one server, two spellings of one name, opposite answers.

  **The report shows the name you typed and the rows show the name that was asked about.** Both are true and they are deliberately not the same field: the target line is what you pointed certdoctor at, and each row of name resolution carries the `xn--` form, because that is the name that actually went out. `--redact` hides both.

  **A name written with combining marks is refused rather than converted.** Composing those needs Unicode tables certdoctor does not carry, and converting them uncomposed produces a valid-looking name for a *different* domain - which resolves nowhere and would put you back where this started, with a confident wrong answer. The refusal says so and asks for the `xn--` form, which is what your browser sends anyway.

- **`--timeout 0` and `--probe-timeout 0` together no longer switch off half of name resolution.** Both are documented as "no limit" and, given together, they left the run with no deadline at all - and the part of certdoctor that queries your resolvers directly refuses to open a socket it cannot bound, because one that blocks forever would outlive any budget. The result was four rows saying the query could not be sent, underneath a layer still reporting `PASS`, on a machine whose resolvers answer in milliseconds. No limit now means the longest limit this program accepts, which is a day.

### Changed

- **`L3` now tries the addresses side by side instead of one after another**, up to eight at a time. On a name behind several addresses this means one address sitting behind a silently dropping firewall no longer eats the time the working ones needed - the others are already being tried beside it. Two things follow that you may notice: attempts are quicker on names with several addresses, and each attempt may now use the whole of what is left of the run's budget rather than a share of it divided between them.

  **The rows still come back in the order the addresses were resolved in**, never in the order the attempts happened to finish, so two reports from the same machine line up row for row.

  **Eight at a time is a ceiling rather than a tuning knob.** How many addresses a name resolves to is decided by whoever answers the DNS query, and without a cap they would be deciding how many connections this machine opens at once - which is not a decision to hand to a stranger, least of all on a network where something is watching for that shape.

### Added

- **The trust matrix now opens with one line saying who signed the certificate and how much of your machine has heard of them.** This is the line that explains why your browser is fine and `npm install` is not, and it is the reason certdoctor exists.

  **It answers with a count of trust stores, never with a conclusion about your network.** `all_stores` means every store certdoctor could assess holds an anchor for this chain. `some_stores` means some do and some do not, which is exactly why one tool on your machine accepts this name and another refuses it. `no_stores` means nothing here accepts it, a browser included.

  **`some_stores` is not an accusation and certdoctor will not turn it into one.** A TLS-inspecting proxy produces that answer. So does your own organisation's certificate authority, on an internal service that is working exactly as intended - and from a single connection these two are not merely hard to tell apart, they are identical in every field this program has. Both cases were built on a test bench and measured, including one where the proxy was given an intermediate to sign with, at which point even the certificate chain matched. So the line states what was measured, the sentence beside it says plainly that both readings fit, and the issuer and the SHA-256 fingerprint travel with it so somebody who can tell them apart has what they need.

  **The commands underneath it are unchanged in shape and now appear in one more case.** If another store on your machine accepted the very same chain, then an anchor that completes it demonstrably exists, so the store that refused can be repaired by being given it - even when the server sent an incomplete chain. Where nothing on your machine accepted the chain, there is still no command, because then the server is the thing to fix.

  **`--json` grows a `signing_authority` finding and `schema_version` goes to `1.9`.** It carries `held_by`, the issuer, the fingerprint, the two lists of stores, and a `caveat` saying what the measurement does not settle. Branch on `held_by`, and read it as the count it is.

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
