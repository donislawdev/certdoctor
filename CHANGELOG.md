# Changelog

All notable changes to Cert Doctor that a user would notice when running the program.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file records only what a person would notice by running the program. Internal structure, guards, CI and measurements are kept in a separate technical changelog that is not part of this repository, so nothing here should be read as the whole story of a change.

## [Unreleased]

### Added

- A CSR decoder: `certdoctor tool csr`, and **CSR decoder** under Tools in the window. It shows what
  a certificate signing request asks for, checks that its signature is intact, and warns about what
  a public certificate authority will not issue - no subject alternative name, a host name such as
  `localhost` or an address written as a host name, a common name outside those names, a key it
  does not accept. A challenge password in the request is reported and never shown.

### Changed

- The certificate decoder sends a certificate signing request to the CSR decoder instead of saying
  only that it holds no certificate, and names a signature algorithm it does not know by its
  identifier instead of `0`.

- The NO_PROXY tester in the window can be run with an empty list. The answer shows what each
  program does when `NO_PROXY` is empty or not set - Go, for one, never sends `localhost` to a
  proxy.
- On Linux and macOS, the NO_PROXY tester shows the list and the address as you paste or type them
  at a terminal. A token pasted into the JWT decoder still stays hidden.
- The JSON report is now schema 2.5. A PAC script row can say `evaluator_failed`: the process that
  runs the script stopped before it answered, and the row shows its exit code.

### Fixed

- The certificate decoder no longer spends many seconds on a certificate with an RSA key far larger
  than any in use. A signature made with an RSA key of more than 16384 bits is not checked, as
  OpenSSL does not check one either.
- In the window, the answer of a tool no longer waits below the bottom edge after you press Decode
  or Test. When the answer does not fit in view, the page scrolls so that the answer starts at the
  top. An answer that fits leaves the page where it was.
- On Windows, the window no longer loads a system library such as `opengl32.dll` from a file of the
  same name placed next to `certdoctor-gui.exe`, for example in a downloads folder. It takes those
  libraries from the Windows system folder only.
- On Windows, a git that uses Schannel with `http.schannelUseSSLCAInfo` turned on is now checked
  against the CA file it actually reads. Before, its row sent you to the Windows store, which that
  git does not use. If git cannot use the file at all - larger than 1 MiB, or with a damaged
  certificate in it - the row says so.
- A PAC file that asks for a huge amount of memory in one step, such as `"x".repeat(1e10)`, no longer
  ends Cert Doctor without a report. The script now runs in a separate process. If that process runs
  out of memory or time, only it stops, and the report says the script was stopped.

## [0.2.0] - 2026-11-14

The first release, so there is no earlier version to compare it with. What the program does, and what it does not do yet, is in the [README](README.md).
