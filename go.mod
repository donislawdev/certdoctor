module github.com/donislawdev/certdoctor

// A FLOOR, NOT A PIN, and the difference matters because this line used to
// claim otherwise.
//
// certdoctor's verdicts rest on crypto/x509 and crypto/tls: what chains verify,
// which TLS versions and cipher suites are offered, what a verification failure
// is called. Those change between Go releases - probe S3 measured one such
// behaviour and overturned the prediction written before it. A release built on
// a different toolchain can therefore reach a different verdict about the same
// machine, and nothing in the report would say so.
//
// WHAT THIS DIRECTIVE ACTUALLY DOES. It states the lowest version that may build
// this module. A newer toolchain already installed is used without asking, and
// Go has no way to declare a maximum - so this line cannot, on its own, make two
// builds of one commit agree. Saying it did was a claim about somebody else's
// runtime made without checking, which is the mistake this project treats as its
// most expensive one.
//
// WHAT ACTUALLY HOLDS THE VERSION STILL: CI installs exactly this version, via
// go-version-file in the workflow. That is a property of the pipeline, not of
// this file, and a release built anywhere else is not covered by it.
//
// Updating this line is a change like any other: it goes through the same
// analysis, and the release binary is rebuilt and re-measured rather than
// assumed equivalent.
//
// MOVED 1.26.5 -> 1.27.0 ON 2026-09-01, AND THE REASON WAS THE FORMATTER RATHER
// THAN THE LIBRARY. gofmt does not follow the toolchain switch the go command
// makes: it is whichever binary sits in the Go installation on PATH. When that
// installation went to 1.27.0 while this line still said 1.26.5, the local
// format gate and the one in CI began measuring with two different instruments,
// and they disagreed IN BOTH DIRECTIONS over one construct in one file -
// measured the same day, three gofmt versions against internal/app/run/run.go.
// No formatting of that file is green under both, so the versions had to meet.
// go1.27.0 was the current stable release, read at https://go.dev/dl/ on
// 2026-09-01.
//
// MOVED 1.27.0 -> 1.27.2 ON 2026-10-14, AND THIS TIME THE REASON WAS THE
// LIBRARY. go1.27.2 carries security fixes to crypto/tls, net/http,
// html/template, net/textproto and os, and the binary links four of the five -
// all but html/template, measured with "go list -deps ./cmd/certdoctor".
// The same release fixed cmd/cover, which under 1.27.0 counted some statements
// twice and so reported coverage higher than it was (golang/go#81832). That is
// how the gap was noticed: the installation on PATH had already moved, and two
// floors in tools/coverage-floor.txt, measured with the old instrument, fell
// below themselves on code nobody had touched. go1.27.2 was the current stable
// release, read at https://go.dev/doc/devel/release on 2026-10-14.
//
// MOVED 1.27.2 -> 1.27.3 ON 2026-10-21, FOR ONE PACKAGE. go1.27.3 changes
// crypto/x509 and nothing else, read at https://go.dev/doc/devel/release on
// 2026-10-21. It fixes GO-2026-6809: Certificate.Verify now drops every chain
// holding one of eight intermediates, picked out by the SHA-256 of their public
// key, whatever pool of roots the caller hands in (golang/go#82345, commit
// 7f86f957633e). govulncheck found it on the path every row of the trust matrix
// is judged on, and that path judges OTHER programs' trust - programs that do
// not carry the list. So a chain through one of the eight reads as refused on
// every row while the program judged may well accept it. ADR113 decides what
// such a row says instead.
go 1.27.3

require github.com/dop251/goja v0.0.0-20261013122152-245c54f48cfc

require (
	github.com/dlclark/regexp2/v2 v2.8.4 // indirect
	github.com/go-sourcemap/sourcemap v2.1.4+incompatible // indirect
	github.com/google/pprof v0.0.0-20261012231050-2af12c3f4d87 // indirect
	golang.org/x/text v0.43.0 // indirect
)
