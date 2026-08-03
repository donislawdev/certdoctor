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
go 1.26.5
