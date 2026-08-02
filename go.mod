module github.com/donislawdev/certdoctor

// Pinned, not a minimum, and that is a contract rather than hygiene.
//
// certdoctor's verdicts rest on crypto/x509 and crypto/tls: what chains verify,
// which TLS versions and cipher suites are offered, what a verification failure
// is called. Those change between Go releases - probe S3 measured one such
// behaviour and overturned the prediction written before it. A release built on
// a different toolchain can therefore reach a different verdict about the same
// machine, and nothing in the report would say so.
//
// Updating this line is a change like any other: it goes through the same
// analysis, and the release binary is rebuilt and re-measured rather than
// assumed equivalent.
go 1.26.5
