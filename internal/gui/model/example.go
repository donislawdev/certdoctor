package model

import _ "embed"

// exampleDocument is a report of example.com as certdoctor --json writes it,
// the one the window's tests draw from - carried in the window for the hidden
// catalogue of its parts (GUI rule 4, --catalogue), which needs a report to
// draw them from and opens no file to get one.
//
// Read from testdata rather than copied out of it, so the tests and the
// catalogue cannot draw from two reports that drifted apart. The guard on
// personal data reads it there (internal/guard/personal_test.go), so nothing
// of a real machine or a real person travels in the window.
//
//go:embed testdata/example-com.json
var exampleDocument []byte

// Example is that report, decoded.
func Example() (Report, error) { return Decode(exampleDocument) }
