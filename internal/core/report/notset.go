package report

// NotSetSummary is the sentence a finding carries for an environment variable
// that is absent.
//
// IT LIVES IN THE CONTRACT PACKAGE BECAUSE TWO SIDES READ IT - ADR137. L0 writes
// it, and the pages for people print every finding that says only this as one
// name in a single "not set" paragraph instead of as a row of its own. A page
// can drop the sentence only when the sentence is this one, and comparing
// against the same function is what keeps a longer sentence written for an
// absent variable some day from being dropped with it.
func NotSetSummary(name string) string { return name + " is not set" }
