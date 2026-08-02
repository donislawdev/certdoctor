// This file is a fixture, never compiled and never part of the build. It exists
// so the appearance guard can be proved to fail on all three kinds of literal it
// claims to see: an escape sequence, a glyph, and a status label written out at
// the call site.
package render

const (
	red   = "\x1b[31m"
	tick  = "✔"
	label = "PASS"
)

func line() string {
	return red + tick + " " + label
}
