// Package render owns everything about how a result looks. The core hands it a
// status and this package decides the glyph, the fallback and the colour - the
// call site never does.
//
// Why that split is a rule and not a preference: a probe allowed to choose its
// own colour will one day choose green for a FAIL, and it will be one probe out
// of thirty, which is exactly the one nobody checks. Consistency has to come
// from the default, not from discipline.
package render

import (
	"fmt"

	"github.com/donislawdev/certdoctor/internal/core/status"
)

// Appearance is everything the renderers know about how one status looks.
//
// There is deliberately no sort priority here. The order statuses appear in is
// already declared once, as severity in the status package, and copying it into
// a second table is how two sources of truth are born. Sorting reads
// status.Severity and this package does not repeat it.
type Appearance struct {
	// Glyph is the marker for a terminal that can render it.
	Glyph string
	// ASCII is the substitute for a terminal that cannot. It is not decoration:
	// a Windows console on a different code page renders the glyph as garbage,
	// and a report whose status looks corrupted is worse than one with no
	// glyphs at all.
	ASCII string
	// Color is a concept, not a value. The escape sequence for it lives in this
	// file and nowhere else, so that the report formats can map the same name
	// onto something that is not an escape sequence at all.
	Color Color
}

// Color is the name of a colour in the palette. The palette is closed, like the
// status vocabulary it serves.
type Color string

const (
	ColorRed    Color = "red"
	ColorYellow Color = "yellow"
	ColorBlue   Color = "blue"
	ColorGreen  Color = "green"
)

// dictionary is the single source of appearance. Values come from the glossary,
// which fixes the glyphs and the fallbacks as a decision already taken.
var dictionary = map[status.Status]Appearance{
	status.Fail:    {Glyph: "✘", ASCII: "x", Color: ColorRed},
	status.Warn:    {Glyph: "!", ASCII: "!", Color: ColorYellow},
	status.Unknown: {Glyph: "?", ASCII: "?", Color: ColorBlue},
	status.Pass:    {Glyph: "✔", ASCII: "+", Color: ColorGreen},
}

// ansi maps a colour name to its escape sequence. This is the only place in the
// repository allowed to contain one, and a guard checks that.
//
// These are the four basic SGR colours rather than a 256-colour or true-colour
// value, and that is a deliberate choice with a reason: the basic colours are
// remapped by the reader's own terminal theme, so a light background, a dark
// background and an accessibility high-contrast setting are all handled by
// their configuration instead of by our guess. Pinning a specific shade would
// look right on one machine and be unreadable on another, and we cannot see the
// other one.
//
// No background colour is ever set, and weight is never used to carry meaning.
//
// This is an assessment of how terminals behave, not a measurement. No terminal
// was measured against these values.
var ansi = map[Color]string{
	ColorRed:    "\x1b[31m",
	ColorYellow: "\x1b[33m",
	ColorBlue:   "\x1b[34m",
	ColorGreen:  "\x1b[32m",
}

// reset ends a colour run. Every painted string carries one, so that a report
// cut short by a broken pipe cannot leave the reader's terminal recoloured.
const reset = "\x1b[0m"

// ColorMode says whether colour is in play.
//
// The zero value is off on purpose. A forgotten assignment then degrades to
// plain text, which is readable everywhere, instead of writing escape sequences
// into a log file.
type ColorMode int

const (
	ColorOff ColorMode = iota
	ColorOn
)

// GlyphMode says which marker set to use.
//
// The zero value is ASCII for the same reason: a forgotten assignment produces
// something plain rather than something that may arrive as garbage.
type GlyphMode int

const (
	GlyphASCII GlyphMode = iota
	GlyphUnicode
)

// Of returns the appearance of a status.
//
// It panics on a status outside the vocabulary, because that can only happen if
// a caller invented a value instead of using a constant - a defect in our own
// code, never bad input from the machine being diagnosed.
func Of(s status.Status) Appearance {
	a, ok := dictionary[s]
	if !ok {
		panic(fmt.Sprintf("render: no appearance declared for status %q", string(s)))
	}
	return a
}

// Marker returns the glyph or its ASCII substitute.
func (a Appearance) Marker(m GlyphMode) string {
	if m == GlyphUnicode {
		return a.Glyph
	}
	return a.ASCII
}

// Label is the status word itself. It comes from the status rather than from the
// call site, so that no renderer writes one out and none of them can drift.
func Label(s status.Status) string { return s.String() }

// Paint wraps text in the colour of a status, or returns it untouched when
// colour is off.
//
// Colour never carries meaning on its own: the marker and the label have to be
// enough. A reader with NO_COLOR set, a reader who cannot distinguish the hues
// and a reader scrolling a CI log all get the same verdict.
func Paint(s status.Status, m ColorMode, text string) string {
	if m != ColorOn {
		return text
	}
	sequence, ok := ansi[Of(s).Color]
	if !ok {
		panic(fmt.Sprintf("render: no escape sequence declared for colour %q", string(Of(s).Color)))
	}
	return sequence + text + reset
}

// Order returns the statuses most severe first.
//
// It exists so that nothing has to range over the dictionary. Iteration over a
// Go map is randomised, so a renderer that walked it would produce a report
// whose section order changed between runs of the same input - the kind of
// defect that survives every test written as a single comparison.
func Order() []status.Status {
	out := make([]status.Status, len(status.All))
	copy(out, status.All)
	return out
}
