package render

import (
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/status"
)

// TestEveryStatusHasACompleteAppearance is the registry test for the dictionary:
// one pass demanding a full set of declarations from every entry. It catches the
// half-added entry, which is the mistake a fifth renderer would make.
func TestEveryStatusHasACompleteAppearance(t *testing.T) {
	if len(dictionary) != len(status.All) {
		t.Fatalf("the dictionary has %d entries, the vocabulary has %d - an entry was added in one place only",
			len(dictionary), len(status.All))
	}
	for _, s := range status.All {
		a, ok := dictionary[s]
		if !ok {
			t.Errorf("status %q has no appearance", s)
			continue
		}
		if a.Glyph == "" {
			t.Errorf("status %q has no glyph", s)
		}
		if a.ASCII == "" {
			t.Errorf("status %q has no ASCII substitute - a terminal that cannot render the glyph would show nothing at all", s)
		}
		if a.Color == "" {
			t.Errorf("status %q has no colour", s)
		}
		if _, hasSequence := ansi[a.Color]; !hasSequence {
			t.Errorf("colour %q of status %q has no escape sequence", a.Color, s)
		}
	}
}

// TestAppearanceMatchesTheGlossary pins the values the glossary froze. Like the
// exit code table, restating it here is the point: it is a second opinion that
// has to be edited deliberately, because these characters go into other people's
// tickets.
func TestAppearanceMatchesTheGlossary(t *testing.T) {
	frozen := map[status.Status]Appearance{
		status.Fail:    {Glyph: "✘", ASCII: "x", Color: ColorRed},
		status.Warn:    {Glyph: "!", ASCII: "!", Color: ColorYellow},
		status.Unknown: {Glyph: "?", ASCII: "?", Color: ColorBlue},
		status.Pass:    {Glyph: "✔", ASCII: "+", Color: ColorGreen},
	}
	for s, want := range frozen {
		if got := Of(s); got != want {
			t.Errorf("appearance of %q is %+v, the glossary says %+v", s, got, want)
		}
	}
}

// TestStatusIsLegibleWithoutColor is the guard on the rule that colour never
// carries meaning alone. Two statuses sharing a marker would be told apart by
// hue only, and a reader with NO_COLOR set, a reader who cannot distinguish the
// hues and a CI log would all lose the difference.
func TestStatusIsLegibleWithoutColor(t *testing.T) {
	seenGlyph := map[string]status.Status{}
	seenASCII := map[string]status.Status{}
	seenLabel := map[string]status.Status{}

	for _, s := range status.All {
		a := Of(s)
		if other, dup := seenGlyph[a.Glyph]; dup {
			t.Errorf("statuses %q and %q share the glyph %q - without colour they are the same mark", other, s, a.Glyph)
		}
		seenGlyph[a.Glyph] = s

		if other, dup := seenASCII[a.ASCII]; dup {
			t.Errorf("statuses %q and %q share the ASCII substitute %q", other, s, a.ASCII)
		}
		seenASCII[a.ASCII] = s

		label := Label(s)
		if other, dup := seenLabel[label]; dup {
			t.Errorf("statuses %q and %q share the label %q", other, s, label)
		}
		seenLabel[label] = s

		for _, r := range a.ASCII {
			if r > 0x7f {
				t.Errorf("the ASCII substitute for %q contains %q, which is not ASCII - it would break on exactly the terminal it exists for", s, r)
			}
		}
	}
}

// TestAppearanceEnumerationIsDeterministic guards against a renderer walking the
// dictionary map. Go randomises map iteration, so a report built that way would
// change section order between runs of the same input.
func TestAppearanceEnumerationIsDeterministic(t *testing.T) {
	first := Order()
	if len(first) != len(status.All) {
		t.Fatalf("Order returned %d statuses, the vocabulary has %d", len(first), len(status.All))
	}
	for i, s := range status.All {
		if first[i] != s {
			t.Fatalf("Order is not in severity order: position %d is %q, want %q", i, first[i], s)
		}
	}
	// Repeated because a map-based implementation would agree with severity
	// order about one call in twenty-four.
	for run := 0; run < 100; run++ {
		again := Order()
		for i := range first {
			if again[i] != first[i] {
				t.Fatalf("Order changed between calls: %v then %v", first, again)
			}
		}
	}
}

// TestOrderCannotBeMutatedByItsCaller keeps the vocabulary from being reordered
// through a slice somebody was handed.
func TestOrderCannotBeMutatedByItsCaller(t *testing.T) {
	got := Order()
	got[0] = status.Pass
	if Order()[0] != status.Fail {
		t.Fatal("Order handed out the underlying slice - one caller could reorder every report")
	}
}

func TestZeroModesAreTheSafeOnes(t *testing.T) {
	var color ColorMode
	if color != ColorOff {
		t.Error("the zero ColorMode must be off, so a forgotten assignment writes plain text rather than escape sequences into a log")
	}
	var glyph GlyphMode
	if glyph != GlyphASCII {
		t.Error("the zero GlyphMode must be ASCII, so a forgotten assignment produces something plain rather than something that may arrive as garbage")
	}
}

func TestPaintIsInertWhenColorIsOff(t *testing.T) {
	for _, s := range status.All {
		if got := Paint(s, ColorOff, "text"); got != "text" {
			t.Errorf("Paint(%q, ColorOff) returned %q, want it untouched", s, got)
		}
	}
}

func TestPaintAlwaysResetsAfterItself(t *testing.T) {
	for _, s := range status.All {
		got := Paint(s, ColorOn, "text")
		if !strings.HasSuffix(got, reset) {
			t.Errorf("Paint(%q, ColorOn) does not reset - a report cut short would leave the terminal recoloured", s)
		}
		if !strings.Contains(got, "text") {
			t.Errorf("Paint(%q, ColorOn) lost the text: %q", s, got)
		}
	}
}

// TestAnInventedStatusIsVISIBLYOddRatherThanFatal is P3-6, and it replaces a
// test that pinned a panic.
//
// THE CASE STILL CANNOT ARISE AND IS STILL HANDLED. A status outside the four is
// a defect in our own code, and the registry test in this file fails the moment
// one appears - at build time, where a defect belongs. What changed is what
// happens at RUN time: a panic there killed a report that had already been
// gathered, every layer walked and every store read, and left no output at all
// and an exit code from outside the table.
//
// WHAT IT MUST NOT BECOME is a plausible-looking substitute. A reader has to be
// unable to mistake this row for a normal one.
func TestAnInventedStatusIsVisiblyOddRatherThanFatal(t *testing.T) {
	invented := status.Status("SKIPPED")

	got := Of(invented)
	if got.Glyph != "??" || got.ASCII != "??" {
		t.Errorf("an invented status renders as %+v, which a reader could mistake for a real verdict", got)
	}
	for _, s := range status.All {
		if Of(s).Glyph == got.Glyph {
			t.Errorf("the fallback appearance is the same as %q, so an invented status is indistinguishable", s)
		}
	}

	// AND PAINTING IT LEAVES THE TEXT ALONE rather than emitting an escape
	// sequence for a colour nobody declared.
	if painted := Paint(invented, ColorOn, "text"); painted != "text" {
		t.Errorf("an invented status painted its text as %q", painted)
	}
}

// TestAllFourStatusesSideBySide is the screen with every control on it, in test
// form: all four statuses in all four combinations of glyph and colour mode.
// Drift shows up on one screen instead of being found by a user.
//
// Run it with -v to look at the table.
func TestAllFourStatusesSideBySide(t *testing.T) {
	modes := []struct {
		name  string
		glyph GlyphMode
		color ColorMode
	}{
		{"unicode, colour", GlyphUnicode, ColorOn},
		{"unicode, no colour", GlyphUnicode, ColorOff},
		{"ascii, colour", GlyphASCII, ColorOn},
		{"ascii, no colour", GlyphASCII, ColorOff},
	}
	for _, m := range modes {
		var line strings.Builder
		for _, s := range Order() {
			marker := Of(s).Marker(m.glyph)
			line.WriteString(Paint(s, m.color, marker+" "+Label(s)) + "   ")
			if marker == "" {
				t.Errorf("%s: status %q rendered no marker", m.name, s)
			}
		}
		t.Logf("%-20s %s", m.name, line.String())
	}
}
