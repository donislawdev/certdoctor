package render

import "os"

// Capability is what one destination can render.
//
// Its zero value is the safe one, deliberately: no colour and plain ASCII
// markers. A forgotten assignment then produces something readable in every
// terminal, every log file and every ticket, instead of writing escape
// sequences into a file somebody greps.
type Capability struct {
	Color ColorMode
	Glyph GlyphMode
}

// DetectCapability works out what a destination can render.
//
// It asks three questions of the operating system and one of the environment,
// and that is the whole of it. Nothing else about this program's behaviour comes
// from a variable: a run has to be reproducible from the command line somebody
// can read in a CI log, and NO_COLOR is the single documented exception because
// it changes how output looks and not what it says.
//
// THE THIRD QUESTION WAS MISSING AND ITS ABSENCE WAS AN ASSUMPTION. Whether the
// console renders a GLYPH was settled by asking it for its code page, with the
// source written down. Whether it renders a COLOUR was not asked at all - being
// a character device was taken as enough. Probe S6 measured a console on the
// owner's machine at mode 0x0003: no virtual terminal processing, which means
// the escape sequence is printed literally and the report reads as
// "<-[34m? UNKNOWN". That is the same harm the ASCII substitute exists to
// prevent for glyphs, arriving through the other channel.
func DetectCapability(destination *os.File, lookupEnv func(string) (string, bool), noColorRequested bool) Capability {
	capability := Capability{}
	if !isTerminal(destination) {
		return capability
	}
	if !noColorRequested && !noColorInEnvironment(lookupEnv) && consoleUnderstandsSequences(destination) {
		capability.Color = ColorOn
	}
	if consoleRendersUnicode() {
		capability.Glyph = GlyphUnicode
	}
	return capability
}

// noColorInEnvironment implements the NO_COLOR convention.
//
// Source: https://no-color.org, read 2026-08-02. The rule is presence AND a
// non-empty value - "when present and not an empty string (regardless of its
// value)" - so an empty NO_COLOR does not disable colour.
//
// That distinction is why this takes a lookup returning two values rather than
// calling os.Getenv. Getenv cannot tell a variable that is unset from one set
// to nothing, and here those two mean opposite things.
func noColorInEnvironment(lookupEnv func(string) (string, bool)) bool {
	if lookupEnv == nil {
		return false
	}
	value, present := lookupEnv("NO_COLOR")
	return present && value != ""
}

// isTerminal reports whether the destination is something a person is looking
// at rather than a file or a pipe.
//
// A redirected stream gets no colour and no glyphs, which is the rule about
// control sequences never reaching a non-terminal. It also covers the case that
// matters most in practice: a report redirected into a file and pasted into a
// ticket by somebody who never saw the escape codes.
func isTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
