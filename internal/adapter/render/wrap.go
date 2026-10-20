package render

import "strings"

// pageWidth is how wide this renderer lays a page out, counted in runes like
// every other width on it.
//
// IT IS A CONSTANT AND NOT A MEASUREMENT OF THE WINDOW, and that is a decision
// rather than a shortcut. The same run gives the same bytes on a console, in a
// file written with --out and in a CI log, so a report pasted into a ticket is
// the page its author saw. Asking the console for its size would also mean
// reading a structure the operating system fills in, on three platforms, for a
// layout preference.
//
// WHY THIS NUMBER. Until OBS165 the page had no width at all: a column was as
// wide as its longest entry, and one long sentence in the trust matrix pushed
// every row of that layer past four hundred characters, so a window of 120
// columns broke each of them into several pieces. The page now fits a window of
// that size with a column to spare - a line exactly as wide as the window makes
// some consoles add an empty line after it - and the longest thing that must
// stay whole, a certificate fingerprint behind its label, still fits on one
// line of it.
const pageWidth = 100

// piece is a run of text no line is ever broken inside.
//
// PROSE IS BROKEN AT ITS SPACES AND DATA IS NOT BROKEN AT ALL, and every place
// that writes a line picks one of the two by building its pieces. A sentence
// wrapped onto a second line reads the same. A command, a path or a fingerprint
// split across two lines is copied in two pieces, and the copy is then a
// different value - so a datum longer than the page is allowed to run past it,
// and that is the only way a line on this page gets wider than pageWidth.
type piece struct {
	text string
	// gap is the number of spaces before this piece when it shares a line with
	// the one before it. A line break replaces the gap rather than following it.
	gap int
}

// prose makes pieces of a sentence, one per word.
//
// A RUN OF SPACES IS KEPT AS THE GAP IT WAS, so a sentence that fits on one line
// comes out byte for byte as it went in - including a value inside it with two
// spaces in a row. Only ASCII space separates words: everything this renderer
// prints has been through visible first, which turns a tab or a line break into
// its escaped spelling, and a no-break space is left alone because not breaking
// there is what it asks for.
func prose(text string) []piece {
	var pieces []piece
	for {
		trimmed := strings.TrimLeft(text, " ")
		if trimmed == "" {
			return pieces
		}
		gap := len(text) - len(trimmed)
		end := strings.IndexByte(trimmed, ' ')
		if end < 0 {
			end = len(trimmed)
		}
		pieces = append(pieces, piece{text: trimmed[:end], gap: gap})
		text = trimmed[end:]
	}
}

// items makes pieces of a list, one per entry, with the separator this page
// has always used between them.
//
// AN ENTRY IS DATA. A store here is a runtime and a path, and a path with a
// space in it broken at that space would read as two entries.
func items(list []string) []piece {
	pieces := make([]piece, 0, len(list))
	for i, entry := range list {
		if i < len(list)-1 {
			entry += ","
		}
		pieces = append(pieces, piece{text: entry, gap: min(i, 1)})
	}
	return pieces
}

// lines breaks pieces into lines. The first line may be firstWidth wide and
// every other one restWidth.
//
// A PIECE ALWAYS GOES ON A LINE THAT HAS NOTHING ON IT YET, whether or not it
// fits. The alternative is an empty line, or a lead with nothing after it, and
// neither says anything a reader can use.
//
// THE FIRST PIECE KEEPS ITS GAP ON THE FIRST LINE. That gap is what separates
// it from the lead its caller writes in front, so a lead never has to end in a
// space and the caller never has to count one.
func lines(pieces []piece, firstWidth, restWidth int) []string {
	var done []string
	var line strings.Builder
	used, limit := 0, firstWidth
	for i, p := range pieces {
		width := widthOf(p.text)
		switch {
		case i == 0:
			line.WriteString(strings.Repeat(" ", p.gap))
			used = p.gap
		case used+p.gap+width > limit:
			done = append(done, line.String())
			line.Reset()
			used, limit = 0, restWidth
		default:
			line.WriteString(strings.Repeat(" ", p.gap))
			used += p.gap
		}
		line.WriteString(p.text)
		used += width
	}
	return append(done, line.String())
}

// writeFlow writes a lead and then the pieces, on as many lines as the page
// needs, with every line after the first starting at indent.
//
// THE LEAD'S WIDTH IS PASSED RATHER THAN MEASURED, because a lead may carry the
// colour of a status and the escape sequence around it takes no room on the
// screen. Measuring it would set every continuation too far right on a colour
// console and nowhere else.
func writeFlow(b *strings.Builder, lead string, leadWidth, indent int, pieces []piece) {
	margin := strings.Repeat(" ", indent)
	for i, line := range lines(pieces, pageWidth-leadWidth, pageWidth-indent) {
		if i == 0 {
			writeTrimmed(b, lead+line)
			continue
		}
		writeTrimmed(b, margin+line)
	}
}

// writeLabelled writes one line of the block under a finding - a label such as
// "note:" and what it says - with every continuation lined up after the label.
//
// LINED UP AFTER THE LABEL rather than under it, so the label column stays
// empty below a label and the eye finds the next one without reading the text.
func writeLabelled(b *strings.Builder, label string, pieces []piece) {
	lead := subIndent + label + " "
	writeFlow(b, lead, widthOf(lead), widthOf(lead), pieces)
}

// subIndent is where the block under a finding starts - the chain, the command,
// the authority and every note.
const subIndent = "        "
