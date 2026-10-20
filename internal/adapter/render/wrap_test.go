package render

import (
	"slices"
	"strings"
	"testing"
)

// The line breaking every part of the terminal page goes through - OBS165.
//
// IT IS TESTED HERE ON ITS OWN, AND NOT ONLY THROUGH THE PAGE, because the page
// can only ever show the cases somebody thought to put in a fixture. What this
// file holds is the promise the whole layout rests on: wrapping moves words to
// another line and does nothing else to them.

// wordsOf is the words of a text, split where prose splits it - at an ASCII
// space and nowhere else.
func wordsOf(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ' ' })
}

// TestASentenceThatFitsComesOutExactlyAsItWentIn is the case almost every
// sentence is in, and it has to cost nothing: not a space added, not a space
// taken, including two in a row inside a value somebody else wrote.
func TestASentenceThatFitsComesOutExactlyAsItWentIn(t *testing.T) {
	for _, sentence := range []string{
		"x",
		"one line",
		"two  spaces stay two",
		"   leading spaces are kept on the first line",
	} {
		got := lines(prose(sentence), 100, 100)
		if len(got) != 1 || got[0] != sentence {
			t.Errorf("%q came out as %q", sentence, got)
		}
	}
}

// TestNothingToSayIsOneEmptyLine is the empty case, which a caller turns into a
// lead with nothing after it. Zero lines would leave the lead unwritten.
func TestNothingToSayIsOneEmptyLine(t *testing.T) {
	for _, pieces := range [][]piece{nil, prose(""), prose("     ")} {
		if got := lines(pieces, 10, 10); len(got) != 1 || got[0] != "" {
			t.Errorf("nothing to say came out as %q", got)
		}
	}
}

// TestALineBreaksAtTheLastSpaceThatFits pins the boundary from both sides: a
// line exactly as wide as allowed stays whole, one character over does not.
func TestALineBreaksAtTheLastSpaceThatFits(t *testing.T) {
	cases := []struct {
		width int
		want  []string
	}{
		{7, []string{"aaa bbb", "ccc"}},
		{6, []string{"aaa", "bbb", "ccc"}},
		{11, []string{"aaa bbb ccc"}},
		{10, []string{"aaa bbb", "ccc"}},
	}
	for _, c := range cases {
		if got := lines(prose("aaa bbb ccc"), c.width, c.width); !slices.Equal(got, c.want) {
			t.Errorf("at width %d: got %q, want %q", c.width, got, c.want)
		}
	}
}

// TestTheFirstLineAndTheRestHaveTheirOwnWidths is the hanging indent: the first
// line shares the page with a lead, and every other line with an indent of a
// different width.
func TestTheFirstLineAndTheRestHaveTheirOwnWidths(t *testing.T) {
	got := lines(prose("aa bb cc dd ee"), 2, 8)
	want := []string{"aa", "bb cc dd", "ee"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestAPieceTooWideForAnyLineStandsAloneAndWhole is the rule that lets a command
// run past the page: a datum is never cut, so the only thing to do with one that
// does not fit is to give it a line of its own.
func TestAPieceTooWideForAnyLineStandsAloneAndWhole(t *testing.T) {
	long := "a-datum-far-wider-than-the-line"
	got := lines([]piece{{text: "short"}, {text: long, gap: 1}, {text: "tail", gap: 1}}, 10, 10)
	want := []string{"short", long, "tail"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}

	// And when it is the very first thing: it still takes the first line rather
	// than leaving that line empty behind its lead.
	if got := lines([]piece{{text: long}}, 3, 3); !slices.Equal(got, []string{long}) {
		t.Errorf("a first piece wider than the line came out as %q", got)
	}
}

// TestTheGapGoesWhereTheLineBreaks: a continuation never starts with the spaces
// that separated it from the word before - they would push it off its indent.
func TestTheGapGoesWhereTheLineBreaks(t *testing.T) {
	if got := lines(prose("a  b"), 1, 1); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("got %q", got)
	}
}

// TestAListBreaksBetweenEntriesAndNeverInsideOne is the reason items exists. A
// store is a runtime and a path, the path has a space in it, and broken there
// one store would read as two.
func TestAListBreaksBetweenEntriesAndNeverInsideOne(t *testing.T) {
	entries := []string{`java C:\Program Files\Java\jre`, `git C:\Program Files\Git\cmd\git.exe`, "curl"}
	got := lines(items(entries), 40, 40)
	want := []string{`java C:\Program Files\Java\jre,`, `git C:\Program Files\Git\cmd\git.exe,`, "curl"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}

	// The separator is the one the page used before it could wrap.
	if got := lines(items([]string{"a", "b", "c"}), 100, 100); !slices.Equal(got, []string{"a, b, c"}) {
		t.Errorf("a list that fits came out as %q", got)
	}
}

// TestEveryContinuationStartsAtItsIndent is writeFlow's half: the lead on the
// first line, the indent on every other, and no padding left at a line end.
func TestEveryContinuationStartsAtItsIndent(t *testing.T) {
	var b strings.Builder
	writeFlow(&b, "lead:", 5, 7, prose(strings.Repeat("word ", 40)))

	page := strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n")
	if len(page) < 2 {
		t.Fatalf("two hundred characters fit on one line of a page %d wide:\n%s", pageWidth, b.String())
	}
	if !strings.HasPrefix(page[0], "lead:word ") {
		t.Errorf("the first line is %q", page[0])
	}
	for _, line := range page[1:] {
		if !strings.HasPrefix(line, "       word") || strings.HasPrefix(line, "        ") {
			t.Errorf("a continuation is not at its indent: %q", line)
		}
		if widthOf(line) > pageWidth {
			t.Errorf("a line of short words ran past the page: %q", line)
		}
	}
}

// TestALeadWithNothingAfterItEndsTheLine: padding a lead carries is dropped when
// nothing follows it, the same rule as every other line on the page.
func TestALeadWithNothingAfterItEndsTheLine(t *testing.T) {
	var b strings.Builder
	writeFlow(&b, "  lead   ", 9, 4, nil)
	if b.String() != "  lead\n" {
		t.Errorf("got %q", b.String())
	}
}

// FuzzWrappingMovesWordsAndDoesNothingElseToThem is the promise as a property,
// over text nobody chose.
//
// FOUR THINGS HOLD FOR ANY TEXT AND ANY TWO WIDTHS. The words come out in the
// order they went in, none lost and none added. No line ends in a space. No
// continuation starts with one. And a line runs past its width only when it is
// one word - the single case where the only alternative would be cutting it.
func FuzzWrappingMovesWordsAndDoesNothingElseToThem(f *testing.F) {
	f.Add("the presented chain does not reach any trust anchor this runtime knows about", 30, 20)
	f.Add("   leading and  doubled   spaces ", 5, 5)
	f.Add("one-word-wider-than-every-line", 4, 4)
	f.Add("", 0, 0)
	f.Add("a b c", -3, 1)
	// Built from code points, so this file carries no character its reader
	// cannot see: two-byte runes, where counting bytes would break too early.
	f.Add(string([]rune{0x0105, 0x0119, ' ', 0x017c, 0x00f3, 0x0142, 0x0107, ' ', 'r', 'u', 'n', 'e', 's'}), 6, 3)
	f.Add("line\nbreak and\ttab stay inside their words", 8, 8)

	f.Fuzz(func(t *testing.T, text string, first, rest int) {
		first, rest = first%300, rest%300
		got := lines(prose(text), first, rest)

		if !slices.Equal(wordsOf(strings.Join(got, " ")), wordsOf(text)) {
			t.Fatalf("the words changed:\n in  %q\n out %q", text, got)
		}
		for i, line := range got {
			if strings.HasSuffix(line, " ") {
				t.Errorf("line %d ends in a space: %q", i, line)
			}
			limit := first
			if i > 0 {
				limit = rest
				if strings.HasPrefix(line, " ") {
					t.Errorf("continuation %d starts with a space: %q", i, line)
				}
			}
			if widthOf(line) > limit && len(wordsOf(line)) > 1 {
				t.Errorf("line %d is %d wide against %d and holds more than one word: %q",
					i, widthOf(line), limit, line)
			}
		}
	})
}
