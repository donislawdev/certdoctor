package parts

import (
	"slices"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"
)

// rowsOf lays a part of text out at a width and reads back the lines it was
// drawn on, the way they stand on the screen: top to bottom, each line's
// pieces left to right.
func rowsOf(t *testing.T, o fyne.CanvasObject, width float32) []string {
	t.Helper()
	w := test.NewTempWindow(t, Box(width, 0, o))
	w.SetPadded(false)
	w.Resize(fyne.NewSize(width, 1000))
	rich := richIn(o)
	if rich == nil {
		t.Fatal("no rich text inside the part")
	}
	type piece struct {
		at   fyne.Position
		text string
	}
	var pieces []piece
	for _, obj := range test.WidgetRenderer(rich).Objects() {
		if txt, ok := obj.(*canvas.Text); ok && txt.Text != "" {
			pieces = append(pieces, piece{txt.Position(), txt.Text})
		}
	}
	slices.SortFunc(pieces, func(a, b piece) int {
		if a.at.Y != b.at.Y {
			return int(a.at.Y - b.at.Y)
		}
		return int(a.at.X - b.at.X)
	})
	var rows []string
	for i, p := range pieces {
		if i == 0 || p.at.Y != pieces[i-1].at.Y {
			rows = append(rows, "")
		}
		rows[len(rows)-1] += p.text
	}
	return rows
}

func richIn(o fyne.CanvasObject) *widget.RichText {
	switch x := o.(type) {
	case *widget.RichText:
		return x
	case *fyne.Container:
		for _, child := range x.Objects {
			if r := richIn(child); r != nil {
				return r
			}
		}
	case fyne.Widget:
		// The theme override round every piece of text is a widget, not a
		// container: what it holds is reached through its renderer.
		for _, child := range test.WidgetRenderer(x).Objects() {
			if r := richIn(child); r != nil {
				return r
			}
		}
	}
	return nil
}

// brokenInside is the first line that ends neither at a separator nor at the
// end of the text - a name or a folder cut in two.
func brokenInside(rows []string) (string, bool) {
	for _, row := range rows[:max(len(rows)-1, 0)] {
		row = strings.TrimRight(row, " ")
		if row == "" || !strings.ContainsRune(pathBreaks+",", rune(row[len(row)-1])) {
			return row, true
		}
	}
	return "", false
}

// TestAPathBreaksOnlyAfterASeparator is OBS218 (a): in a column too narrow for
// it, a path and a list of names break after a separator, never inside a
// folder or a name, and nothing is lost or moved - at every width tried, so
// the check does not rest on where one width happens to fall. The same words
// drawn by the part that drew them before - Code for a path, Para for the
// names - have to show a line cut inside a name at one of those widths, or
// the check could not tell the two apart.
func TestAPathBreaksOnlyAfterASeparator(t *testing.T) {
	newApp(t)
	widths := []float32{120, 140, 160, 180, 200, 220}
	for _, c := range []struct {
		style  Style
		text   string
		before func(Style, string) fyne.CanvasObject
	}{
		{MonoMuted, `C:\Users\jdoe\AppData\Local\Programs\Python\Python315\python.exe`, Code},
		{MonoMuted, `/usr/lib/jvm/java-21-openjdk-amd64/lib/security/cacerts`, Code},
		{BodyMuted, "NODE_USE_SYSTEM_CA, NODE_EXTRA_CA_CERTS, REQUESTS_CA_BUNDLE", Para},
	} {
		wrapped, oldCut := false, false
		for _, width := range widths {
			rows := rowsOf(t, Path(c.style, c.text), width)
			wrapped = wrapped || len(rows) > 1
			if row, bad := brokenInside(rows); bad {
				t.Errorf("%q at %v is broken inside a name, on the line %q: %q", c.text, width, row, rows)
			}
			// Pieces share a line while they fit: one folder a line also
			// ends every line at a separator, and reads like a column.
			if pieces := len(pathPieces(c.text)); len(rows) >= pieces {
				t.Errorf("%q at %v drawn on %d lines for %d pieces - every piece on a line of its own: %q",
					c.text, width, len(rows), pieces, rows)
			}
			if got := strings.Join(rows, ""); strings.ReplaceAll(got, " ", "") != strings.ReplaceAll(c.text, " ", "") {
				t.Errorf("%q at %v drawn as %q", c.text, width, rows)
			}
			_, cut := brokenInside(rowsOf(t, c.before(c.style, c.text), width))
			oldCut = oldCut || cut
		}
		if !wrapped {
			t.Errorf("%q fits on one line at every width tried, so this check proves nothing", c.text)
		}
		if !oldCut {
			t.Errorf("%q drawn the old way breaks only at separators at every width too, so this check cannot fail", c.text)
		}
	}
}

// TestAPieceWiderThanALineIsStillBrokenAndKept - a name with no separator,
// longer than the column, is broken inside after all rather than run past the
// edge, and every character of it is still drawn.
func TestAPieceWiderThanALineIsStillBrokenAndKept(t *testing.T) {
	newApp(t)
	text := strings.Repeat("abcdefghij", 6)
	rows := rowsOf(t, Path(MonoMuted, text), 120)
	if len(rows) < 2 {
		t.Fatalf("a %d character name stands on one line in 120: %q", len(text), rows)
	}
	if strings.Join(rows, "") != text {
		t.Errorf("drawn as %q, which is not %q", rows, text)
	}
}

func TestPathPiecesPutBackTogetherAreTheWords(t *testing.T) {
	for _, words := range []string{"", "-", `C:\`, `a\b/c_d-e`, "no separator", `\\server\share\`, "na\xc3\xafve_caf\xc3\xa9"} {
		pieces := pathPieces(words)
		if len(pieces) == 0 || strings.Join(pieces, "") != words {
			t.Errorf("%q cut into %q", words, pieces)
		}
		for _, p := range pieces[:len(pieces)-1] {
			if !strings.ContainsRune(pathBreaks, []rune(p)[len([]rune(p))-1]) {
				t.Errorf("%q: the piece %q does not end at a separator", words, p)
			}
		}
	}
}
