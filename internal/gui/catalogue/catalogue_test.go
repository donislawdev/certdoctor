package catalogue

import (
	"os"
	"path/filepath"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"

	"github.com/donislawdev/certdoctor/internal/gui/look"
	"github.com/donislawdev/certdoctor/internal/gui/model"
)

// measuredPairs is how many pairs of colours the window was measured to draw
// one over the other on 2026-11-03 (ADR122). The count may grow with a new
// part and never shrink without a reason: a pair that drops off the list is a
// measurement nobody makes any more, and the check below would stay green.
const measuredPairs = 51

// TestEveryPairTheWindowDrawsMeetsItsThreshold is the contrast of the window
// measured rather than judged (docs/26 section 7.1): every pair of colours
// the window draws one over the other, at 4.5 for words and 3.0 for edges of
// controls, the focus ring and marks.
func TestEveryPairTheWindowDrawsMeetsItsThreshold(t *testing.T) {
	pairs := Pairs()
	if len(pairs) < measuredPairs {
		t.Fatalf("%d pairs measured, and %d were on 2026-11-03 - a pair has dropped off the list", len(pairs), measuredPairs)
	}
	for _, p := range below(pairs) {
		t.Errorf("%s on %s: %.2f, needs %.1f", p.Front, p.Back, p.Ratio, p.Need)
	}
}

// TestTheContrastCheckCanFail hands the check the one ink the window keeps
// under 4.5 on purpose - the word on a control that cannot be pressed - held
// to the threshold for words.
func TestTheContrastCheckCanFail(t *testing.T) {
	faint := Pair{
		Front: string(look.InkDisabled), Back: string(look.Page),
		Ratio: look.Contrast(look.Colour(look.InkDisabled), look.Colour(look.Page)), Need: 4.5,
	}
	if got := below([]Pair{faint}); len(got) != 1 {
		t.Fatalf("a pair at %.2f against 4.5 was not reported", faint.Ratio)
	}
}

// TestEveryPageOfTheCatalogueFitsTheWindow lays the hidden screen out at the
// window's own size, the way it is opened (GUI rule 4).
func TestEveryPageOfTheCatalogueFitsTheWindow(t *testing.T) {
	test.NewTempApp(t).Settings().SetTheme(look.Theme())
	sample := sampleReport(t)
	parts, _ := Parts(appIcon(t), sample)
	for name, page := range map[string]fyne.CanvasObject{
		"palette":     Palette(),
		"type ladder": TypeLadder(sample),
		"parts":       parts,
	} {
		w := test.NewWindow(page)
		w.SetPadded(false)
		size := fyne.NewSize(look.WindowWidth, look.WindowHeight)
		w.Resize(size)
		w.Resize(size)
		if need := page.MinSize().Width; need > size.Width {
			t.Errorf("the %s page asks for %.1f of width in a window of %.1f", name, need, size.Width)
		}
		w.Close()
	}
}

func below(pairs []Pair) []Pair {
	var out []Pair
	for _, p := range pairs {
		if p.Ratio < p.Need {
			out = append(out, p)
		}
	}
	return out
}

func appIcon(t *testing.T) fyne.Resource {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "assets", "icon", "certdoctor.png"))
	if err != nil {
		t.Fatal(err)
	}
	return fyne.NewStaticResource("certdoctor.png", b)
}

func sampleReport(t *testing.T) model.Report {
	t.Helper()
	r, err := model.Example()
	if err != nil {
		t.Fatal(err)
	}
	return r
}
