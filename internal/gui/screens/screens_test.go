package screens

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"

	"github.com/donislawdev/certdoctor/internal/gui/look"
	"github.com/donislawdev/certdoctor/internal/gui/model"
	"github.com/donislawdev/certdoctor/internal/gui/parts"
	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// screen is one screen as the window can show it, built fresh for each size,
// because a canvas object belongs to one window at a time.
type screen struct {
	name  string
	build func() fyne.CanvasObject
}

// A size the window can be at. The minimum is the one that matters most: it
// is what the window's minimum size promises every screen will fit in (GUI
// rule 21). The large one is a common desktop, where the report stops growing.
var sizes = []fyne.Size{
	fyne.NewSize(look.WindowMinWidth, look.WindowMinHeight),
	fyne.NewSize(look.WindowWidth, look.WindowHeight),
	fyne.NewSize(1920, 1080),
}

// TestEveryScreenFitsItsWindow lays every screen out at every size above and
// fails when one asks for more width than the window has.
//
// What a screen too wide does is not a cut edge in a picture: the toolkit
// will not shrink a window below what its content needs, so the window at its
// minimum would quietly be wider than its minimum, or the screen eats its own
// right margin where no eye catches it. Measured on 2026-11-03 at the old
// minimum of 980: the report with the trust matrix needed 988, which nobody
// had seen on the picture.
//
// What it does not see: height, and words cut short inside a part that clips
// them on purpose - a clipped title asks for no width by design.
func TestEveryScreenFitsItsWindow(t *testing.T) {
	newApp(t)
	for _, s := range everyScreen(t) {
		for _, size := range sizes {
			if need := widthNeeded(s.build(), size); need > size.Width {
				t.Errorf("%s at %v asks for %.1f of width", s.name, size, need)
			}
		}
	}
}

// TestTheWidthCheckCanFail lays the report out in a window far narrower than
// any the window allows, where the trust matrix alone cannot fit.
func TestTheWidthCheckCanFail(t *testing.T) {
	newApp(t)
	narrow := fyne.NewSize(look.WindowMinWidth/2, look.WindowMinHeight)
	report := fixture(t, "example-com.json")
	o, _ := Report(icon(t), report, len(report.Layers)-1, 0)
	if need := widthNeeded(o, narrow); need <= narrow.Width {
		t.Fatalf("the report at %v asks for only %.1f - the check cannot tell a screen that does not fit", narrow, need)
	}
}

// TestEveryScreenLeadsToGitHubAndDonate holds the decision of 2026-11-03 that
// the two buttons leading out of the window stand on every screen, in the
// bar at the top, because a button that is there on one screen and gone on
// the next is one people conclude they imagined (ADR122).
func TestEveryScreenLeadsToGitHubAndDonate(t *testing.T) {
	newApp(t)
	for _, s := range everyScreen(t) {
		o := s.build()
		for _, label := range []string{words.T(words.LinkGitHub), words.T(words.LinkDonate)} {
			if findButton(o, label) == nil {
				t.Errorf("%s has no %q button", s.name, label)
			}
		}
	}
}

// widthNeeded is how wide the content asks to be once laid out at size.
// Twice, because wrapped text knows its height only once it has a width, and
// its minimum can change with that.
func widthNeeded(content fyne.CanvasObject, size fyne.Size) float32 {
	w := test.NewWindow(content)
	defer w.Close()
	w.SetPadded(false)
	w.Resize(size)
	w.Resize(size)
	return content.MinSize().Width
}

// everyScreen is every screen the window has, with the data each is drawn
// from: the three reports kept as test data, every layer of each, and the
// four ways the window says certdoctor itself could not run.
func everyScreen(t *testing.T) []screen {
	t.Helper()
	ic := icon(t)
	var all []screen
	for _, open := range []bool{false, true} {
		all = append(all, screen{fmt.Sprintf("start (options open %v)", open), func() fyne.CanvasObject {
			o, _ := Start(ic, "0.1.0", open)
			return o
		}})
	}
	for _, name := range []string{"example-com.json", "untrusted-root.json", "wrong-host.json"} {
		r := fixture(t, name)
		all = append(all, screen{"running " + name, func() fyne.CanvasObject {
			return Running(ic, r.Version, r.Target, 12, 30)
		}})
		for layer := range r.Layers {
			all = append(all, screen{fmt.Sprintf("report %s %s", name, r.Layers[layer].ID), func() fyne.CanvasObject {
				o, _ := Report(ic, r, layer, 0)
				return o
			}})
		}
	}
	for _, trouble := range [][3]words.Key{
		{words.MissingTitle, words.MissingWhat, words.MissingTodo},
		{words.VersionTitle, words.VersionWhat, words.VersionTodo},
		{words.RefusedTitle, "", words.RefusedTodo},
		{words.CrashedTitle, words.CrashedWhat, words.CrashedTodo},
	} {
		all = append(all, screen{"trouble " + string(trouble[0]), func() fyne.CanvasObject {
			what := ""
			if trouble[1] != "" {
				what = words.T(trouble[1])
			}
			return Trouble(ic, "0.1.0", words.T(trouble[0]), what, words.T(trouble[2]), longPrinted)
		}})
	}
	return all
}

// longPrinted stands for what certdoctor printed before it stopped: one long
// line with no space to break at, which is the shape that widens a screen.
const longPrinted = "certdoctor: https://exa%20mple.com/a/path/that/keeps/going/without/a/single/space/to/break/at/" +
	"and/on/and/on is not a URL certdoctor can read"

// findButton is the button with these words on a drawn screen, looked for
// through the containers the screen is built of.
func findButton(o fyne.CanvasObject, label string) fyne.CanvasObject {
	if b, ok := o.(*parts.Button); ok && b.Label == label {
		return b
	}
	if c, ok := o.(*fyne.Container); ok {
		for _, child := range c.Objects {
			if found := findButton(child, label); found != nil {
				return found
			}
		}
	}
	return nil
}

// newApp is a test application in the window's theme. One typeface for the
// whole process: the toolkit keeps what it measured of a piece of text
// without keying it on the face, so a second face drawn in the same process
// is laid out with the first one's widths (ADR122).
func newApp(t *testing.T) {
	t.Helper()
	test.NewTempApp(t).Settings().SetTheme(look.Theme())
}

func icon(t *testing.T) fyne.Resource {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "assets", "icon", "certdoctor.png"))
	if err != nil {
		t.Fatal(err)
	}
	return fyne.NewStaticResource("certdoctor.png", b)
}

func fixture(t *testing.T, name string) model.Report {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "model", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	r, err := model.Decode(b)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return r
}
