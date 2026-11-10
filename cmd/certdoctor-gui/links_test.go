//go:build cgo

package main

import (
	"errors"
	"net/url"
	"slices"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/donislawdev/certdoctor/internal/gui/flow"
	"github.com/donislawdev/certdoctor/internal/gui/parts"
	"github.com/donislawdev/certdoctor/internal/gui/screens"
	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// browsed is a browser that keeps each page it is handed, and answers when the
// test says.
type browsed struct {
	pages []string
	done  []func(error)
}

func (b *browsed) browse(u *url.URL, done func(error)) {
	b.pages = append(b.pages, u.String())
	b.done = append(b.done, done)
}

// pressLinks presses GitHub and then Donate on the screen the window shows.
func pressLinks(t *testing.T, win *window, screen string) {
	t.Helper()
	for _, label := range []string{words.T(words.LinkGitHub), words.T(words.LinkDonate)} {
		b, ok := findButton(win.w.Content(), label).(*parts.Button)
		if !ok {
			t.Fatalf("the %s screen has no %s on its bar", screen, label)
		}
		b.Tapped(nil)
	}
}

// TestTheLinksOnEveryScreenOpenTheirPages presses both links on each of the four
// screens a window shows. They are built afresh with every screen, so a screen
// whose links nobody wired would draw two buttons that do nothing.
func TestTheLinksOnEveryScreenOpenTheirPages(t *testing.T) {
	win, h, _ := testWindow(t)
	b := &browsed{}
	win.browse = b.browse
	want := []string{words.RepositoryURL, words.SupportURL}
	check := func(screen string) {
		t.Helper()
		b.pages = nil
		pressLinks(t, win, screen)
		if !slices.Equal(b.pages, want) {
			t.Errorf("GitHub and Donate on the %s screen opened %q, want %q", screen, b.pages, want)
		}
	}

	check("start")
	win.form.Address.SetText("https://example.com")
	win.diagnose()
	check("running")
	h.runs[0].done(flow.Process{Out: exampleReport(t), Code: 4})
	check("report")
	win.again()
	h.runs[1].done(flow.Process{Code: 2, Printed: []byte("certdoctor: not a URL")})
	if win.flow.Phase() != flow.Troubled {
		t.Fatalf("a refusal left the window on %d", win.flow.Phase())
	}
	check("trouble")
	win.back()
	check("start, shown again")
}

// TestAPageTheDesktopDidNotOpenIsSaidUnderItsLink - when the toolkit could not
// hand the page over, the window says so over the screen, with the address
// to copy. The answer comes back after the program that opens it ended, by
// which time the screen can be another: the notice stands under the same link
// of the screen there is.
func TestAPageTheDesktopDidNotOpenIsSaidUnderItsLink(t *testing.T) {
	win, _, _ := testWindow(t)
	b := &browsed{}
	win.browse = b.browse
	pressLinks(t, win, "start")
	b.done[0](nil)
	if win.w.Canvas().Overlays().Top() != nil {
		t.Fatal("a page that opened was said not to have")
	}

	win.form.Address.SetText("https://example.com")
	win.diagnose()
	b.done[1](errors.New("no program opens this kind of address"))
	if win.notice == nil || !win.notice.Visible() || win.w.Canvas().Overlays().Top() == nil {
		t.Fatal("a page the desktop did not open was not said")
	}
	for _, said := range []string{words.T(words.LinkFailed), words.SupportURL} {
		if !showsText(win.notice.Content, said) {
			t.Errorf("what the window says about the page does not say %q", said)
		}
	}

	// Under Donate, the link it is about, on the running screen: right edges
	// in line, as the Save report menu stands under its button. In fyne
	// v2.8.2 the popup itself is moved and what it holds stands at its
	// corner (widget/popup.go), and the edges meet within a padding.
	donate, ok := findButton(win.w.Content(), words.T(words.LinkDonate)).(*parts.Button)
	if !ok {
		t.Fatal("no Donate on the running screen")
	}
	right := win.notice.Position().X + win.notice.Content.Size().Width
	want := fyne.CurrentApp().Driver().AbsolutePositionForObject(donate).X + donate.Size().Width
	if gap := right - want; gap < -2*theme.Padding() || gap > 2*theme.Padding() {
		t.Errorf("what is said about Donate ends at %v, and Donate at %v - it does not stand under the link", right, want)
	}

	// A second page that did not open replaces what was said, rather than
	// standing on it.
	first := win.notice
	win.visit(words.RepositoryURL)
	b.done[2](errors.New("still none"))
	if first.Visible() || win.notice == first || len(win.w.Canvas().Overlays().List()) != 1 {
		t.Errorf("a second page that did not open left %d things over the screen, the first still shown %v",
			len(win.w.Canvas().Overlays().List()), first.Visible())
	}
}

// TestAPageIsHandedOverBesideTheLoop - openBeside hands the page to the
// toolkit and its answer to done. The toolkit's test app opens nothing, so
// nothing appears on the screen of whoever runs this.
func TestAPageIsHandedOverBesideTheLoop(t *testing.T) {
	test.NewTempApp(t)
	u, err := url.Parse(words.RepositoryURL)
	if err != nil {
		t.Fatal(err)
	}
	answered := make(chan error, 1)
	openBeside(u, func(err error) { answered <- err })
	select {
	case err := <-answered:
		if err != nil {
			t.Errorf("the toolkit's test app answered %v for a page it opens without a word", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("handing a page over never answered")
	}
}

// TestAnAddressThatIsNotOneIsSaidRatherThanHandedOn - an address the window
// cannot read as one is not handed to the browser, and is said like a page
// that did not open.
func TestAnAddressThatIsNotOneIsSaidRatherThanHandedOn(t *testing.T) {
	win, _, _ := testWindow(t)
	b := &browsed{}
	win.browse = b.browse
	const broken = "https://exa%zzmple.com"
	win.lead([]screens.Link{{Button: parts.NewButton(parts.Quiet, "Broken", nil, nil), Address: broken}})
	win.visit(broken)
	if len(b.pages) != 0 {
		t.Errorf("%q was handed to the browser", broken)
	}
	if top := win.w.Canvas().Overlays().Top(); top == nil || !showsText(top, broken) {
		t.Error("an address that is not one was not said")
	}
}

// showsText says whether o, or anything inside it, is drawn as text - shows
// for the toolkit's labels and buttons, and the window's own parts besides.
func showsText(o fyne.CanvasObject, text string) bool {
	return shows(o, text) || drawsText(o, text)
}

// drawsText says whether o, or anything inside it, is the rich text the
// window's parts draw words with, saying text.
func drawsText(o fyne.CanvasObject, text string) bool {
	if r, ok := o.(*widget.RichText); ok && r.String() == text {
		return true
	}
	var inside []fyne.CanvasObject
	switch x := o.(type) {
	case *fyne.Container:
		inside = x.Objects
	case fyne.Widget:
		inside = test.WidgetRenderer(x).Objects()
	}
	for _, child := range inside {
		if drawsText(child, text) {
			return true
		}
	}
	return false
}
