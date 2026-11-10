//go:build cgo

package main

import (
	"net/url"

	"fyne.io/fyne/v2/widget"

	"github.com/donislawdev/certdoctor/internal/gui/parts"
	"github.com/donislawdev/certdoctor/internal/gui/screens"
	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// lead makes the links on a screen's bar lead out: a press hands the link's
// page to the browser (ADR122), and they are the links a page that did not
// open is said under.
func (win *window) lead(links []screens.Link) {
	win.links = links
	for _, l := range links {
		l.OnTapped = func() { win.visit(l.Address) }
	}
}

// visit hands the page at address to the browser beside the toolkit's loop,
// because the toolkit waits for the program that opens it on two platforms.
func (win *window) visit(address string) {
	u, err := url.Parse(address)
	if err != nil {
		win.notVisited(address)
		return
	}
	win.browse(u, func(opened error) {
		if opened != nil {
			win.notVisited(address)
		}
	})
}

// notVisited says that the page at address did not open, under the link to
// it on the screen the window shows now - the answer can come after the
// screen changed, and every screen has the same links in the same place -
// with the address and Copy beside it. A press anywhere else puts it away.
//
// What it cannot say: xdg-open on Linux is only started, so one that found
// nothing to open the page with returns no error and nothing is said. Both
// addresses stand in the README for that case.
func (win *window) notVisited(address string) {
	for _, l := range win.links {
		if l.Address != address {
			continue
		}
		if win.notice != nil {
			win.notice.Hide()
		}
		notice := parts.Notice(words.T(words.LinkFailed), words.T(words.LinkFailedNote), address)
		win.notice = widget.NewPopUp(notice, win.w.Canvas())
		win.notice.ShowAtPosition(under(l.Button, notice))
		return
	}
}
