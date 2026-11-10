//go:build cgo

package main

import (
	"context"
	"net/url"

	"fyne.io/fyne/v2"

	"github.com/donislawdev/certdoctor/internal/gui/flow"
)

// THIS FILE IS ON THE CONCURRENCY GUARD'S sandboxAllowlist, AND IT IS A FILE OF
// ITS OWN FOR THAT REASON. The entry excuses go statements and nothing else:
// no sync, no channel, no select. It counts them - two, each the owner's
// decision: waitFor (2026-11-09, ADR121) and openBeside (2026-11-10, ADR122).
// A third goroutine here changes that count in the guard first, and so is a
// question before it is code.

// waitFor runs args through port beside the toolkit's loop, with input on the
// run's standard input, and hands what came of it to done on the toolkit's
// goroutine. A diagnosis and a saved copy of its report both come this way.
//
// Beside the loop, because a run takes up to its limit and a window that waits
// for it on its own goroutine stops drawing, cannot be cancelled, and is called
// not responding by the system. The answer travels back through fyne.Do - the
// toolkit's own way into its goroutine - rather than through anything the two
// goroutines share, so nothing here needs a lock or a channel (fyne v2.8.2,
// thread.go: "Developers should use this only from within goroutines they have
// created"). The goroutine ends when the run does: port.Run returns when the
// process has ended, and ctx is how the window ends it sooner.
func waitFor(ctx context.Context, port flow.Port, args []string, input []byte, done func(flow.Process)) {
	go func() {
		answer := port.Run(ctx, args, input)
		fyne.Do(func() { done(answer) })
	}()
}

// openBeside hands u to the browser through the toolkit beside its loop, and
// what came of it to done on the toolkit's goroutine.
//
// Beside the loop because the toolkit hands a page over by starting a program
// and, on two platforms, waiting for it to end - rundll32 on Windows and open
// on macOS, xdg-open on Linux only started (fyne v2.8.2, app/app_windows.go,
// app/app_desktop_darwin.go, app/app_xdg.go) - and a window waiting on its
// own goroutine stops drawing for that long. None of the three touches the
// toolkit's drawing, so the call is safe off its goroutine. The goroutine ends
// when that program does. The window itself connects to nothing (inviolable
// rule 16): the address goes to the browser, on a press.
func openBeside(u *url.URL, done func(error)) {
	open := fyne.CurrentApp().OpenURL
	go func() {
		err := open(u)
		fyne.Do(func() { done(err) })
	}()
}
