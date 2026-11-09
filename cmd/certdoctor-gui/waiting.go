//go:build cgo

package main

import (
	"context"

	"fyne.io/fyne/v2"

	"github.com/donislawdev/certdoctor/internal/gui/flow"
)

// THIS FILE IS ON THE CONCURRENCY GUARD'S sandboxAllowlist, AND IT IS A FILE OF
// ITS OWN FOR THAT REASON - the owner's decision of 2026-11-09, recorded with
// ADR121. The entry excuses a go statement and nothing else: no sync, no
// channel, no select. An entry takes the guard off a file for that question
// for ever, so the file holds the one function that needs it.

// waitFor runs args through port beside the toolkit's loop and hands what came
// of it to done on the toolkit's goroutine.
//
// Beside the loop, because a run takes up to its limit and a window that waits
// for it on its own goroutine stops drawing, cannot be cancelled, and is called
// not responding by the system. The answer travels back through fyne.Do - the
// toolkit's own way into its goroutine - rather than through anything the two
// goroutines share, so nothing here needs a lock or a channel (fyne v2.8.2,
// thread.go: "Developers should use this only from within goroutines they have
// created"). The goroutine ends when the run does: port.Run returns when the
// process has ended, and ctx is how the window ends it sooner.
func waitFor(ctx context.Context, port flow.Port, args []string, done func(flow.Process)) {
	go func() {
		answer := port.Run(ctx, args)
		fyne.Do(func() { done(answer) })
	}()
}
