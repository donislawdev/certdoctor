//go:build cgo

package main

import "fyne.io/fyne/v2"

// keepDark asks for the title bar of w dark again after every change of the
// settings s - which on Windows the toolkit answers by setting that bar from
// the system's mode for apps (see darkTitleBar). Through fyne.Do, which on
// the toolkit's loop queues the call behind the change being handled, so it
// lands after the toolkit's own answer whichever listener was added first.
func keepDark(s fyne.Settings, w fyne.Window, darken func(fyne.Window)) {
	s.AddListener(func(fyne.Settings) { fyne.Do(func() { darken(w) }) })
}
