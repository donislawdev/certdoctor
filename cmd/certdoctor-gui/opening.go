//go:build cgo

package main

import (
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/driver"

	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// openOrRefuse shows w and runs the toolkit's loop only when the toolkit gave
// it a window (ADR125 point 1). When it did not, refuse is called and the
// answer is 1, the exit code a build with no window in it gives too.
//
// Read in fyne v2.8.2 (internal/driver/glfw/driver.go, initFailed and Quit):
// when the window cannot be created before the loop runs, the toolkit logs why
// to a standard error that a program built for the windows subsystem does not
// have, then calls Quit, which closes nothing because the loop was never marked
// running - and Run waits forever. A double click, nothing on screen, and the
// process in the task list until the session ends.
//
// The same failure has a second shape, measured 2026-11-03 in a Linux
// container with no display: the toolkit cannot initialise GLFW, logs why, and
// its next call into GLFW - the first line that creates the window - panics
// instead of returning an error, before anything of ours is laid out. That is
// a crash with a stack trace and exit code 2 where a refusal belongs, so a
// panic out of Show is a refusal too when it left no window behind. When a
// window does exist, whatever panicked is not the toolkit failing to give one,
// and it goes on as the panic it was rather than under a sentence about OpenGL.
//
// ShowAndRun is Show followed by Run and nothing else, so where the window
// opens this is the same two calls in the same order. The question between
// them is asked of the window's state, not of what the toolkit logged.
func openOrRefuse(w fyne.Window, run func(), refuse func(panicked any)) int {
	panicked := show(w)
	if !shown(w) {
		refuse(panicked)
		return 1
	}
	if panicked != nil {
		panic(panicked)
	}
	run()
	return 0
}

// show shows w and hands back what it panicked with, or nil.
func show(w fyne.Window) (panicked any) {
	defer func() { panicked = recover() }()
	w.Show()
	return nil
}

// shown reports whether the toolkit gave w a native window when it was shown.
//
// Asked of the driver's NativeWindow, which hands over a zero handle when the
// window it wraps was never created - read in fyne v2.8.2, where the files for
// Windows, macOS, X11 and Wayland each fill the handle in only when the view
// exists. A public answer about state, which does not depend on the wording of
// anything the toolkit logged on the way.
//
// A window that cannot answer is taken as shown: the toolkit's test driver
// draws without a native window at all, so for it nothing has failed. The same
// goes for a context this does not know how to read.
func shown(w fyne.Window) bool {
	native, ok := w.(driver.NativeWindow)
	if !ok {
		return true
	}
	handle, answered := uintptr(0), false
	native.RunNative(func(context any) {
		switch c := context.(type) {
		case driver.WindowsWindowContext:
			handle, answered = c.HWND, true
		case driver.MacWindowContext:
			handle, answered = c.NSWindow, true
		case driver.X11WindowContext:
			handle, answered = c.WindowHandle, true
		case driver.WaylandWindowContext:
			handle, answered = c.WaylandSurface, true
		}
	})
	return !answered || handle != 0
}

// causeMarker is the word the toolkit's logger puts in front of the error it
// was handed (fyne v2.8.2, log.go, LogError). Read as an anchor and never shown.
const causeMarker = "Cause:"

// causeFrom picks the toolkit's own reason out of what it logged while the
// window was being opened: the text after the LAST cause marker, because the
// failure that stopped the window is the last thing the toolkit said before
// this program asked. Measured 2026-11-03 on Linux with no display: the first
// cause logged was about the toolkit's cache directory, and only the last one
// about the graphics library. When no line carries one and the toolkit
// panicked instead, what it panicked with, and otherwise nothing. Detail for
// the sentence and never the decision, which shown takes from state - a
// toolkit that changes how it logs costs the detail and not the refusal.
func causeFrom(logged string, panicked any) string {
	cause := ""
	for _, line := range strings.Split(logged, "\n") {
		if _, after, found := strings.Cut(line, causeMarker); found {
			cause = strings.TrimSpace(after)
		}
	}
	if cause == "" && panicked != nil {
		cause = fmt.Sprint(panicked)
	}
	return cause
}

// refusal is the sentence that says the window could not be opened, with the
// toolkit's cause quoted when it gave one.
func refusal(cause string) string {
	if cause == "" {
		return words.T(words.WindowRefused)
	}
	return fmt.Sprintf(words.T(words.WindowRefusedCause), cause)
}
