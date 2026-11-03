//go:build cgo

package main

import "golang.org/x/sys/windows"

// The kind of system dialog: one OK button under an error icon, brought to the
// front, because it is the only thing this process has on screen.
const dialogKind = windows.MB_OK | windows.MB_ICONERROR | windows.MB_SETFOREGROUND

// sayInADialog puts title and body in a system dialog owned by no window, for
// the one moment this program has something to say and no window to say it in.
// A program built for the windows subsystem has no console either, so without
// this the sentence goes nowhere a person looks.
//
// Through golang.org/x/sys/windows rather than syscall, by the owner's decision
// (ADR127): the call is typed, this file holds no unsafe, and the package loads
// user32.dll from the system directory rather than by the search order. The
// module was already linked into the window by the toolkit, so nothing new is
// compiled in - this is the one file of ours that names it, and it stands on
// externalImportAllowlist for that.
//
// The dialog needs a desktop and answers nought without one. That answer is not
// read: the sentence has already gone to standard error and the exit code says
// the rest.
func sayInADialog(title, body string) {
	caption, err := windows.UTF16PtrFromString(title)
	if err != nil {
		return
	}
	text, err := windows.UTF16PtrFromString(body)
	if err != nil {
		return
	}
	_, _ = windows.MessageBox(0, text, caption, dialogKind)
}
