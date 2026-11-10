//go:build !windows && cgo

package main

import "fyne.io/fyne/v2"

// darkTitleBar leaves the title bar to the system outside Windows. macOS
// draws it in the appearance the system is set to, and on Linux the window
// manager draws it - neither through anything the toolkit offers to set.
func darkTitleBar(fyne.Window) {}
