//go:build windows && cgo

package main

import (
	"testing"
	"unsafe"

	"fyne.io/fyne/v2/test"
	"golang.org/x/sys/windows"
)

// hiddenWindow is a top-level window of the system's own STATIC class that is
// never shown: no WS_VISIBLE, so nothing appears on the screen and nothing
// takes the keyboard while the test asks Windows about its title bar.
func hiddenWindow(t *testing.T) uintptr {
	t.Helper()
	user32 := windows.NewLazySystemDLL("user32.dll")
	create := user32.NewProc("CreateWindowExW")
	destroy := user32.NewProc("DestroyWindow")
	class, err := windows.UTF16PtrFromString("STATIC")
	if err != nil {
		t.Fatal(err)
	}
	const overlappedWindow = 0x00CF0000 // WS_OVERLAPPEDWINDOW, without WS_VISIBLE
	hwnd, _, callErr := create.Call(0, uintptr(unsafe.Pointer(class)), 0, overlappedWindow, 0, 0, 200, 100, 0, 0, 0, 0)
	if hwnd == 0 {
		t.Fatalf("CreateWindowExW made no window: %v", callErr)
	}
	t.Cleanup(func() { _, _, _ = destroy.Call(hwnd) })
	return hwnd
}

// TestWindowsTakesTheDarkTitleBar asks Windows for the dark title bar of a
// real window and of no window at all. A real one is answered with success -
// so the library loads, the call is found and the value has the size Windows
// reads - and no window is answered with an error rather than a crash. What
// the bar then looks like on a desktop in light mode is not measured here:
// that needs a window on the screen.
func TestWindowsTakesTheDarkTitleBar(t *testing.T) {
	if err := darken(hiddenWindow(t)); err != nil {
		t.Errorf("Windows refused the dark title bar of a real window: %v", err)
	}
	if err := darken(0); err == nil {
		t.Error("Windows took a dark title bar for no window at all - the call is not reaching it")
	}
	// A window of the toolkit's test driver has no native handle, and is
	// left alone rather than asked about.
	test.NewTempApp(t)
	darkTitleBar(test.NewTempWindow(t, nil))
}
