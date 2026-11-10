//go:build windows && cgo

package main

import (
	"unsafe"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/driver"
	"golang.org/x/sys/windows"
)

// THIS FILE IS ON TWO GUARDS' LISTS - unsafeAllowlist and
// externalImportAllowlist - by the owner's decision of 2026-11-10, recorded
// with ADR122, and a file of its own for that reason: an entry takes a guard
// off a file for ever, so the file holds the one call that needs it.

// darkTitleBar asks Windows to draw the title bar of w dark, as the window
// under it is whatever the desktop is set to (ADR122).
//
// The toolkit sets the same attribute itself, from the system's mode for
// apps: dark only when AppsUseLightTheme is 0, which a Windows 11 left as it
// was installed is not - so a dark window under a white bar (fyne v2.8.2,
// internal/driver/glfw/window_windows.go, setDarkMode and isDark). It does so
// when it creates the window and again after every change of settings, so
// this is asked once the window is shown and again after each change -
// keepDark.
//
// A window with no native handle - not created yet, or one of the toolkit's
// test driver - is left alone. What Windows answers is not said: a bar it
// would not darken keeps the colour it had, which is where the window was
// before this existed.
func darkTitleBar(w fyne.Window) {
	native, ok := w.(driver.NativeWindow)
	if !ok {
		return
	}
	native.RunNative(func(context any) {
		if c, ok := context.(driver.WindowsWindowContext); ok && c.HWND != 0 {
			_ = darken(c.HWND)
		}
	})
}

// darken sets DWMWA_USE_IMMERSIVE_DARK_MODE on the window: attribute 20, a
// BOOL - four bytes - set to TRUE (learn.microsoft.com, DWMWINDOWATTRIBUTE
// enumeration, read 2026-11-10: "supported starting with Windows 11 Build
// 22000"; Windows 10 since 20H1 takes it too, and an older one answers an
// error and keeps its bar). x/sys/windows loads dwmapi.dll from the system
// directory.
func darken(hwnd uintptr) error {
	on := int32(1)
	return windows.DwmSetWindowAttribute(windows.HWND(hwnd), windows.DWMWA_USE_IMMERSIVE_DARK_MODE,
		unsafe.Pointer(&on), uint32(unsafe.Sizeof(on)))
}
