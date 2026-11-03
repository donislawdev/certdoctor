// Package icon carries the application's picture as bytes, for the window:
// its title bar, the task bar and the bar across the top of every screen.
//
// A package beside the picture rather than a copy of it under internal/gui.
// Go's embed directive cannot reach a parent directory, and a second copy of
// certdoctor.png would be a second source of truth for a file appicon.py draws
// and the release build compares (ADR117). Bytes import nothing, and only the
// window imports this package, so the command line never links them.
package icon

import _ "embed"

// PNG is the icon, 1024 px square with an alpha channel. One size rather than
// a set: the toolkit scales it down itself and asks for one resource.
//
//go:embed certdoctor.png
var PNG []byte
