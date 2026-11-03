// Package planted imports the window's toolkit, for the guard that says where
// that toolkit may be imported.
package planted

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/widget"
)

var _ fyne.CanvasObject = widget.NewLabel("")
