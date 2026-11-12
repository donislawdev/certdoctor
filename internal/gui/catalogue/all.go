package catalogue

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"

	"github.com/donislawdev/certdoctor/internal/gui/model"
	"github.com/donislawdev/certdoctor/internal/gui/parts"
)

// All is the catalogue as the window shows it under --catalogue (GUI rule 4):
// every part in every state, the tools' parts, then the palette and the ladder of type, one
// page under the other in one scroll - and the box to type in that should
// hold the keyboard, so its focused state is drawn as well.
func All(icon fyne.Resource, r model.Report) (fyne.CanvasObject, fyne.Focusable) {
	page, focus := Parts(icon, r)
	return container.NewVScroll(parts.Stack(0, page, ToolParts(), Palette(), TypeLadder(r))), focus
}
