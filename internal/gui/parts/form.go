package parts

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"

	"github.com/donislawdev/certdoctor/internal/gui/look"
)

// Field is one line of a form: a column of names on the left, all of one
// width so they line up, and the control with its note on the right. The
// name stands in the middle of the control's height, so it reads on the
// control's line whatever the control is.
func Field(name string, control fyne.CanvasObject, note string) fyne.CanvasObject {
	if note == "" {
		return FieldWith(name, control, nil)
	}
	return FieldWith(name, control, Para(CaptionMuted, note))
}

// FieldWith is a field whose note is a part of its own - a FieldNote that
// turns from the hint to a refusal - or none when note is nil.
func FieldWith(name string, control, note fyne.CanvasObject) fyne.CanvasObject {
	right := []fyne.CanvasObject{control}
	if note != nil {
		right = append(right, note)
	}
	return RowTop(look.GapField, 1,
		Width(look.LabelWidth, Height(look.ControlHeight, Middle(Text(Strong, name)))),
		Stack(look.GapTight, right...),
	)
}

// Form is fields one under another, a field's distance apart.
func Form(fields ...fyne.CanvasObject) fyne.CanvasObject {
	return Stack(look.GapField, fields...)
}

// AppMark is the program's icon at the size of the bar it stands in.
func AppMark(icon fyne.Resource) fyne.CanvasObject {
	img := canvas.NewImageFromResource(icon)
	img.FillMode = canvas.ImageFillContain
	img.SetMinSize(fyne.NewSquareSize(look.IconApp))
	return img
}

// Header is the bar across the top: the program's mark and name on the
// left, the places of the window beside them when nav is not nil, and
// whatever the screen puts at the far end.
func Header(icon fyne.Resource, name, version string, nav fyne.CanvasObject, trailing ...fyne.CanvasObject) fyne.CanvasObject {
	left := Row(look.GapInline,
		Middle(AppMark(icon)),
		Middle(Text(Heading, name)),
		Middle(Text(CaptionMuted, version)),
	)
	if nav != nil {
		left = Row(look.GapScreen, left, Middle(nav))
	}
	objects := append([]fyne.CanvasObject{left}, trailing...)
	return Stack(0, Bar(Height(look.ControlHeight, RowGrow(look.GapButtons, 0, objects...))), Rule())
}
