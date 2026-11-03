package parts

import (
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/theme"

	"github.com/donislawdev/certdoctor/internal/gui/look"
	"github.com/donislawdev/certdoctor/internal/gui/model"
	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// The trust matrix: one row a store, five columns, the one naming where the
// store lives taking the width the others leave. Columns are declared once,
// here, and the head and every row are laid from the same list.

type cell struct {
	width float32 // zero: takes what is left
	head  words.Key
	// drop gives the column's room to the one that takes what is left, when
	// that one would get narrower than look.ColInstanceMin - the rule for a
	// narrow window, worked out from the room there is rather than from a
	// window size somebody measured.
	drop bool
}

var matrixColumns = []cell{
	{look.ColTrusts, words.ColTrusts, false},
	{look.ColRuntime, words.ColRuntime, false},
	{0, words.ColInstance, false},
	{look.ColAnchors, words.ColAnchors, false},
	{look.ColChosen, words.ColChosen, true},
	{look.ColToggle, "", false},
}

// columnsLayout lays one line of the matrix from matrixColumns. The head and
// every row are laid by it, so a column is the same width all the way down.
type columnsLayout struct{}

func (columnsLayout) widths(total float32) []float32 {
	ws := make([]float32, len(matrixColumns))
	grow, used := -1, float32(look.InsetCell*(len(matrixColumns)-1))
	for i, c := range matrixColumns {
		ws[i] = c.width
		used += c.width
		if c.width == 0 {
			grow = i
		}
	}
	left := total - used
	if left < look.ColInstanceMin {
		for i, c := range matrixColumns {
			if c.drop {
				left += ws[i] + look.InsetCell
				ws[i] = -1
			}
		}
	}
	ws[grow] = max(left, 0)
	return ws
}

func (l columnsLayout) MinSize(objects []fyne.CanvasObject) fyne.Size {
	var w, h float32 = look.ColInstanceMin, 0
	for i, c := range matrixColumns {
		if !c.drop {
			w += c.width
		}
		if i > 0 && !c.drop {
			w += look.InsetCell
		}
		h = max(h, objects[i].MinSize().Height)
	}
	return fyne.NewSize(w, h)
}

func (l columnsLayout) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	var x float32
	for i, w := range l.widths(size.Width) {
		o := objects[i]
		if w < 0 {
			o.Hide()
			continue
		}
		o.Show()
		o.Move(fyne.NewPos(x, 0))
		o.Resize(fyne.NewSize(w, size.Height))
		x += w + look.InsetCell
	}
}

func matrixLine(cells []fyne.CanvasObject) fyne.CanvasObject {
	return PadXY(look.InsetCell, 0, fyne.NewContainerWithLayout(columnsLayout{}, cells...))
}

// MatrixHead is the line naming the columns.
func MatrixHead() fyne.CanvasObject {
	cells := make([]fyne.CanvasObject, len(matrixColumns))
	for i, c := range matrixColumns {
		if c.head == "" {
			cells[i] = Gap(0)
			continue
		}
		if c.width == look.ColAnchors {
			cells[i] = Number(CaptionStrong, words.T(c.head))
			continue
		}
		cells[i] = Text(CaptionStrong, words.T(c.head))
	}
	return Inset(0, 0, 0, look.GapInline, matrixLine(cells))
}

// TrustTone is how a store's answer looks: the shape of the status it
// stands closest to, and a word that says which answer it is.
func TrustTone(t model.Trust) (look.Tone, words.Key) {
	switch t {
	case model.TrustYes:
		return look.TonePass, words.TrustsYes
	case model.TrustNo:
		return look.ToneFail, words.TrustsNo
	}
	return look.ToneUnknown, words.TrustsNot
}

// MatrixRow is one store. open shows its command under it, and state is
// how the pointer or the keyboard lights it.
func MatrixRow(s model.Store, open bool, state State) fyne.CanvasObject {
	tone, word := TrustTone(s.Trust)
	over := look.Surface
	if state == Hover || state == Focused || open {
		over = look.Raised
	}
	chosen := strings.Join(s.ChosenBy, ", ")
	line := matrixLine([]fyne.CanvasObject{
		Own(Pill(tone, words.T(word), over)),
		Middle(Clip(Strong, s.Runtime)),
		Middle(Clip(MonoMuted, s.Instance)),
		Middle(Number(Body, strconv.Itoa(s.Anchors))),
		Middle(Clip(BodyMuted, chosen)),
		toggle(s.Command != "", open),
	})
	rows := []fyne.CanvasObject{Inset(0, look.InsetRow, 0, look.InsetRow, line)}
	if open && s.Command != "" {
		rows = append(rows, Inset(look.InsetCell+look.ColTrusts+look.InsetCell, 0, look.InsetCell, look.InsetRow,
			Command(s.Command, s.NeedsAdmin, s.Elevation, s.Caveat, nil)))
	}
	face := canvas.NewRectangle(look.Colour(over))
	face.CornerRadius = look.RadiusControl
	objects := []fyne.CanvasObject{face}
	if state == Focused {
		ring := canvas.NewRectangle(look.Colour(look.Raised))
		ring.CornerRadius = look.RadiusControl
		ring.StrokeColor = look.Colour(look.Focus)
		ring.StrokeWidth = look.StrokeFocus
		objects = []fyne.CanvasObject{ring}
	}
	objects = append(objects, Stack(0, rows...))
	return Layers(objects...)
}

// toggle is the sign at the end of a row that opens to show a command: a
// triangle pointing at the row's content when closed, down when open. A row
// with nothing to open has none.
func toggle(has, open bool) fyne.CanvasObject {
	if !has {
		return Gap(0)
	}
	icon := theme.MenuExpandIcon()
	if open {
		icon = theme.MenuDropDownIcon()
	}
	img := canvas.NewImageFromResource(theme.NewColoredResource(icon, fyne.ThemeColorName(look.InkMuted)))
	img.FillMode = canvas.ImageFillContain
	img.SetMinSize(fyne.NewSquareSize(look.IconControl))
	return Middle(img)
}

// Matrix is the head and the rows, with a hairline between rows.
func Matrix(stores []model.Store, open int) fyne.CanvasObject {
	rows := []fyne.CanvasObject{MatrixHead(), Rule()}
	for i, s := range stores {
		if i > 0 {
			rows = append(rows, Rule())
		}
		rows = append(rows, MatrixRow(s, i == open, Rest))
	}
	return Stack(0, rows...)
}
