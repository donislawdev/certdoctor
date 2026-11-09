package parts

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/donislawdev/certdoctor/internal/gui/look"
)

// Kind is how loud a button is. One screen has one Primary at most: the
// thing the screen is for.
type Kind int

const (
	Primary Kind = iota
	Secondary
	Quiet
)

// State is what the pointer and the keyboard are doing to a control. The
// catalogue pins one, to show every state side by side.
type State int

const (
	Rest State = iota
	Hover
	Press
	Focused
	Disabled
)

// Button is a real control - it takes the pointer, the keyboard and the
// focus - drawn from the palette rather than by the toolkit's button, whose
// look is the toolkit author's decision.
type Button struct {
	widget.BaseWidget
	touch
	Kind     Kind
	Label    string
	Icon     fyne.Resource
	OnTapped func()

	// fits is everything the button will say, when its words change: it is
	// as wide as the widest from the start, so nothing beside it moves.
	fits []string
}

// NewButton makes a button.
func NewButton(k Kind, label string, icon fyne.Resource, tapped func()) *Button {
	b := &Button{Kind: k, Label: label, Icon: icon, OnTapped: tapped}
	b.self = b
	b.ExtendBaseWidget(b)
	return b
}

// Pin shows the button in one state for good. For the catalogue only.
func (b *Button) Pin(s State) *Button {
	b.pin(s)
	return b
}

func (b *Button) Tapped(*fyne.PointEvent) {
	if b.disabled || b.OnTapped == nil {
		return
	}
	b.OnTapped()
}

func (b *Button) TypedKey(k *fyne.KeyEvent) {
	if presses(k) {
		b.Tapped(nil)
	}
}

func (b *Button) CreateRenderer() fyne.WidgetRenderer {
	r := &buttonRenderer{b: b}
	r.face = canvas.NewRectangle(color.Transparent)
	r.face.CornerRadius = look.RadiusControl
	r.ring = canvas.NewRectangle(color.Transparent)
	r.ring.CornerRadius = look.RadiusControl + look.FocusGap
	r.ring.StrokeWidth = look.StrokeFocus
	r.label = canvas.NewText(b.Label, color.Transparent)
	r.label.TextSize = look.TextBody
	r.label.TextStyle = fyne.TextStyle{Bold: b.Kind == Primary}
	r.icon = canvas.NewImageFromResource(nil)
	r.icon.FillMode = canvas.ImageFillContain
	r.Refresh()
	return r
}

type buttonRenderer struct {
	b     *Button
	face  *canvas.Rectangle
	ring  *canvas.Rectangle
	label *canvas.Text
	icon  *canvas.Image
}

// paint is the face, the edge and the ink of a button of a kind in a state.
func paint(k Kind, s State) (face, edge, ink look.Role) {
	switch k {
	case Primary:
		switch s {
		case Hover:
			return look.AccentHovered, "", look.OnAccent
		case Press:
			return look.AccentPressed, "", look.OnAccent
		case Disabled:
			return look.Raised, "", look.InkDisabled
		}
		return look.Accent, "", look.OnAccent
	case Secondary:
		switch s {
		case Hover:
			return look.Hovered, look.EdgeControl, look.Ink
		case Press:
			return look.Surface, look.EdgeControl, look.Ink
		case Disabled:
			return look.Surface, look.EdgeCard, look.InkDisabled
		}
		return look.Raised, look.EdgeControl, look.Ink
	}
	switch s {
	case Hover:
		return look.Raised, "", look.Ink
	case Press:
		return look.Hovered, "", look.Ink
	case Disabled:
		return "", "", look.InkDisabled
	}
	return "", "", look.InkMuted
}

func (r *buttonRenderer) Refresh() {
	s := r.b.state()
	face, edge, ink := paint(r.b.Kind, s)
	r.face.FillColor = color.Transparent
	if face != "" {
		r.face.FillColor = look.Colour(face)
	}
	r.face.StrokeColor = color.Transparent
	r.face.StrokeWidth = 0
	if edge != "" {
		r.face.StrokeColor = look.Colour(edge)
		r.face.StrokeWidth = look.Hairline
	}
	r.ring.StrokeColor = color.Transparent
	if s == Focused {
		r.ring.StrokeColor = look.Colour(look.Focus)
	}
	r.label.Text = r.b.Label
	r.label.Color = look.Colour(ink)
	if r.b.Icon != nil {
		r.icon.Resource = theme.NewColoredResource(r.b.Icon, fyne.ThemeColorName(ink))
		r.icon.Show()
	} else {
		r.icon.Hide()
	}
	r.face.Refresh()
	r.ring.Refresh()
	r.label.Refresh()
	r.icon.Refresh()
	r.Layout(r.b.Size())
}

func (r *buttonRenderer) MinSize() fyne.Size {
	words := r.label.MinSize().Width
	for _, f := range r.b.fits {
		words = max(words, fyne.MeasureText(f, r.label.TextSize, r.label.TextStyle).Width)
	}
	w := words + 2*look.InsetControl
	if r.b.Icon != nil {
		w += look.IconControl + look.GapInline
	}
	return fyne.NewSize(w, look.ControlHeight)
}

func (r *buttonRenderer) Layout(size fyne.Size) {
	r.face.Move(fyne.NewPos(0, 0))
	r.face.Resize(size)
	out := float32(look.FocusGap) + float32(look.StrokeFocus)/2
	r.ring.Move(fyne.NewPos(-out, -out))
	r.ring.Resize(fyne.NewSize(size.Width+2*out, size.Height+2*out))
	content := r.label.MinSize().Width
	if r.b.Icon != nil {
		content += look.IconControl + look.GapInline
	}
	x := (size.Width - content) / 2
	if r.b.Icon != nil {
		r.icon.Move(fyne.NewPos(x, (size.Height-look.IconControl)/2))
		r.icon.Resize(fyne.NewSquareSize(look.IconControl))
		x += look.IconControl + look.GapInline
	}
	r.label.Move(fyne.NewPos(x, (size.Height-r.label.MinSize().Height)/2))
	r.label.Resize(r.label.MinSize())
}

func (r *buttonRenderer) Objects() []fyne.CanvasObject {
	return []fyne.CanvasObject{r.ring, r.face, r.icon, r.label}
}

func (r *buttonRenderer) Destroy() {}
