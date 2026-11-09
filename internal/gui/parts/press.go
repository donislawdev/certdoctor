package parts

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/widget"
)

// Pressable is a part pressed as a whole - a layer in the rail, a store in
// the matrix, the head of a fold - and what it opens under its head, if
// anything.
//
// The head, and the face behind the whole part, are drawn anew from the
// part's State whenever the pointer or the keyboard changes it, by the
// drawing the part was made with. What it opens is kept as it is - the
// options with what was typed in them, a command with its Copy - so it does
// not lose that the moment the pointer moves (GUI rule 3).
type Pressable struct {
	widget.BaseWidget
	touch
	// OnTapped is called after a press, once what the part opens has been
	// opened or put away.
	OnTapped func()

	draw func(s State, open bool) (face, head fyne.CanvasObject)
	body fyne.CanvasObject
	open bool
	// headHeight is how tall the head was laid out: a press below it lands
	// on what the part opened, which is not a press on the part.
	headHeight float32
}

// NewPressable makes a part drawn by draw, opening body under its head when
// pressed. body may be nil: a part with nothing under it is open while it is
// the chosen one - a layer in the rail, whose page stands beside the rail.
func NewPressable(draw func(s State, open bool) (face, head fyne.CanvasObject), body fyne.CanvasObject, open bool) *Pressable {
	p := &Pressable{draw: draw, body: body, open: open}
	p.self = p
	p.ExtendBaseWidget(p)
	return p
}

// Pin shows the part in one state for good. For the catalogue only.
func (p *Pressable) Pin(s State) *Pressable {
	p.pin(s)
	return p
}

// Open says whether what the part opens is open - or, for a part with
// nothing under it, whether it is the chosen one.
func (p *Pressable) Open() bool { return p.open }

// SetOpen opens or puts away what the part opens.
func (p *Pressable) SetOpen(open bool) {
	if open == p.open {
		return
	}
	p.open = open
	p.Refresh()
}

// Tapped presses the part: a part with something under its head opens it
// or puts it away. A press on what is open under the head is not a press on
// the part - a command is read there, not closed.
func (p *Pressable) Tapped(e *fyne.PointEvent) {
	if p.disabled || (e != nil && e.Position.Y >= p.headHeight) {
		return
	}
	if p.body != nil {
		p.SetOpen(!p.open)
	}
	if p.OnTapped != nil {
		p.OnTapped()
	}
}

func (p *Pressable) TypedKey(k *fyne.KeyEvent) {
	if presses(k) {
		p.Tapped(nil)
	}
}

func (p *Pressable) CreateRenderer() fyne.WidgetRenderer {
	r := &pressRenderer{p: p}
	r.draw()
	return r
}

type pressRenderer struct {
	p          *Pressable
	face, head fyne.CanvasObject
}

func (r *pressRenderer) draw() {
	r.face, r.head = r.p.draw(r.p.state(), r.p.open)
	if r.p.body != nil {
		if r.p.open {
			r.p.body.Show()
		} else {
			r.p.body.Hide()
		}
	}
}

// MinSize is the head over what is open under it. The face stands behind
// them and asks for nothing.
func (r *pressRenderer) MinSize() fyne.Size {
	size := r.head.MinSize()
	if b := r.p.body; b != nil && b.Visible() {
		m := b.MinSize()
		size = fyne.NewSize(max(size.Width, m.Width), size.Height+m.Height)
	}
	return size
}

func (r *pressRenderer) Layout(size fyne.Size) {
	if r.face != nil {
		r.face.Move(fyne.NewPos(0, 0))
		r.face.Resize(size)
	}
	r.p.headHeight = fit(r.head, 0, size.Width)
	if b := r.p.body; b != nil && b.Visible() {
		fit(b, r.p.headHeight, size.Width)
	}
}

// fit lays o across width at y, at the height it asks for - asked twice,
// because a sentence that wraps knows its height only once it knows its
// width - and says how tall it came out.
func fit(o fyne.CanvasObject, y, width float32) float32 {
	o.Resize(fyne.NewSize(width, o.MinSize().Height))
	h := o.MinSize().Height
	o.Move(fyne.NewPos(0, y))
	o.Resize(fyne.NewSize(width, h))
	return h
}

func (r *pressRenderer) Refresh() {
	r.draw()
	r.Layout(r.p.Size())
	canvas.Refresh(r.p)
}

func (r *pressRenderer) Objects() []fyne.CanvasObject {
	objects := make([]fyne.CanvasObject, 0, 3)
	if r.face != nil {
		objects = append(objects, r.face)
	}
	objects = append(objects, r.head)
	if r.p.body != nil {
		objects = append(objects, r.p.body)
	}
	return objects
}

func (r *pressRenderer) Destroy() {}
