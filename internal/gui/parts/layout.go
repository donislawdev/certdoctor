// Package parts is every piece the window is built from. A screen puts parts
// together and sets no colour, distance, size or word of its own: those come
// from look and words.
package parts

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
)

// The toolkit's stock boxes put ONE distance, the theme's padding, between
// everything they hold. A design has several, so these layouts take the
// distance as an argument and the argument is always a role from look.

// stack lays its children top to bottom, each the full width, gap apart.
type stack struct{ gap float32 }

// Stack lays objects top to bottom, gap apart.
func Stack(gap float32, objects ...fyne.CanvasObject) *fyne.Container {
	return fyne.NewContainerWithLayout(stack{gap: gap}, objects...)
}

func (s stack) MinSize(objects []fyne.CanvasObject) fyne.Size {
	var w, h float32
	n := 0
	for _, o := range objects {
		if !o.Visible() {
			continue
		}
		m := o.MinSize()
		w = max(w, m.Width)
		h += m.Height
		n++
	}
	if n > 1 {
		h += s.gap * float32(n-1)
	}
	return fyne.NewSize(w, h)
}

func (s stack) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	var y float32
	for _, o := range objects {
		if !o.Visible() {
			continue
		}
		// Twice: a sentence that wraps knows its height only once it knows
		// its width.
		o.Resize(fyne.NewSize(size.Width, o.MinSize().Height))
		h := o.MinSize().Height
		o.Move(fyne.NewPos(0, y))
		o.Resize(fyne.NewSize(size.Width, h))
		y += h + s.gap
	}
}

// row lays its children left to right at their own width, gap apart and
// centred on one line. The child at grow, if any, takes the width left over.
type row struct {
	gap  float32
	grow int
	top  bool
}

// Row lays objects left to right, gap apart, each at its own width.
func Row(gap float32, objects ...fyne.CanvasObject) *fyne.Container {
	return fyne.NewContainerWithLayout(row{gap: gap, grow: -1}, objects...)
}

// RowGrow is Row with the object at index grow taking the width left over -
// a name that pushes what follows it to the far edge.
func RowGrow(gap float32, grow int, objects ...fyne.CanvasObject) *fyne.Container {
	return fyne.NewContainerWithLayout(row{gap: gap, grow: grow}, objects...)
}

// RowTop is RowGrow with every child standing at the top of the line rather
// than centred on it - for a line whose growing part wraps.
func RowTop(gap float32, grow int, objects ...fyne.CanvasObject) *fyne.Container {
	return fyne.NewContainerWithLayout(row{gap: gap, grow: grow, top: true}, objects...)
}

func (r row) MinSize(objects []fyne.CanvasObject) fyne.Size {
	var w, h float32
	n := 0
	for _, o := range objects {
		if !o.Visible() {
			continue
		}
		m := o.MinSize()
		w += m.Width
		h = max(h, m.Height)
		n++
	}
	if n > 1 {
		w += r.gap * float32(n-1)
	}
	return fyne.NewSize(w, h)
}

func (r row) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	extra := size.Width - r.MinSize(objects).Width
	if extra < 0 {
		extra = 0
	}
	var x float32
	for i, o := range objects {
		if !o.Visible() {
			continue
		}
		w := o.MinSize().Width
		if i == r.grow {
			w += extra
		}
		o.Resize(fyne.NewSize(w, o.MinSize().Height))
		h := o.MinSize().Height
		y := (size.Height - h) / 2
		if r.top {
			y = 0
		}
		if isTall(o) {
			h, y = size.Height, 0
		}
		o.Move(fyne.NewPos(x, y))
		o.Resize(fyne.NewSize(w, h))
		x += w + r.gap
	}
}

// tall marks a child of a row that takes the row's whole height rather than
// its own - a bar down the edge of a card, which has no height of its own.
type tall struct{ layers }

// Tall makes an object as tall as the row it stands in.
func Tall(o fyne.CanvasObject) *fyne.Container {
	return fyne.NewContainerWithLayout(tall{}, o)
}

func isTall(o fyne.CanvasObject) bool {
	c, ok := o.(*fyne.Container)
	if !ok {
		return false
	}
	_, ok = c.Layout.(tall)
	return ok
}

// Own keeps an object at its own width at the leading edge of the room it
// is given, centred up and down - a pill in a table cell wider than it.
func Own(o fyne.CanvasObject) *fyne.Container {
	return fyne.NewContainerWithLayout(own{}, o)
}

type own struct{}

func (own) MinSize(objects []fyne.CanvasObject) fyne.Size {
	var m fyne.Size
	for _, o := range objects {
		m = m.Max(o.MinSize())
	}
	return m
}

func (own) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	for _, o := range objects {
		m := o.MinSize()
		h := min(m.Height, size.Height)
		o.Move(fyne.NewPos(0, (size.Height-h)/2))
		o.Resize(fyne.NewSize(min(m.Width, size.Width), h))
	}
}

// inset keeps room round its children, which all fill what is left.
type inset struct{ left, top, right, bottom float32 }

// Inset keeps the given room round an object.
func Inset(left, top, right, bottom float32, o fyne.CanvasObject) *fyne.Container {
	return fyne.NewContainerWithLayout(inset{left, top, right, bottom}, o)
}

// Pad keeps the same room on every side, PadXY one room across and another
// up and down.
func Pad(all float32, o fyne.CanvasObject) *fyne.Container { return Inset(all, all, all, all, o) }

func PadXY(x, y float32, o fyne.CanvasObject) *fyne.Container { return Inset(x, y, x, y, o) }

func (p inset) MinSize(objects []fyne.CanvasObject) fyne.Size {
	var m fyne.Size
	for _, o := range objects {
		if o.Visible() {
			m = m.Max(o.MinSize())
		}
	}
	return fyne.NewSize(m.Width+p.left+p.right, m.Height+p.top+p.bottom)
}

func (p inset) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	for _, o := range objects {
		o.Move(fyne.NewPos(p.left, p.top))
		o.Resize(fyne.NewSize(size.Width-p.left-p.right, size.Height-p.top-p.bottom))
	}
}

// column centres one object across, at most limit wide. fill makes it as tall
// as the room rather than as tall as what it holds.
type column struct {
	limit float32
	fill  bool
}

// Column centres an object across and stops it growing past limit.
func Column(limit float32, o fyne.CanvasObject) *fyne.Container {
	return fyne.NewContainerWithLayout(column{limit: limit}, o)
}

// ColumnFill is Column taking all the height it is given - for a part of a
// screen that scrolls inside the window instead of with it.
func ColumnFill(limit float32, o fyne.CanvasObject) *fyne.Container {
	return fyne.NewContainerWithLayout(column{limit: limit, fill: true}, o)
}

func (c column) MinSize(objects []fyne.CanvasObject) fyne.Size {
	var m fyne.Size
	for _, o := range objects {
		m = m.Max(o.MinSize())
	}
	return m
}

func (c column) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	for _, o := range objects {
		w := min(size.Width, c.limit)
		w = max(w, o.MinSize().Width)
		// At its own height: a card in a column is as tall as what it
		// holds, never as tall as the window - unless the column fills.
		o.Resize(fyne.NewSize(w, o.MinSize().Height))
		h := o.MinSize().Height
		if c.fill {
			h = size.Height
		}
		o.Move(fyne.NewPos((size.Width-w)/2, 0))
		o.Resize(fyne.NewSize(w, h))
	}
}

// limit stops its object growing past a width, at the leading edge.
type limit struct{ width float32 }

// Limit stops an object growing past a width - a paragraph past the width
// that still reads easily - and keeps it at the leading edge.
func Limit(w float32, o fyne.CanvasObject) *fyne.Container {
	return fyne.NewContainerWithLayout(limit{width: w}, o)
}

func (l limit) MinSize(objects []fyne.CanvasObject) fyne.Size {
	var m fyne.Size
	for _, o := range objects {
		m = m.Max(o.MinSize())
	}
	return m
}

func (l limit) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	for _, o := range objects {
		w := max(min(size.Width, l.width), o.MinSize().Width)
		o.Move(fyne.NewPos(0, 0))
		o.Resize(fyne.NewSize(w, size.Height))
	}
}

// fixed gives its object exactly a width, a height, or both - zero leaves
// that side to the object.
type fixed struct{ width, height float32 }

// Width holds an object at exactly this width.
func Width(w float32, o fyne.CanvasObject) *fyne.Container {
	return fyne.NewContainerWithLayout(fixed{width: w}, o)
}

// Height holds an object at exactly this height, centred up and down.
func Height(h float32, o fyne.CanvasObject) *fyne.Container {
	return fyne.NewContainerWithLayout(fixed{height: h}, o)
}

// Box holds an object at exactly this width and height.
func Box(w, h float32, o fyne.CanvasObject) *fyne.Container {
	return fyne.NewContainerWithLayout(fixed{width: w, height: h}, o)
}

func (f fixed) MinSize(objects []fyne.CanvasObject) fyne.Size {
	var m fyne.Size
	for _, o := range objects {
		m = m.Max(o.MinSize())
	}
	if f.width > 0 {
		m.Width = f.width
	}
	if f.height > 0 {
		m.Height = f.height
	}
	return m
}

func (f fixed) Layout(objects []fyne.CanvasObject, size fyne.Size) { fill(objects, size) }

// fill gives every object all of the room.
func fill(objects []fyne.CanvasObject, size fyne.Size) {
	for _, o := range objects {
		o.Move(fyne.NewPos(0, 0))
		o.Resize(size)
	}
}

// floor asks for at least a width and a height, and gives its object all of
// the room it gets.
type floor struct{ width, height float32 }

// AtLeast asks for at least this width and height, and more when its object
// asks for more - the size a window may not be made smaller than, because the
// toolkit keeps a window no smaller than what it holds (GUI rule 21).
func AtLeast(w, h float32, o fyne.CanvasObject) *fyne.Container {
	return fyne.NewContainerWithLayout(floor{width: w, height: h}, o)
}

func (f floor) MinSize(objects []fyne.CanvasObject) fyne.Size {
	m := fyne.NewSize(f.width, f.height)
	for _, o := range objects {
		m = m.Max(o.MinSize())
	}
	return m
}

func (f floor) Layout(objects []fyne.CanvasObject, size fyne.Size) { fill(objects, size) }

// middle stands its object in the middle of the height it is given, at the
// object's own height - for a short line inside a taller band.
type middle struct{}

// Middle centres an object up and down at its own height.
func Middle(o fyne.CanvasObject) *fyne.Container {
	return fyne.NewContainerWithLayout(middle{}, o)
}

func (middle) MinSize(objects []fyne.CanvasObject) fyne.Size {
	var m fyne.Size
	for _, o := range objects {
		m = m.Max(o.MinSize())
	}
	return m
}

func (middle) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	for _, o := range objects {
		h := min(o.MinSize().Height, size.Height)
		o.Move(fyne.NewPos(0, (size.Height-h)/2))
		o.Resize(fyne.NewSize(size.Width, h))
	}
}

// layers puts every child over the same area, first at the bottom - a fill
// under a content.
type layers struct{}

// Layers puts objects over one another, the first at the bottom.
func Layers(objects ...fyne.CanvasObject) *fyne.Container {
	return fyne.NewContainerWithLayout(layers{}, objects...)
}

func (layers) MinSize(objects []fyne.CanvasObject) fyne.Size {
	var m fyne.Size
	for _, o := range objects {
		if o.Visible() {
			m = m.Max(o.MinSize())
		}
	}
	return m
}

func (layers) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	for _, o := range objects {
		o.Move(fyne.NewPos(0, 0))
		o.Resize(size)
	}
}

// Gap is empty room of a width, between groups on one line.
func Gap(w float32) fyne.CanvasObject {
	r := canvas.NewRectangle(color.Transparent)
	r.SetMinSize(fyne.NewSize(w, 0))
	return r
}
