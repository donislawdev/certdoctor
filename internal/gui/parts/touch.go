package parts

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/driver/desktop"
)

// touch is what the pointer and the keyboard are doing to a part that takes
// them - a button, a layer in the rail, a store in the matrix, the head of a
// fold. Kept once for all of them, so every one lights the same way and is
// pressed by the same keys (GUI rule 5). The part it is in is redrawn on
// every change.
type touch struct {
	self fyne.Widget

	hovered, pressed, focused, disabled bool
	pinned                              *State
}

// state is the one state the part is drawn in. Disabled wins over all, then
// what the pointer does, and the keyboard's focus last, because a part under
// the pointer is the one a person is looking at.
func (t *touch) state() State {
	switch {
	case t.pinned != nil:
		return *t.pinned
	case t.disabled:
		return Disabled
	case t.pressed:
		return Press
	case t.hovered:
		return Hover
	case t.focused:
		return Focused
	}
	return Rest
}

// pin shows the part in one state for good. For the catalogue only.
func (t *touch) pin(s State) {
	t.pinned = &s
	if s == Disabled {
		t.disabled = true
	}
	t.self.Refresh()
}

func (t *touch) set(flag *bool, on bool) {
	*flag = on
	t.self.Refresh()
}

func (t *touch) MouseIn(*desktop.MouseEvent)    { t.set(&t.hovered, true) }
func (t *touch) MouseMoved(*desktop.MouseEvent) {}
func (t *touch) MouseOut()                      { t.set(&t.hovered, false) }
func (t *touch) MouseDown(*desktop.MouseEvent)  { t.set(&t.pressed, true) }
func (t *touch) MouseUp(*desktop.MouseEvent)    { t.set(&t.pressed, false) }
func (t *touch) FocusGained()                   { t.set(&t.focused, true) }
func (t *touch) FocusLost()                     { t.set(&t.focused, false) }
func (t *touch) TypedRune(rune)                 {}
func (t *touch) Disable()                       { t.set(&t.disabled, true) }
func (t *touch) Enable()                        { t.set(&t.disabled, false) }
func (t *touch) Disabled() bool                 { return t.disabled }

// Cursor is the hand over a part that does something when pressed, and the
// plain pointer over one that does not.
func (t *touch) Cursor() desktop.Cursor {
	if t.disabled {
		return desktop.DefaultCursor
	}
	return desktop.PointerCursor
}

// presses says whether a key presses the part it is typed into: Space, Return
// and Enter. Never Tab, which moves the keyboard on.
func presses(k *fyne.KeyEvent) bool {
	return k.Name == fyne.KeySpace || k.Name == fyne.KeyReturn || k.Name == fyne.KeyEnter
}
