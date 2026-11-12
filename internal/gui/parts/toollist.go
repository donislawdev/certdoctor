package parts

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/widget"

	"github.com/donislawdev/certdoctor/internal/gui/look"
)

// ToolEntry is one tool in the list, in the words the window calls it.
type ToolEntry struct {
	ID, Title, Summary string
}

// ToolGroup is the tools of one category, under its heading.
type ToolGroup struct {
	Title string
	Tools []ToolEntry
}

// ToolList is the list of tools down the side of Tools: a box to search it,
// then the tools by category, one of them the tool the page beside shows.
//
// IT IS BUILT FOR DOZENS (ADR141 point 11): the search narrows the list as it
// is typed, a heading goes with the last of its tools, and a search that
// leaves nothing says so instead of leaving an empty column. What matches is
// not decided here - the screen hands Filter a rule it can test without a
// window (GUI rule 15).
type ToolList struct {
	widget.BaseWidget
	// OnChosen is told the tool chosen, each time it is another one.
	OnChosen func(id string)
	// Search is the box the list is searched with.
	Search *widget.Entry

	ids     []string
	entries []*Pressable
	// group is the index in heads of the heading each entry stands under.
	group   []int
	heads   []fyne.CanvasObject
	nothing fyne.CanvasObject
	chosen  int
	list    fyne.CanvasObject
}

// NewToolList is the list titled title, searched with a box showing hint,
// saying nothing when a search leaves no tool, with the tool chosen chosen.
func NewToolList(title, hint, nothing string, groups []ToolGroup, chosen string) *ToolList {
	l := &ToolList{Search: widget.NewEntry(), chosen: -1}
	l.Search.SetPlaceHolder(hint)
	var items []fyne.CanvasObject
	if title != "" {
		items = append(items, Inset(look.InsetCell, 0, 0, look.GapInline, Text(CaptionStrong, title)))
	}
	// The box held off both edges by the room its focus ring takes, so the
	// scroll the list stands in does not cut the ring, or its right edge, off.
	items = append(items, Inset(look.FocusGap, look.FocusGap, look.FocusGap, look.GapInline, l.Search))
	for g, group := range groups {
		head := Inset(look.InsetCell, look.GapRow, 0, 0, Text(CaptionMuted, group.Title))
		l.heads = append(l.heads, head)
		items = append(items, head)
		for _, tool := range group.Tools {
			items = append(items, l.add(tool, tool.ID == chosen, g))
		}
	}
	l.nothing = Inset(look.InsetCell, look.GapRow, 0, 0, Para(CaptionMuted, nothing))
	l.nothing.Hide()
	l.list = Stack(look.GapTight, append(items, l.nothing)...)
	l.ExtendBaseWidget(l)
	return l
}

// add is one tool of the list, as a part to press.
func (l *ToolList) add(tool ToolEntry, chosen bool, group int) *Pressable {
	i := len(l.entries)
	entry := NewPressable(func(s State, open bool) (fyne.CanvasObject, fyne.CanvasObject) {
		return nil, ToolItem(tool.Title, tool.Summary, open, s)
	}, nil, chosen)
	entry.OnTapped = func() { l.Choose(tool.ID) }
	if chosen {
		l.chosen = i
	}
	l.ids = append(l.ids, tool.ID)
	l.entries = append(l.entries, entry)
	l.group = append(l.group, group)
	return entry
}

// Choose makes the tool id the chosen one. The one already chosen, or one the
// list does not have, changes nothing.
func (l *ToolList) Choose(id string) {
	for i, have := range l.ids {
		if have == id && choose(l.entries, &l.chosen, i) && l.OnChosen != nil {
			l.OnChosen(id)
		}
	}
}

// Chosen is the tool chosen now, empty when none is.
func (l *ToolList) Chosen() string {
	if l.chosen < 0 {
		return ""
	}
	return l.ids[l.chosen]
}

// Filter shows the tools shown says to show and hides the rest, with the
// headings left without a tool, and says so when none is left. The chosen
// tool stays chosen while hidden: the page beside does not change under the
// person typing a search.
func (l *ToolList) Filter(shown func(id string) bool) {
	left := make([]bool, len(l.heads))
	any := false
	for i, entry := range l.entries {
		visible := shown(l.ids[i])
		setShown(entry, visible)
		left[l.group[i]] = left[l.group[i]] || visible
		any = any || visible
	}
	for g, head := range l.heads {
		setShown(head, left[g])
	}
	setShown(l.nothing, !any)
	l.Refresh()
}

// Showing says whether the tool id is on the list as it is filtered now.
func (l *ToolList) Showing(id string) bool {
	for i, have := range l.ids {
		if have == id {
			return l.entries[i].Visible()
		}
	}
	return false
}

func setShown(o fyne.CanvasObject, shown bool) {
	if shown {
		o.Show()
		return
	}
	o.Hide()
}

func (l *ToolList) CreateRenderer() fyne.WidgetRenderer { return widget.NewSimpleRenderer(l.list) }
