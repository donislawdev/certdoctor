package parts

import (
	"testing"

	"fyne.io/fyne/v2"

	"github.com/donislawdev/certdoctor/internal/gui/look"
	"github.com/donislawdev/certdoctor/internal/gui/model"
)

// TestAFieldRowCarriesItsStatusOnlyWhenItHasOne - a row of fields is a label
// in its column, the value, and a badge only for a row that judges: a fact
// drawn with a status would read as a verdict.
func TestAFieldRowCarriesItsStatusOnlyWhenItHasOne(t *testing.T) {
	newApp(t)
	table := Fields([]FieldRow{
		{Label: "Expires", Value: "2026-11-12", Note: "3 hours ago", Status: model.Fail},
		{Label: "Type", Value: "JWT"},
	}).(*fyne.Container)
	judged, fact := table.Objects[0].(*fyne.Container), table.Objects[1].(*fyne.Container)
	if len(judged.Objects) != 3 || len(fact.Objects) != 2 {
		t.Errorf("a judged row has %d parts and a fact %d, want 3 and 2", len(judged.Objects), len(fact.Objects))
	}
	if w := judged.Objects[0].MinSize().Width; w != look.LabelWidth {
		t.Errorf("the label column is %v wide, want look.LabelWidth", w)
	}
	if len(judged.Objects[1].(*fyne.Container).Objects) != 2 || len(fact.Objects[1].(*fyne.Container).Objects) != 1 {
		t.Error("the note is not under the value of the row that has one, or stands under a row with none")
	}
}

// TestAToolListSaysWhatItDoesNotHave - asked about a tool it does not list,
// the list says it is not shown, and choosing it changes nothing.
func TestAToolListSaysWhatItDoesNotHave(t *testing.T) {
	newApp(t)
	l := NewToolList("", "Search", "Nothing", []ToolGroup{{Title: "Tokens", Tools: []ToolEntry{{ID: "jwt"}}}}, "")
	if l.Chosen() != "" || l.Showing("pem") || !l.Showing("jwt") {
		t.Errorf("chosen %q, showing pem %v, showing jwt %v", l.Chosen(), l.Showing("pem"), l.Showing("jwt"))
	}
	l.Choose("jwt")
	l.Choose("jwt")
	if l.Chosen() != "jwt" {
		t.Errorf("chosen %q", l.Chosen())
	}
}
