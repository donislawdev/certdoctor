package parts

import (
	"testing"

	"fyne.io/fyne/v2/test"

	"github.com/donislawdev/certdoctor/internal/gui/look"
)

func TestTabsChooseOnePlaceAndResetSaysNothing(t *testing.T) {
	test.NewTempApp(t).Settings().SetTheme(look.Theme())
	tabs := NewTabs([]string{"Diagnose", "Tools"}, 0)
	var told []int
	tabs.OnChosen = func(i int) { told = append(told, i) }
	tabs.Choose(1)
	tabs.Choose(1)
	tabs.Choose(7)
	if tabs.Chosen() != 1 || len(told) != 1 || told[0] != 1 {
		t.Errorf("chosen %d, told %v - want 1, told once", tabs.Chosen(), told)
	}
	if tabs.entries[0].Open() || !tabs.entries[1].Open() {
		t.Error("the place chosen is not the one drawn chosen")
	}
	tabs.Reset(0)
	if tabs.Chosen() != 0 || len(told) != 1 || !tabs.entries[0].Open() {
		t.Errorf("Reset told OnChosen (%v) or did not choose (%d)", told, tabs.Chosen())
	}
	tabs.entries[1].Tapped(nil)
	if tabs.Chosen() != 1 || len(told) != 2 {
		t.Error("a press on a tab does not choose it")
	}
}

func TestTheToolListHidesWhatASearchLeavesOut(t *testing.T) {
	test.NewTempApp(t).Settings().SetTheme(look.Theme())
	l := NewToolList("", "Search", "Nothing", []ToolGroup{
		{Title: "Tokens", Tools: []ToolEntry{{ID: "jwt", Title: "JWT"}, {ID: "saml", Title: "SAML"}}},
		{Title: "Certificates", Tools: []ToolEntry{{ID: "pem", Title: "PEM"}}},
	}, "saml")
	if l.Chosen() != "saml" {
		t.Fatalf("chosen %q", l.Chosen())
	}
	l.Filter(func(id string) bool { return id == "pem" })
	if l.entries[0].Visible() || l.entries[1].Visible() || l.heads[0].Visible() || !l.heads[1].Visible() ||
		l.nothing.Visible() {
		t.Error("a search for one certificate tool left a token tool, its heading, or the empty line shown")
	}
	if l.Chosen() != "saml" {
		t.Error("a search changed the tool chosen")
	}
	l.Filter(func(string) bool { return false })
	if !l.nothing.Visible() || l.heads[1].Visible() {
		t.Error("a search that leaves nothing does not say so")
	}
	var told string
	l.OnChosen = func(id string) { told = id }
	l.entries[2].Tapped(nil)
	if l.Chosen() != "pem" || told != "pem" {
		t.Errorf("a press chose %q, told %q", l.Chosen(), told)
	}
	l.Choose("no-such-tool")
	if l.Chosen() != "pem" {
		t.Error("choosing a tool the list does not have changed the choice")
	}
}
