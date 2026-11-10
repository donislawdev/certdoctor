package request

import (
	"slices"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/switches"
	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// TestEveryFormatSaveReportOffersIsOneTheCommandLineWrites - a copy is written
// by the command line, so a format it does not declare would be refused in
// front of the person, and the terminal page is for a terminal, not a file.
func TestEveryFormatSaveReportOffersIsOneTheCommandLineWrites(t *testing.T) {
	endings := map[string]bool{}
	for _, f := range SaveFormats {
		if !slices.Contains(switches.Formats, f.Value) || f.Value == "terminal" {
			t.Errorf("Save report offers %q, which --format does not write to a file (%v)", f.Value, switches.Formats)
		}
		if !strings.HasPrefix(f.Ending, ".") || len(f.Ending) < 2 || endings[f.Ending] {
			t.Errorf("%q ends its files in %q - an ending of its own, with its dot", f.Value, f.Ending)
		}
		endings[f.Ending] = true
		for _, k := range []words.Key{f.Name, f.Note} {
			if strings.HasPrefix(words.T(k), "<") {
				t.Errorf("%q is shown with %q, which has no words", f.Value, k)
			}
		}
	}
	if len(SaveFormats) != 3 || SaveFormats[0].Value != "html" {
		t.Errorf("Save report offers %v - the page first, then Markdown and JSON", SaveFormats)
	}
}

// TestASaveIsTheCommandLineReadingTheReportBack - the switches are the ones
// the command line declares, and every value stays with its switch, so a path
// beginning with a dash is still where the copy goes.
func TestASaveIsTheCommandLineReadingTheReportBack(t *testing.T) {
	got := SaveArgs(SaveFormats[1], "-report.md")
	want := []string{"--from=-", "--format=md", "--out=-report.md"}
	if !slices.Equal(got, want) {
		t.Fatalf("a copy in Markdown to -report.md is asked as %q, want %q", got, want)
	}
	for _, arg := range got {
		name, _, _ := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
		if _, declared := switches.Named(name); !declared {
			t.Errorf("%q names a switch the command line does not declare", arg)
		}
	}
}
