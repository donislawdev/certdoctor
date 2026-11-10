package request

import "github.com/donislawdev/certdoctor/internal/gui/words"

// Format is one way Save report writes a copy of the report: by the command
// line, from the report the window drew, read back with --from (ADR121 (c)).
// The window never renders a page itself.
type Format struct {
	// Value is what --format is given - one of the values the command line
	// declares for it.
	Value string
	// Ending is how the file's name ends, with its dot.
	Ending string
	// Name and Note are how the menu shows it.
	Name, Note words.Key
}

// SaveFormats is what Save report offers, in the order of its menu: the page
// first, because a report is saved most often to be read or attached, and the
// document last, for another tool. One list, read by the menu and by the
// dialog alike, so the two cannot come to disagree about what the third
// choice is.
var SaveFormats = []Format{
	{Value: "html", Ending: ".html", Name: words.SaveHTML, Note: words.SaveHTMLNote},
	{Value: "md", Ending: ".md", Name: words.SaveMD, Note: words.SaveMDNote},
	{Value: "json", Ending: ".json", Name: words.SaveJSON, Note: words.SaveJSONNote},
}

// SaveArgs is the command line that writes the report it reads on standard
// input to path, as f: --from - reads it, --format writes it in f, and --out
// puts it at path, replacing whatever is there - which the window asks about
// first. Every value goes with its switch after "=", so a path that begins
// with a dash is still the value of --out.
func SaveArgs(f Format, path string) []string {
	return []string{"--from=-", "--format=" + f.Value, "--out=" + path}
}
