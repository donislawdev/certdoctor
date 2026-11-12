// Package spec is the contract of the tools (ADR141): which tools there are,
// what each takes, and the shape of what each gives back. It holds no tool.
//
// IT IS THE ONE PACKAGE OF THE TOOLS THE WINDOW MAY IMPORT. The window draws
// its list of tools and its forms from here and reads the document a tool
// writes through here, and it runs the tool itself as a child process - so
// the code that reads somebody else's bytes never runs inside the window, and
// a token that crashes a parser ends a child, not the window (ADR121).
//
// A tool is one entry in All and one package beside this one. The command line
// joins the two in cmd/certdoctor, and the window names each tool in its own
// catalogue of words. Each side holds a test naming every tool here, so a tool
// cannot reach one side and be missed by the other - the shape
// internal/core/switches has for the switches.
//
// THE IDENTIFIERS ARE PUBLIC. A tool's id is a word in somebody's script and an
// input's name is a key in somebody's request document, so neither is renamed
// or reused - a tool that goes away is marked as gone, never given to another.
package spec

import "strings"

// Category is a group the tools are listed under. The list is closed: a new
// category is a decision, because the window lays its list out by them.
type Category string

// The categories, in the order the lists show them.
const (
	Tokens Category = "tokens"
)

// Categories is every category, in the order the lists show them.
var Categories = []Category{Tokens}

// Shape is what an input is made of, which decides how it is read.
type Shape string

// The shapes an input can have.
const (
	// Line is text on one line: read from a terminal by one paste and Enter,
	// and from a file or a pipe as the whole of it.
	Line Shape = "line"
)

// Input is one thing a tool takes.
type Input struct {
	// Name is the input's key in a request document and, for every input after
	// the first, the switch --<name>-file. Public.
	Name string
	// Shape is what the input is made of.
	Shape Shape
	// MaxBytes is the most of it that is read. More is refused before anything
	// parses it.
	MaxBytes int
	// There is no field saying an input is a secret yet: the first tool taking
	// a password or a key brings it, with how the window hides it (ADR141 point
	// 10). No input of any tool comes back in a message - that holds for all.
}

// Tool is one tool.
type Tool struct {
	// ID is the word after "certdoctor tool". Public.
	ID string
	// Category is the group it is listed under.
	Category Category
	// Title names it in a list.
	Title string
	// Summary is the sentence --help and the lists print beside it.
	Summary string
	// Keywords are the other words people search for it by.
	Keywords []string
	// Inputs are what it takes, the first one read from standard input or
	// --file.
	Inputs []Input
}

// All is every tool, in the order the lists show them within a category.
var All = []Tool{
	{
		ID:       "jwt",
		Category: Tokens,
		Title:    "JWT decoder",
		Summary: "Shows what a JSON Web Token says - its header, its claims and its times - " +
			"without checking its signature.",
		Keywords: []string{"token", "bearer", "jws", "jwe", "oauth", "oidc", "id_token", "access_token", "claims"},
		Inputs:   []Input{{Name: "token", Shape: Line, MaxBytes: 256 << 10}},
	},
}

// Find is the tool with id, and whether there is one.
func Find(id string) (Tool, bool) {
	for _, t := range All {
		if t.ID == id {
			return t, true
		}
	}
	return Tool{}, false
}

// Match says whether somebody searching for query is looking for t: every
// word of the query stands in its id, title, summary or keywords, or in also
// - the words another surface calls it by - ignoring case. An empty query
// matches every tool.
func (t Tool) Match(query string, also ...string) bool {
	words := append(append([]string{t.ID, t.Title, t.Summary}, t.Keywords...), also...)
	hay := strings.ToLower(strings.Join(words, " "))
	for _, word := range strings.Fields(strings.ToLower(query)) {
		if !strings.Contains(hay, word) {
			return false
		}
	}
	return true
}

// Input is the input of t called name, and whether t has one.
func (t Tool) Input(name string) (Input, bool) {
	for _, in := range t.Inputs {
		if in.Name == name {
			return in, true
		}
	}
	return Input{}, false
}
