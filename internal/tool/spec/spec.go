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
	Certificates Category = "certificates"
	Proxy        Category = "proxy"
	Tokens       Category = "tokens"
)

// Categories is every category, in the order the lists show them -
// certificates first, because they are what the program is about, then the
// proxy, which stands on the way to every server it asks about.
var Categories = []Category{Certificates, Proxy, Tokens}

// Shape is what an input is made of, which decides how it is read.
type Shape string

// The shapes an input can have.
const (
	// Line is text on one line: read from a terminal by one paste and Enter,
	// and from a file or a pipe as the whole of it.
	Line Shape = "line"
	// Bytes is the whole of a file or a pipe, text or not - a certificate
	// arrives as PEM text or as DER bytes (ADR146). It is not held to being
	// text at the door: the tool reading it says what it is. A terminal is
	// not asked for it, because a paste of many lines has no Enter that ends
	// it - it is piped in or named with --file.
	Bytes Shape = "bytes"
)

// Shapes is every shape an input can have. The list is closed: a new shape
// is how the command line and the window read an input, so it is a decision
// with a reading in each (ADR141 point 2).
var Shapes = []Shape{Line, Bytes}

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
	// File is the name of a file --help shows it read from, saying what kind
	// of file it is: token.txt, chain.pem.
	File string
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
		ID:       "cert",
		Category: Certificates,
		Title:    "Certificate decoder",
		Summary: "Shows what a certificate or a chain says - names, dates, key, fingerprints - and whether " +
			"the chain is complete and in order, without connecting anywhere.",
		Keywords: []string{"certificate", "x509", "pem", "der", "crt", "cer", "chain", "fingerprint", "thumbprint",
			"expiry", "san", "x5c"},
		Inputs: []Input{{Name: "certificates", Shape: Bytes, MaxBytes: 256 << 10, File: "chain.pem"}},
	},
	{
		ID:       "noproxy",
		Category: Proxy,
		Title:    "NO_PROXY tester",
		Summary: "Shows which programs send an address through the proxy and which go to it directly under a " +
			"NO_PROXY list - curl, .NET, Go, Python, requests and pip, Node.js - since each reads the list its own way.",
		Keywords: []string{"no_proxy", "proxy", "bypass", "exception", "exclusion", "curl", "git", "dotnet",
			"golang", "python", "pip", "requests", "node", "fetch", "undici", "java", "environment", "variable"},
		// 64 KiB holds any list kept by hand many times over - an ASSESSMENT,
		// not a source. The address is read for its scheme, host and port only,
		// and a URL copied from a browser can be long past them.
		Inputs: []Input{
			{Name: "list", Shape: Line, MaxBytes: 64 << 10, File: "no_proxy.txt"},
			{Name: "address", Shape: Line, MaxBytes: 64 << 10, File: "address.txt"},
		},
	},
	{
		ID:       "jwt",
		Category: Tokens,
		Title:    "JWT decoder",
		Summary: "Shows what a JSON Web Token says - its header, its claims and its times - " +
			"without checking its signature.",
		Keywords: []string{"token", "bearer", "jws", "jwe", "oauth", "oidc", "id_token", "access_token", "claims"},
		Inputs:   []Input{{Name: "token", Shape: Line, MaxBytes: 256 << 10, File: "token.txt"}},
	},
}

// FileSwitch is the switch, without its dashes, that names a file for the
// input at index i: file for the first, <name>-file for every other (ADR141
// point 2). Public - the command line takes it, and the window names it when
// it sends a person there for an input longer than it takes (ADR144).
func (t Tool) FileSwitch(i int) string {
	if i == 0 {
		return "file"
	}
	return t.Inputs[i].Name + "-file"
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
