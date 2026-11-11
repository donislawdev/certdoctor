package main

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// stdHeading is the section of THIRD-PARTY-NOTICES.md for the Go runtime and
// standard library, which is no module and so has no path to be headed by. The
// notices guard in internal/guard spells it the same way.
const stdHeading = "Go standard library and runtime"

// A component is one section of the notices: the standard library, one module,
// or one work that is not a module.
type component struct {
	path       string       // the module path or the work's heading, empty for the standard library
	version    string       // the version every build links
	licences   []string     // the terms of its licence expression, every one of which applies, each once
	copyrights []string     // the copyright lines of the texts the section quotes
	files      []listedFile // for a work beside a binary, the files the section lists
}

// The notices, as far as a bill of materials needs them.
type notices struct {
	std       component
	modules   map[string]component
	works     map[string]component // by heading, nil when there is none
	extracted []extractedLicence   // in the order the notices first name them
}

// A listedFile is one file a work beside a binary consists of, as its section
// lists it - the format the notices guard holds to the pin the release fetches
// the files by (listedFile in internal/guard/renderer_test.go).
type listedFile struct {
	path, size, sha256 string
}

var listedFileLine = regexp.MustCompile("^- `([^`]+)`, ([0-9]+) bytes, SHA-256 `([0-9a-f]{64})`$")

// An extractedLicence is a text the SPDX License List has no identifier for,
// with the words SPDX asks a document to carry for it.
type extractedLicence struct {
	id, name, text string
}

// A section is the raw shape of one "##" heading of the notices: its first
// paragraph, joined into one line, the items of a list outside its quoted
// texts, and every quoted text beneath it.
type section struct {
	heading string
	opening string
	items   []string
	blocks  [][]string
}

// openingLine is how every section starts: the version in backticks, then the
// licence expression, each ended by a full stop. The expression is identifiers
// joined by AND and OR, with WITH and an exception after a licence and brackets
// where they group - parseExpression reads it, and this only finds where it
// ends.
var openingLine = regexp.MustCompile("^Version `([^`]+)`\\. " +
	"(\\(*[A-Za-z0-9.-]+\\)*(?: (?:AND|OR|WITH) \\(*[A-Za-z0-9.-]+\\)*)*)\\.(?: |$)")

// copyrightLine is a line of a quoted text that states a copyright, and
// copyrightHolds is what makes it a statement rather than a template: a year,
// or the sign in one of its two spellings. Apache 2.0 ends with
// "Copyright [yyyy] [name of copyright owner]", which is an instruction to the
// reader and names nobody.
var (
	copyrightLine  = regexp.MustCompile(`^(?:(?:Portions|Revisions)\s+)?Copyright\s`)
	copyrightHolds = regexp.MustCompile(`(?i)\d{4}|\(c\)|\x{00A9}`)
)

// parseNotices reads what the document needs out of THIRD-PARTY-NOTICES.md.
//
// It refuses rather than guesses. The notices are compiled into every binary
// and printed by --license, so a section this cannot read is a section a person
// reads differently from the document published beside it.
func parseNotices(text string) (notices, error) {
	sections, err := splitSections(text)
	if err != nil {
		return notices{}, err
	}
	n := notices{modules: map[string]component{}}
	haveStd := false
	extracted := map[string]bool{}
	for _, s := range sections {
		c, named, err := readComponent(s)
		if err != nil {
			return notices{}, err
		}
		for _, id := range named {
			if !strings.HasPrefix(id, refPrefix) || extracted[id] {
				continue
			}
			e, err := extract(id, s)
			if err != nil {
				return notices{}, err
			}
			n.extracted = append(n.extracted, e)
			extracted[id] = true
		}
		w, isWork := works[c.path]
		switch {
		case c.path == "" && haveStd:
			return notices{}, fmt.Errorf("the section %q appears twice", stdHeading)
		case c.path == "":
			n.std, haveStd = c, true
		case n.modules[c.path].path != "" || n.works[c.path].path != "":
			return notices{}, fmt.Errorf("the section %q appears twice", c.path)
		case isWork:
			if err := w.check(c); err != nil {
				return notices{}, err
			}
			if n.works == nil {
				n.works = map[string]component{}
			}
			n.works[c.path] = c
		default:
			n.modules[c.path] = c
		}
	}
	if !haveStd {
		return notices{}, fmt.Errorf("there is no section %q, and every build links the standard library", stdHeading)
	}
	return n, nil
}

// check refuses a section that does not say what this work is: files that
// travel beside a binary are listed, each with its size and sum, and a work
// compiled in has no files of its own to list.
func (w work) check(c component) error {
	switch {
	case w.beside != "" && w.in != "":
		return fmt.Errorf("programs.go says the work %q is both compiled into %s and beside %s", c.path, w.in, w.beside)
	case w.beside != "" && len(c.files) == 0:
		return fmt.Errorf("the section %q is of files beside a binary, and lists none as \"- `<path>`, <n> bytes, SHA-256 `<sum>`\"", c.path)
	case w.beside == "" && len(c.files) > 0:
		return fmt.Errorf("the section %q lists files, and it is a work compiled into a binary rather than beside one", c.path)
	}
	return nil
}

// splitSections cuts the notices at their "##" headings. Deeper headings stay
// inside the section above them, and a heading inside a quoted text is text.
func splitSections(text string) ([]section, error) {
	var (
		out       []section
		block     []string
		fenced    bool
		gathering bool // still inside the first paragraph of the latest section
	)
	for n, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "```"):
			if fenced {
				if len(out) == 0 {
					return nil, fmt.Errorf("the quoted text closed on line %d comes before any section, so it belongs to nothing", n+1)
				}
				out[len(out)-1].blocks = append(out[len(out)-1].blocks, block)
				block = nil
			}
			fenced, gathering = !fenced, false
		case fenced:
			block = append(block, line)
		case strings.HasPrefix(line, "## "):
			out = append(out, section{heading: strings.TrimSpace(line[3:])})
			gathering = true
		case strings.HasPrefix(line, "- ") && len(out) > 0:
			last := &out[len(out)-1]
			last.items = append(last.items, strings.TrimSpace(line))
			gathering = gathering && last.opening == ""
		case !gathering:
		case strings.TrimSpace(line) == "":
			gathering = out[len(out)-1].opening == ""
		case strings.HasPrefix(line, "#"):
			gathering = false
		default:
			last := &out[len(out)-1]
			last.opening = strings.TrimSpace(last.opening + " " + strings.TrimSpace(line))
		}
	}
	if fenced {
		return nil, errors.New("a quoted text is opened and never closed")
	}
	return out, nil
}

// readComponent reads one section's opening line and copyright lines.
//
// It answers with every licence the expression names as well, for the texts
// an unlisted one stands for to be found.
func readComponent(s section) (component, []string, error) {
	m := openingLine.FindStringSubmatch(s.opening)
	if m == nil {
		return component{}, nil, fmt.Errorf("the section %q does not open with \"Version `<version>`. <SPDX expression>.\"", s.heading)
	}
	expr, err := parseExpression(m[2])
	if err != nil {
		return component{}, nil, fmt.Errorf("the section %q opens with the licence expression %q, and %v", s.heading, m[2], err)
	}
	c := component{path: s.heading, version: m[1], licences: expr.terms()}
	if s.heading == stdHeading {
		c.path = ""
	}
	named := expr.licences()
	for _, id := range named {
		if !listedLicences[id] && unlistedNamed(id) == nil {
			return component{}, nil, fmt.Errorf("the section %q names %s, which is not an identifier read on the SPDX License List - "+
				"read the list, then add it to licences.go", s.heading, id)
		}
	}
	for _, id := range expr.exceptions() {
		if !listedExceptions[id] {
			return component{}, nil, fmt.Errorf("the section %q names the exception %s, which is not an identifier read on "+
				"the SPDX list of exceptions - read the list, then add it to licences.go", s.heading, id)
		}
	}
	for _, item := range s.items {
		if f := listedFileLine.FindStringSubmatch(item); f != nil {
			c.files = append(c.files, listedFile{path: f[1], size: f[2], sha256: f[3]})
		}
	}
	for _, block := range s.blocks {
		for _, line := range block {
			line = strings.TrimSpace(line)
			if copyrightLine.MatchString(line) && copyrightHolds.MatchString(line) && !contains(c.copyrights, line) {
				c.copyrights = append(c.copyrights, line)
			}
		}
	}
	return c, named, nil
}

// extract finds the quoted text an unlisted identifier stands for: the one
// block of its section that opens with the line licences.go gives for it.
func extract(id string, s section) (extractedLicence, error) {
	u := unlistedNamed(id)
	var found []string
	for _, block := range s.blocks {
		if first := firstLine(block); first == u.opens {
			found = append(found, withoutBlankEnds(block))
		}
	}
	if len(found) != 1 {
		return extractedLicence{}, fmt.Errorf("the section %q names %s, and %d of its quoted texts open with %q where one should",
			s.heading, id, len(found), u.opens)
	}
	return extractedLicence{id: id, name: u.name, text: found[0]}, nil
}

// firstLine is the first line of a quoted text that is not blank.
func firstLine(block []string) string {
	for _, line := range block {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// withoutBlankEnds is a quoted text as one string, without the blank lines a
// fence may leave before and after it. Indentation inside stays, because in a
// licence it is part of the text.
func withoutBlankEnds(block []string) string {
	start, end := 0, len(block)
	for start < end && strings.TrimSpace(block[start]) == "" {
		start++
	}
	for end > start && strings.TrimSpace(block[end-1]) == "" {
		end--
	}
	return strings.Join(block[start:end], "\n")
}

func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}
