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

// A component is one section of THIRD-PARTY-NOTICES.md: the standard library,
// or one module.
type component struct {
	path       string   // the module path, empty for the standard library
	version    string   // the version every build links
	licences   []string // SPDX identifiers, every one of which applies
	copyrights []string // the copyright lines of the texts the section quotes
}

// The notices, as far as a bill of materials needs them.
type notices struct {
	std       component
	modules   map[string]component
	extracted []extractedLicence // in the order the notices first name them
}

// An extractedLicence is a text the SPDX License List has no identifier for,
// with the words SPDX asks a document to carry for it.
type extractedLicence struct {
	id, name, text string
}

// A section is the raw shape of one "##" heading of the notices: its first
// paragraph, joined into one line, and every quoted text beneath it.
type section struct {
	heading string
	opening string
	blocks  [][]string
}

// openingLine is how every section starts: the version in backticks, then the
// licence expression, each ended by a full stop. The expression is one or more
// identifiers joined by AND, which is all SPDX grammar this project needs - a
// text quoted in the notices always applies, so nothing here is a choice
// between licences.
var openingLine = regexp.MustCompile("^Version `([^`]+)`\\. ([A-Za-z0-9.-]+(?: AND [A-Za-z0-9.-]+)*)\\.(?: |$)")

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
		c, err := readComponent(s)
		if err != nil {
			return notices{}, err
		}
		for _, id := range c.licences {
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
		switch {
		case c.path == "" && haveStd:
			return notices{}, fmt.Errorf("the section %q appears twice", stdHeading)
		case c.path == "":
			n.std, haveStd = c, true
		case n.modules[c.path].path != "":
			return notices{}, fmt.Errorf("the section %q appears twice", c.path)
		default:
			n.modules[c.path] = c
		}
	}
	if !haveStd {
		return notices{}, fmt.Errorf("there is no section %q, and every build links the standard library", stdHeading)
	}
	for _, u := range unlisted {
		if !extracted[u.id] {
			return notices{}, fmt.Errorf("%s is in the list of unlisted texts and no section names it - remove it from licences.go", u.id)
		}
	}
	return n, nil
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
func readComponent(s section) (component, error) {
	m := openingLine.FindStringSubmatch(s.opening)
	if m == nil {
		return component{}, fmt.Errorf("the section %q does not open with \"Version `<version>`. <SPDX expression>.\"", s.heading)
	}
	c := component{path: s.heading, version: m[1], licences: strings.Split(m[2], " AND ")}
	if s.heading == stdHeading {
		c.path = ""
	}
	seen := map[string]bool{}
	for _, id := range c.licences {
		if seen[id] {
			return component{}, fmt.Errorf("the section %q names %s twice", s.heading, id)
		}
		seen[id] = true
		if !listedLicences[id] && unlistedNamed(id) == nil {
			return component{}, fmt.Errorf("the section %q names %s, which is not an identifier read on the SPDX License List - "+
				"read the list, then add it to licences.go", s.heading, id)
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
	return c, nil
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
