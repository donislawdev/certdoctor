package spec

import (
	"sort"

	"github.com/donislawdev/certdoctor/internal/core/status"
)

// Outcome is what a tool gives back: the same four parts from every tool, so
// the terminal and the window draw all of them with one piece of code each
// (ADR141 point 5).
type Outcome struct {
	// Notes say what the tool did to its input before reading it - a prefix
	// taken off, quotes removed - so nothing is changed without saying so.
	Notes []string
	// Checks are the tool's judgements, each with one of the four statuses.
	Checks []Check
	// Data is what the tool found, typed by the tool, for a script to read. It
	// goes into the document as it marshals.
	Data any
	// View is what a person is shown, as blocks of the closed list below.
	View []Block
}

// Check is one judgement.
type Check struct {
	// ID names the check within its tool. Public: a script reads it.
	ID string
	// Status is one of the four (inviolable rule 20).
	Status status.Status
	// Summary is the sentence a person reads.
	Summary string
}

// BlockKind is a kind of block. The list is closed, because every surface
// draws every kind: a new one is a decision and a drawing in each.
type BlockKind string

// The kinds of block.
const (
	// Fields is a table of labels and values.
	Fields BlockKind = "fields"
	// Code is text shown exactly, in a monospaced face, to be read or copied.
	Code BlockKind = "code"
	// Text is a paragraph.
	Text BlockKind = "text"
)

// BlockKinds is every kind of block.
var BlockKinds = []BlockKind{Fields, Code, Text}

// Block is one part of what a person is shown.
type Block struct {
	Kind  BlockKind
	Title string
	// Fields are the rows of a Fields block.
	Fields []Field
	// Language says what a Code block holds - "json" or "text".
	Language string
	// Body is the text of a Code or a Text block.
	Body string
}

// Field is one row of a Fields block.
type Field struct {
	Label string
	Value string
	// Note is said beside the value, for example how long ago a time was.
	Note string
	// Status marks the row when it carries a judgement, and is empty when it
	// carries a fact.
	Status status.Status
}

// Refusal is a tool saying its input is not something it can read. The
// command line ends with exit code 3, as for any input it cannot use (ADR141
// point 6).
//
// The reason never quotes the input - it says where, by part and position -
// because the input may be a credential and a message is copied into tickets.
type Refusal struct {
	Reason string
}

func (r *Refusal) Error() string { return r.Reason }

// SortChecks puts the worst status first (the order of status.All) and,
// within a status, keeps the order a tool lists its check ids in - one rule
// for every tool, so two tools never list their findings two ways. A check
// whose id is not in order goes last within its status.
func SortChecks(checks []Check, order []string) []Check {
	rank := func(c Check) (int, int) {
		severity := len(status.All)
		for i, s := range status.All {
			if s == c.Status {
				severity = i
			}
		}
		for i, id := range order {
			if id == c.ID {
				return severity, i
			}
		}
		return severity, len(order)
	}
	sort.SliceStable(checks, func(a, b int) bool {
		sa, oa := rank(checks[a])
		sb, ob := rank(checks[b])
		return sa < sb || sa == sb && oa < ob
	})
	return checks
}
