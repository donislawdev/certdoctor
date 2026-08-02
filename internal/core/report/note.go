package report

import (
	"github.com/donislawdev/certdoctor/internal/core/layer"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// NoteKind says what sort of shortfall a note records.
//
// The list is closed, and that is the point rather than tidiness. Notes are the
// one place a run admits it did less than it promised. With an open list a
// consumer has nothing to filter on, so notes read as commentary and stop being
// read at all - which turns the ban on silence back into prose.
type NoteKind string

const (
	// NoteNotImplemented - a capability that does not exist yet. Every one of
	// these disappears when the thing it names is built.
	NoteNotImplemented NoteKind = "not_implemented"
	// NoteUndetermined - a field we could not establish. The value in the
	// report is then empty rather than guessed.
	NoteUndetermined NoteKind = "undetermined"
	// NoteReduced - a value shown in a narrower form than we hold. Today the
	// target is reduced to its origin, because the masking function that would
	// let us print more of it does not exist yet.
	NoteReduced NoteKind = "reduced"
	// NoteNoEffect - an option was accepted and changes nothing today. An
	// option that quietly does nothing leaves the user waiting for an effect
	// that is not coming.
	NoteNoEffect NoteKind = "no_effect"
	// NoteSkipped - work that was planned and not done, typically because the
	// run ran out of its budget.
	NoteSkipped NoteKind = "skipped"
	// NoteDegraded - a lesser answer rather than no answer.
	NoteDegraded NoteKind = "degraded"
)

// noteKindMeanings is the registry. Keeping the text here rather than at the
// call site is what stops the same kind from being worded three ways.
var noteKindMeanings = map[NoteKind]string{
	NoteNotImplemented: "this part of certdoctor is not built yet",
	NoteUndetermined:   "certdoctor could not establish this and did not guess",
	NoteReduced:        "the value is shown in a narrower form than certdoctor holds",
	NoteNoEffect:       "the option was accepted and changes nothing today",
	NoteSkipped:        "planned work that was not done",
	NoteDegraded:       "a lesser answer rather than no answer",
}

// AllNoteKinds lists every kind exactly once, in declaration order.
var AllNoteKinds = []NoteKind{
	NoteNotImplemented,
	NoteUndetermined,
	NoteReduced,
	NoteNoEffect,
	NoteSkipped,
	NoteDegraded,
}

// Valid reports whether k is one of the declared kinds.
func (k NoteKind) Valid() bool {
	_, ok := noteKindMeanings[k]
	return ok
}

// Meaning returns the user-facing English text for k, or the empty string for a
// kind outside the registry.
func (k NoteKind) Meaning() string { return noteKindMeanings[k] }

// String makes NoteKind printable without a conversion at every call site.
func (k NoteKind) String() string { return string(k) }

// Note is one admission that the run did less than it promised.
type Note struct {
	Kind NoteKind
	// Layer names the layer this is about, or is empty when the note is about
	// the run as a whole.
	Layer layer.ID
	// Field names the report field this is about, in the form a reader of the
	// machine-readable output would recognise. Empty when the note is not
	// about one field.
	Field string
	// Reason carries the closed-vocabulary reason where one applies, so a
	// pipeline can branch without reading Detail.
	Reason status.Reason
	// Detail is one line of English and is always present. A note without it
	// tells the reader that something is missing and not what.
	Detail string
}
