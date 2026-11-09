package flow

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// Kind is what stood in the way of a report.
type Kind int

// The kinds the window tells apart. Each has its own sentences, and the ones
// a person acts on differently are different kinds: a program that is not
// there is put back, one of another version is unpacked again, a refusal of
// the options is answered by changing them.
const (
	// Missing: nothing beside the window under the command line's name.
	Missing Kind = iota + 1
	// NotStarted: something is there and the system did not start it.
	NotStarted
	// Overran: the run was still going Grace after its limit and the window
	// stopped it.
	Overran
	// Refused: the command line refused what it was asked - USAGE or CONFIG.
	Refused
	// Crashed: it ended with no report for any other reason.
	Crashed
	// TooLong: what it wrote is longer than MaxDocument.
	TooLong
	// NotAReport: what it wrote is not a document the window can read.
	NotAReport
	// NoHead: the document does not say which version or schema it is.
	NoHead
	// OtherVersion: the document is from another version of certdoctor.
	OtherVersion
	// OtherSchema: the document is in another schema than the window reads.
	OtherSchema
	// OtherExit: the document's exit code is not the one the program ended
	// with, so it is not that run's.
	OtherExit
	// NoLayers: the document has no layer to show.
	NoLayers
)

// Trouble is what stood in the way of a report, with the facts its sentences
// name.
type Trouble struct {
	Kind Kind
	// Program is the path that was run (Missing, NotStarted).
	Program string
	// Said is the system's or the reader's own words (NotStarted, NotAReport).
	Said string
	// Code is the exit code the program ended with, and Reported the one the
	// document gave (OtherExit).
	Code, Reported int
	// Theirs and Ours are the version or schema of the document and of the
	// window (OtherVersion, OtherSchema).
	Theirs, Ours string
	// Limit is the run's time limit in seconds (Overran).
	Limit float64
	// Printed is what the window shows of what the command line printed.
	Printed string
}

// Sentences is a trouble as the window says it.
type Sentences struct {
	Title, What, Todo, Printed string
}

// Sentences says t in the catalogue's words.
func (t Trouble) Sentences() Sentences {
	s := Sentences{Printed: t.Printed}
	unreadable := func(what string) {
		s.Title, s.What, s.Todo = words.T(words.UnreadableTitle), what, words.T(words.UnreadableTodo)
	}
	switch t.Kind {
	case Missing:
		s.Title, s.What, s.Todo = words.T(words.MissingTitle), fmt.Sprintf(words.T(words.MissingWhat), t.Program),
			words.T(words.MissingTodo)
	case NotStarted:
		s.Title, s.What, s.Todo = words.T(words.NotStartedTitle),
			fmt.Sprintf(words.T(words.NotStartedWhat), t.Program, withoutFullStop(t.Said)), words.T(words.NotStartedTodo)
	case Overran:
		s.Title, s.What, s.Todo = words.T(words.OverranTitle),
			fmt.Sprintf(words.T(words.OverranWhat), seconds(Grace.Seconds()), seconds(t.Limit)), words.T(words.OverranTodo)
	case Refused:
		s.Title, s.Todo = words.T(words.RefusedTitle), words.T(words.RefusedTodo)
	case Crashed:
		s.Title, s.What, s.Todo = words.T(words.CrashedTitle), crashed(t.Code), words.T(words.CrashedTodo)
	case TooLong:
		unreadable(fmt.Sprintf(words.T(words.UnreadableLong), MaxDocument>>20))
	case NotAReport:
		unreadable(fmt.Sprintf(words.T(words.UnreadableNotReport), withoutFullStop(t.Said)))
	case NoHead:
		unreadable(words.T(words.UnreadableNoHead))
	case OtherVersion:
		s.Title, s.What, s.Todo = words.T(words.VersionTitle), fmt.Sprintf(words.T(words.VersionWhat), t.Ours, t.Theirs),
			words.T(words.VersionTodo)
	case OtherSchema:
		s.Title, s.What, s.Todo = words.T(words.VersionTitle), fmt.Sprintf(words.T(words.SchemaWhat), t.Ours, t.Theirs),
			words.T(words.VersionTodo)
	case OtherExit:
		unreadable(fmt.Sprintf(words.T(words.UnreadableExit), t.Reported, t.Code))
	case NoLayers:
		unreadable(words.T(words.UnreadableEmpty))
	}
	return s
}

// crashed is what happened to a run that ended with code and no report: the
// code and its name from the frozen table when it is one of them, and the
// sentence without a code when it is not - a negative one is a process the
// system ended, which gave no code at all.
func crashed(code int) string {
	if c := exitcode.Code(code); code >= 0 && c.Valid() {
		return fmt.Sprintf(words.T(words.CrashedWhatCode), code, c.Name())
	}
	return words.T(words.CrashedWhat)
}

// Progress is the time a running run has taken, as the running screen shows
// it: the words, the share of the limit gone, and whether there is a limit to
// draw a share of.
type Progress struct {
	Text    string
	Share   float32
	Bounded bool
}

// Progress is how far the running run is at now: whole seconds, against the
// limit when there is one. A share and never a promise of what is left - the
// command line says nothing until it is done (ADR121 point 5).
//
// The share moves in whole seconds too, so the screen asked every frame
// changes once a second - drawn by the software renderer, a bar moved sixty
// times a second is a core kept busy for nothing anybody can read.
func (f *Flow) Progress(now time.Time) Progress {
	whole := float64(int(max(f.Elapsed(now), 0)))
	gone := strconv.Itoa(int(whole))
	limit := f.Limit()
	if limit == 0 {
		return Progress{Text: fmt.Sprintf(words.T(words.RunningNoLimit), gone)}
	}
	share := float32(min(whole/limit, 1))
	return Progress{Text: fmt.Sprintf(words.T(words.RunningElapsed), gone, seconds(limit)), Share: share, Bounded: true}
}

// seconds is a number of seconds as a person writes it: no trailing zeros, no
// exponent.
func seconds(s float64) string { return strconv.FormatFloat(s, 'f', -1, 64) }

// withoutFullStop is words without the full stop they may end with, for a
// sentence that supplies its own - Windows ends its own words with one.
func withoutFullStop(s string) string { return strings.TrimRight(strings.TrimSpace(s), ".") }
