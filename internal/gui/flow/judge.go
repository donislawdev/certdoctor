package flow

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	"github.com/donislawdev/certdoctor/internal/gui/model"
	"github.com/donislawdev/certdoctor/internal/gui/words"
)

// Outcome is what came of a run: a report to draw and the layer it opens on,
// or the trouble that stood in the way.
type Outcome struct {
	Report model.Report
	// Open is the layer the report opens on, as an index into Report.Layers.
	Open    int
	Trouble *Trouble
}

// maxPrintedLines is how much of what the command line printed the window
// shows. Its refusal is one line, and a stack says what broke in its first
// ones.
const maxPrintedLines = 20

// judge is what came of p, for a window of version given limit seconds.
//
// The order is the order of what can be known. Whether anything ran comes
// first, then whether the window stopped it, then whether it wrote anything -
// the command line writes standard output once, at the end, or not at all
// (cmd/certdoctor/cli.go, execute), so nothing written is no report and the
// exit code says why. Only then is what it wrote read: its head before the
// rest, so a document of another version or schema is named as one rather
// than failing as a document this window cannot read.
//
// The document is not validated here: the command line validates it before it
// writes it and writes nothing it could not (ADR121 point 1, the owner's
// decision of 2026-11-09). What is asked is what the window has to trust to
// draw it - its version, its schema, an exit code that is the program's own,
// and layers to show.
func judge(p Process, version string, limit float64) Outcome {
	printed := excerpt(p.Printed, p.PrintedTooLong)
	trouble := func(t Trouble) Outcome {
		t.Printed = printed
		return Outcome{Trouble: &t}
	}
	switch {
	case p.Missing:
		return trouble(Trouble{Kind: Missing, Program: p.Program})
	case p.StartFailed != nil:
		return trouble(Trouble{Kind: NotStarted, Program: p.Program, Said: p.StartFailed.Error()})
	case errors.Is(p.Stopped, context.DeadlineExceeded):
		return trouble(Trouble{Kind: Overran, Limit: limit})
	case len(p.Out) == 0:
		return trouble(Trouble{Kind: withoutReport(p.Code), Code: p.Code})
	case p.OutTooLong:
		return trouble(Trouble{Kind: TooLong})
	}
	head, err := model.ReadHead(p.Out)
	switch {
	case err != nil:
		return trouble(Trouble{Kind: NotAReport, Said: err.Error()})
	case head.Version == "" || head.Schema == "":
		return trouble(Trouble{Kind: NoHead})
	case head.Version != version:
		return trouble(Trouble{Kind: OtherVersion, Theirs: head.Version, Ours: version})
	case head.Schema != model.SchemaVersion:
		return trouble(Trouble{Kind: OtherSchema, Theirs: head.Schema, Ours: model.SchemaVersion})
	}
	r, err := model.Decode(p.Out)
	switch {
	case err != nil:
		return trouble(Trouble{Kind: NotAReport, Said: err.Error()})
	case r.Verdict.ExitCode != p.Code:
		return trouble(Trouble{Kind: OtherExit, Reported: r.Verdict.ExitCode, Code: p.Code})
	case len(r.Layers) == 0:
		return trouble(Trouble{Kind: NoLayers})
	}
	return Outcome{Report: r, Open: opening(r)}
}

// withoutReport is the kind of a run that ended without writing a report: the
// command line refused what it was asked (USAGE and CONFIG in the frozen
// table), or something else ended it.
func withoutReport(code int) Kind {
	switch exitcode.Code(code) {
	case exitcode.Usage, exitcode.Config:
		return Refused
	}
	return Crashed
}

// opening is the layer the report opens on: the one its verdict is about
// (ADR123), or the first when the verdict names none or names a layer the
// report does not carry.
func opening(r model.Report) int {
	for i, l := range r.Layers {
		if r.Verdict.Layer != "" && l.ID == r.Verdict.Layer {
			return i
		}
	}
	return 0
}

// excerpt is the part of what the command line printed that the window shows:
// its first lines, as text, with a line saying so when there was more - and
// nothing when it printed nothing but space. more says the stream was longer
// than what was kept of it.
func excerpt(printed []byte, more bool) string {
	text := strings.ReplaceAll(strings.ToValidUTF8(string(printed), string(utf8.RuneError)), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], " \t\r")
	}
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	cut := more
	if len(lines) > maxPrintedLines {
		lines, cut = lines[:maxPrintedLines], true
	}
	if len(lines) == 0 {
		return ""
	}
	shown := strings.Join(lines, "\n")
	if cut {
		shown += "\n" + words.T(words.PrintedCut)
	}
	return shown
}
