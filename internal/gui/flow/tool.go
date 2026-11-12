package flow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	"github.com/donislawdev/certdoctor/internal/gui/words"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// A TOOL RUNS THE WAY A DIAGNOSIS DOES (ADR141 point 7): the command line
// beside the window, through the same port, asked with a request document on
// standard input and answering with its document - so the window runs no
// tool's code and a token that crashes a parser ends the child, not the
// window. What is here knows no toolkit and is checked without a window
// (GUI rule 15).

// ToolLimit is how long a tool's run is given before the window ends it. A
// tool reads what it was handed and connects to nothing, so a run this long is
// a broken one, not a slow one.
const ToolLimit = 20 * time.Second

// ToolArgs are the arguments the tool id is run with.
func ToolArgs(id string) []string { return []string{"tool", id, "--request", "-", "--json"} }

// ToolInput is the request document for the tool id, with the text typed in
// each of its boxes - never an argument, which a list of running programs
// shows to everyone on the machine (ADR141 point 3).
func ToolInput(id string, typed map[string]string) []byte {
	type text struct {
		Text string `json:"text"`
	}
	doc := struct {
		SchemaVersion string          `json:"schema_version"`
		Tool          string          `json:"tool"`
		Inputs        map[string]text `json:"inputs"`
	}{spec.SchemaVersion, id, map[string]text{}}
	for name, t := range typed {
		doc.Inputs[name] = text{t}
	}
	data, _ := json.Marshal(doc) // strings and a map of them always marshal
	return data
}

// ToolAnswer is what came of a tool's run - one of the three, or none of
// them for a run the window ended itself because another took its place.
type ToolAnswer struct {
	// Document is the tool's answer.
	Document *spec.Document
	// Refusal is the tool's own sentence on an input it cannot read.
	Refusal string
	// Problem is what stood in the way of any answer, in the window's words.
	Problem *Sentences
}

// JudgeTool reads what the run of the tool id left behind, for the window of
// version.
func JudgeTool(id string, p Process, version string) ToolAnswer {
	problem := func(title, what, todo string) ToolAnswer {
		return ToolAnswer{Problem: &Sentences{Title: title, What: what, Todo: todo,
			Printed: excerpt(p.Printed, p.PrintedTooLong)}}
	}
	todo := fmt.Sprintf(words.T(words.ToolTodo), id)
	switch {
	case p.Missing:
		s := Trouble{Kind: Missing, Program: p.Program}.Sentences()
		return ToolAnswer{Problem: &s}
	case p.StartFailed != nil:
		s := Trouble{Kind: NotStarted, Program: p.Program, Said: p.StartFailed.Error()}.Sentences()
		return ToolAnswer{Problem: &s}
	case errors.Is(p.Stopped, context.DeadlineExceeded):
		return problem(words.T(words.ToolOverranTitle),
			fmt.Sprintf(words.T(words.ToolOverranWhat), seconds(ToolLimit.Seconds())), todo)
	case p.Stopped != nil:
		return ToolAnswer{}
	case p.Code == exitcode.Config.Int() && len(p.Out) == 0 && refusal(p.Printed) != "":
		return ToolAnswer{Refusal: refusal(p.Printed)}
	case p.Code != exitcode.OK.Int() || len(p.Out) == 0:
		return problem(words.T(words.ToolCrashedTitle), fmt.Sprintf(words.T(words.ToolCrashedWhat), p.Code), todo)
	case p.OutTooLong:
		return problem(words.T(words.ToolUnreadableTitle),
			fmt.Sprintf(words.T(words.UnreadableLong), MaxDocument>>20), todo)
	}
	return readToolDocument(id, p.Out, version, problem, todo)
}

// readToolDocument reads a tool's document and holds it to this window: the
// version that wrote it, the schema, and the tool it answers for.
func readToolDocument(id string, out []byte, version string, problem func(string, string, string) ToolAnswer,
	todo string) ToolAnswer {
	d, err := spec.ReadDocument(out)
	switch {
	case err != nil:
		return problem(words.T(words.ToolUnreadableTitle),
			fmt.Sprintf(words.T(words.ToolUnreadableWhat), withoutFullStop(err.Error())), todo)
	case d.Program.Version != version || d.SchemaVersion != spec.SchemaVersion:
		return problem(words.T(words.VersionTitle), fmt.Sprintf(words.T(words.ToolVersionWhat), version,
			d.Program.Version), words.T(words.VersionTodo))
	case d.Tool != id:
		return problem(words.T(words.ToolUnreadableTitle),
			fmt.Sprintf(words.T(words.ToolUnreadableWhat), "it answers for another tool"), todo)
	}
	return ToolAnswer{Document: &d}
}

// refusal is the first line the command line printed, without the program's
// name in front, as a sentence of its own: the command line writes it to
// follow "certdoctor:", in lower case and without a full stop, and on a
// screen it stands alone.
func refusal(printed []byte) string {
	line, _, _ := strings.Cut(strings.TrimSpace(string(printed)), "\n")
	line = strings.TrimSpace(strings.TrimPrefix(line, "certdoctor:"))
	if line == "" {
		return ""
	}
	first, size := utf8.DecodeRuneInString(line)
	line = string(unicode.ToUpper(first)) + line[size:]
	if !strings.HasSuffix(line, ".") {
		line += "."
	}
	return line
}
