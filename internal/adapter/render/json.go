package render

import (
	"bytes"
	"encoding/json"
	"io"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// SchemaVersion is the version of the machine readable contract.
//
// People keep this output in their repositories for years, so the number is a
// promise: adding a field raises the minor, and removing one, renaming one or
// changing what one means raises the major. A consumer must ignore fields it
// does not know, and that is written in the README rather than assumed.
//
// It stays at 1.0 for the whole of the first milestone even though almost every
// slice adds fields. Nothing is released and nobody consumes it yet, so counting
// up to 1.8 before the first user exists would be noise dressed as diligence.
// The number moves when there is somebody it could mislead.
const SchemaVersion = "1.0"

// JSON renders the machine readable report.
//
// Its shape is declared twice on purpose: once as the struct tags below, which
// produce the document, and once as the schema in schema.go, which checks it.
// Two declarations of one contract is normally how drift starts. Here it is the
// point - a rename that only happens in one of them is exactly what the guard
// is for, and a schema derived from the structs would agree with them even when
// both are wrong.
type JSON struct{}

type jsonReport struct {
	// SchemaVersion is first because a consumer has to read it before trying
	// anything else with the document.
	SchemaVersion string      `json:"schema_version"`
	Tool          jsonTool    `json:"tool"`
	Run           jsonRun     `json:"run"`
	Verdict       jsonVerdict `json:"verdict"`
	Layers        []jsonLayer `json:"layers"`
	Notes         []jsonNote  `json:"notes"`
}

type jsonTool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type jsonRun struct {
	StartedAt      string       `json:"started_at"`
	DurationMS     int64        `json:"duration_ms"`
	Target         string       `json:"target"`
	PrivilegeLevel string       `json:"privilege_level"`
	Platform       jsonPlatform `json:"platform"`
	Redacted       bool         `json:"redacted"`
	BudgetExceeded bool         `json:"budget_exceeded"`
}

type jsonPlatform struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
	// Container is null rather than false when nothing has established it. A
	// false here would state a measurement nobody took, and the accompanying
	// note says which.
	Container *bool `json:"container"`
}

type jsonVerdict struct {
	Status   string `json:"status"`
	Sentence string `json:"sentence"`
	// ExitCode repeats what the process returns. The redundancy is deliberate:
	// a report saved to a file keeps information the process exit status
	// cannot.
	ExitCode int `json:"exit_code"`
}

type jsonLayer struct {
	ID     string  `json:"id"`
	Name   string  `json:"name"`
	Status string  `json:"status"`
	Reason *string `json:"reason"`
	Detail *string `json:"detail"`
}

type jsonNote struct {
	Kind   string  `json:"kind"`
	Layer  *string `json:"layer"`
	Field  *string `json:"field"`
	Reason *string `json:"reason"`
	Detail string  `json:"detail"`
}

// Render writes the whole document, or nothing.
func (JSON) Render(w io.Writer, r report.Report) error {
	document, err := Encode(r)
	if err != nil {
		return err
	}
	_, err = w.Write(document)
	return err
}

// Encode turns a report into the bytes of the machine readable document.
//
// It is separate from Render so that the schema guard can check the document
// without a writer, and so that the caller can hold the finished bytes before
// deciding where they go. Nothing half written ever reaches a destination.
func Encode(r report.Report) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetIndent("", "  ")

	// HTML escaping is left on. Certificate subjects arrive from the network
	// and this renderer is not the place to decide what is safe to drop into a
	// page - turning it off here would buy slightly prettier output and hand a
	// footgun to whoever embeds the result somewhere else.
	if err := encoder.Encode(documentFor(r)); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func documentFor(r report.Report) jsonReport {
	return jsonReport{
		SchemaVersion: SchemaVersion,
		Tool:          jsonTool{Name: r.Tool.Name, Version: r.Tool.Version},
		Run: jsonRun{
			StartedAt:      r.Run.StartedAt.UTC().Format(time.RFC3339),
			DurationMS:     r.Run.Duration.Milliseconds(),
			Target:         r.Run.Target,
			PrivilegeLevel: r.Run.PrivilegeLevel.String(),
			Platform: jsonPlatform{
				OS:        r.Run.Platform.OS,
				Arch:      r.Run.Platform.Arch,
				Container: tristate(r.Run.Platform.Container),
			},
			Redacted:       r.Run.Redacted,
			BudgetExceeded: r.Run.BudgetExceeded,
		},
		Verdict: jsonVerdict{
			Status:   Label(r.Verdict.Status),
			Sentence: r.Verdict.Sentence,
			ExitCode: r.Verdict.ExitCode.Int(),
		},
		Layers: layersOf(r),
		Notes:  notesOf(r),
	}
}

func layersOf(r report.Report) []jsonLayer {
	// A non-nil empty slice encodes as [] rather than null. An empty array says
	// "there were none of these", null says "this field was never filled in",
	// and those are different claims.
	rows := make([]jsonLayer, 0, len(r.Layers))
	for _, row := range r.Layers {
		rows = append(rows, jsonLayer{
			ID:     row.ID.String(),
			Name:   row.ID.Name(),
			Status: Label(row.Status),
			Reason: optional(row.Reason.String()),
			Detail: optional(row.Detail),
		})
	}
	return rows
}

func notesOf(r report.Report) []jsonNote {
	notes := make([]jsonNote, 0, len(r.Notes))
	for _, note := range r.Notes {
		notes = append(notes, jsonNote{
			Kind:   note.Kind.String(),
			Layer:  optional(note.Layer.String()),
			Field:  optional(note.Field),
			Reason: optional(note.Reason.String()),
			Detail: note.Detail,
		})
	}
	return notes
}

// optional turns an empty string into a JSON null, so that "this does not apply
// here" and "this is the empty string" are not the same document.
func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func tristate(t report.Tristate) *bool {
	switch t {
	case report.DeterminedTrue:
		yes := true
		return &yes
	case report.DeterminedFalse:
		no := false
		return &no
	default:
		return nil
	}
}
