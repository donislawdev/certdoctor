package spec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/donislawdev/certdoctor/internal/core/status"
	"github.com/donislawdev/certdoctor/internal/tool/jsontext"
)

// SchemaVersion is the version of the document every tool writes with --json,
// one for all of them and independent of the report's (ADR141 point 5). MINOR
// grows when a field or a block kind is added, MAJOR when one changes or goes.
const SchemaVersion = "1.0"

// Document is what a tool writes with --json, and what the window reads.
//
// Its fields are declared here, once, because the command line writes it and
// the window reads it, and the two must not disagree about a key.
type Document struct {
	// SchemaVersion is first because a reader has to read it before anything
	// else.
	SchemaVersion string `json:"schema_version"`
	// Program is who wrote the document.
	Program Program `json:"program"`
	// Tool is the tool's id.
	Tool string `json:"tool"`
	// EvaluatedAt is the time the tool judged against, in RFC 3339 and UTC,
	// so a saved document says when its "expired 3 hours ago" was true.
	EvaluatedAt string          `json:"evaluated_at"`
	Notes       []string        `json:"notes"`
	Checks      []DocumentCheck `json:"checks"`
	// Data is the tool's own, described with the tool.
	Data json.RawMessage `json:"data"`
	View []DocumentBlock `json:"view"`
}

// Program names the program and its version.
type Program struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// DocumentCheck is a Check as written.
type DocumentCheck struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Summary string `json:"summary"`
}

// DocumentBlock is a Block as written: a Fields block carries fields, a Code
// block language and body, a Text block body, and nothing else.
type DocumentBlock struct {
	Kind     string           `json:"kind"`
	Title    string           `json:"title"`
	Fields   *[]DocumentField `json:"fields,omitempty"`
	Language *string          `json:"language,omitempty"`
	Body     *string          `json:"body,omitempty"`
}

// DocumentField is a Field as written. Note and Status are null when the row
// has none.
type DocumentField struct {
	Label  string  `json:"label"`
	Value  string  `json:"value"`
	Note   *string `json:"note"`
	Status *string `json:"status"`
}

// NewDocument is what tool, judged at evaluatedAt by the program's version,
// writes for out.
func NewDocument(tool Tool, version, evaluatedAt string, out Outcome) (Document, error) {
	data, err := json.Marshal(out.Data)
	if err != nil {
		return Document{}, fmt.Errorf("the data of %s does not marshal: %w", tool.ID, err)
	}
	d := Document{
		SchemaVersion: SchemaVersion,
		Program:       Program{Name: "certdoctor", Version: version},
		Tool:          tool.ID,
		EvaluatedAt:   evaluatedAt,
		Notes:         append([]string{}, out.Notes...),
		Checks:        []DocumentCheck{},
		Data:          data,
		View:          []DocumentBlock{},
	}
	for _, c := range out.Checks {
		d.Checks = append(d.Checks, DocumentCheck{ID: c.ID, Status: string(c.Status), Summary: c.Summary})
	}
	for _, b := range out.View {
		d.View = append(d.View, written(b))
	}
	return d, nil
}

// written is a block as the document carries it.
func written(b Block) DocumentBlock {
	w := DocumentBlock{Kind: string(b.Kind), Title: b.Title}
	switch b.Kind {
	case Fields:
		fields := []DocumentField{}
		for _, f := range b.Fields {
			fields = append(fields, DocumentField{Label: f.Label, Value: f.Value, Note: orNull(f.Note),
				Status: orNull(string(f.Status))})
		}
		w.Fields = &fields
	case Code:
		w.Language, w.Body = &b.Language, &b.Body
	default:
		w.Body = &b.Body
	}
	return w
}

func orNull(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Marshal writes the document, two spaces per level and with <, > and &
// left as themselves - it is read by people and programs, never pasted into
// HTML by this program.
func (d Document) Marshal() ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(d); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// ReadDocument reads a document strictly: a name carried twice, a key it does
// not know, a status or a kind outside the closed lists, or a block carrying
// another kind's keys is refused. The window reads its child's output through
// this, so a document it draws is one the contract describes.
func ReadDocument(data []byte) (Document, error) {
	var d Document
	if err := strictly(data, &d); err != nil {
		return Document{}, err
	}
	// The data is kept on one line, as NewDocument makes it, rather than with
	// the indentation of the document it was read out of.
	var compact bytes.Buffer
	if err := json.Compact(&compact, d.Data); err != nil {
		return Document{}, fmt.Errorf("the document's data is not JSON: %w", err)
	}
	d.Data = compact.Bytes()
	return d, d.check()
}

// check holds what the struct alone does not.
func (d Document) check() error {
	if d.SchemaVersion == "" || d.Program.Version == "" || d.Tool == "" || d.Checks == nil || d.View == nil {
		return fmt.Errorf("the document lacks one of schema_version, program.version, tool, checks or view")
	}
	for _, c := range d.Checks {
		if c.ID == "" || !status.Status(c.Status).Valid() {
			return fmt.Errorf("a check has no id or a status outside the four")
		}
	}
	for _, b := range d.View {
		if err := b.check(); err != nil {
			return err
		}
	}
	return nil
}

// check holds a block to its kind's keys.
func (b DocumentBlock) check() error {
	kind := BlockKind(b.Kind)
	ok := slices.Contains(BlockKinds, kind) &&
		(b.Fields != nil) == (kind == Fields) &&
		(b.Language != nil) == (kind == Code) &&
		(b.Body != nil) == (kind != Fields)
	if !ok {
		return fmt.Errorf("a block of the kind %q carries keys of another kind, or is of no kind", b.Kind)
	}
	if b.Fields != nil {
		for _, f := range *b.Fields {
			if f.Status != nil && !status.Status(*f.Status).Valid() {
				return fmt.Errorf("a field has a status outside the four")
			}
		}
	}
	return nil
}

// strictly decodes data into v, refusing what is not exactly JSON, what
// carries a name twice, a key v does not have, and more after the value.
func strictly(data []byte, v any) error {
	if _, dups, err := jsontext.Parse(data); err != nil {
		return fmt.Errorf("the document %w", err)
	} else if len(dups) > 0 {
		return fmt.Errorf("the document carries the name %q twice (at %q)", dups[0].Name, dups[0].Path)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("the document does not have the shape of the contract: %w", err)
	}
	return nil
}
