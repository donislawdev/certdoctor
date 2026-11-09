// Package model is what the window shows, read from the document the command
// line writes with --json. It knows that contract and nothing of the toolkit,
// so it can be read and checked without a window (ADR121).
//
// It reads bytes and never a path: the document reaches the window from the
// command line it runs, and where those bytes come from is the business of the
// part that runs it, not of the part that reads them.
package model

import (
	"encoding/json"

	"github.com/donislawdev/certdoctor/internal/core/status"
)

// Status is one of the report's four statuses. The window takes the type and
// the four values from the vocabulary the report itself is written with, so the
// two cannot spell a status differently - the statuses are a public contract
// (ADR6), and a second spelling of them here would be the copy that drifts.
type Status = status.Status

// The four statuses.
const (
	Pass    = status.Pass
	Warn    = status.Warn
	Fail    = status.Fail
	Unknown = status.Unknown
)

// SchemaVersion is the schema of the document this window draws. It is the
// command line's own, held equal to render.SchemaVersion by a guard that reads
// both (internal/guard/window_test.go) - the window may not import the
// renderer (ADR124), and a document of another schema is refused rather than
// drawn (ADR121 point 1).
const SchemaVersion = "2.4"

// Report is one run.
type Report struct {
	Schema     string
	Target     string
	DurationMS int64
	Privilege  string
	OS, Arch   string
	Version    string
	Verdict    Verdict
	Layers     []Layer
}

// Verdict is the sentence at the top and what it rests on.
type Verdict struct {
	Status   Status
	Sentence string
	ExitCode int
	// Layer is the layer the sentence is about, by its id, or nothing when the
	// sentence names none (ADR123). The window opens the report on it rather
	// than working the ladder out again.
	Layer string
}

// Head is what a document says about itself before anything else is read:
// the schema it is written in and the version of the program that wrote it.
type Head struct {
	Schema  string
	Version string
}

// Layer is one row of the causal ladder, L0 to L5.
type Layer struct {
	ID, Name string
	Status   Status
	Reason   string
	Detail   string
	Findings []Finding
	Stores   []Store
}

// Finding is one fact a layer found, in the report's own words.
type Finding struct {
	Kind    string
	Summary string
}

// Trust is what one store says of the presented chain: yes, no, or not
// assessed - three states, never two.
type Trust int

// The three answers a store gives.
const (
	TrustNotAssessed Trust = iota
	TrustYes
	TrustNo
)

// Store is one row of the trust matrix.
type Store struct {
	Runtime    string
	Instance   string
	Anchors    int
	Trust      Trust
	ChosenBy   []string
	Command    string
	NeedsAdmin bool
	Elevation  string
	Caveat     string
}

// wire is the part of the document the window reads, in the document's own
// names. Everything else in the document is left alone, so a field the
// command line adds in a MINOR version of the schema reaches nothing here.
type wire struct {
	wireHead
	Run struct {
		Target     string `json:"target"`
		DurationMS int64  `json:"duration_ms"`
		Privilege  string `json:"privilege_level"`
		Platform   struct {
			OS   string `json:"os"`
			Arch string `json:"arch"`
		} `json:"platform"`
	} `json:"run"`
	Verdict struct {
		Status   Status  `json:"status"`
		Sentence string  `json:"sentence"`
		ExitCode int     `json:"exit_code"`
		Layer    *string `json:"layer"`
	} `json:"verdict"`
	Layers []wireLayer `json:"layers"`
}

// wireHead is the two fields a document is asked for before it is read: the
// schema, which comes first in it, and the version that wrote it. Read on
// their own as well, so a document of another schema is told apart from one
// that is not a document at all - a whole read of another schema can fail on
// a field this window does not know, and say nothing about which it was.
type wireHead struct {
	Schema string `json:"schema_version"`
	Tool   struct {
		Version string `json:"version"`
	} `json:"tool"`
}

type wireLayer struct {
	ID       string        `json:"id"`
	Name     string        `json:"name"`
	Status   Status        `json:"status"`
	Reason   *string       `json:"reason"`
	Detail   string        `json:"detail"`
	Findings []wireFinding `json:"findings"`
}

type wireFinding struct {
	Kind       string     `json:"kind"`
	Summary    string     `json:"summary"`
	TrustStore *wireStore `json:"trust_store"`
}

type wireStore struct {
	Runtime  string   `json:"runtime"`
	Instance string   `json:"instance"`
	Anchors  int      `json:"trust_anchor_count"`
	Trusts   *bool    `json:"trusts_presented_chain"`
	Selected []string `json:"selected_by"`
	Fix      *struct {
		Command   string  `json:"command"`
		Elevated  bool    `json:"requires_elevation"`
		Elevation *string `json:"elevation"`
		Caveat    *string `json:"caveat"`
	} `json:"fix"`
}

// ReadHead reads what a document says about itself: its schema and the version
// that wrote it. An answer, never a judgement - whether they are the ones this
// window draws is the caller's question.
func ReadHead(document []byte) (Head, error) {
	var h wireHead
	if err := json.Unmarshal(document, &h); err != nil {
		return Head{}, err
	}
	return Head{Schema: h.Schema, Version: h.Tool.Version}, nil
}

// Decode reads a document written with --json.
//
// It does not judge the document. The command line validated it before it
// wrote it and writes nothing it could not validate, and the window asks that
// the version and the schema are its own before it reads further (ADR121
// point 1) - a reader that also validated would be a second validator, and the
// two would disagree on the day one of them is changed.
func Decode(document []byte) (Report, error) {
	var w wire
	if err := json.Unmarshal(document, &w); err != nil {
		return Report{}, err
	}
	r := Report{
		Schema:     w.Schema,
		Target:     w.Run.Target,
		DurationMS: w.Run.DurationMS,
		Privilege:  w.Run.Privilege,
		OS:         w.Run.Platform.OS,
		Arch:       w.Run.Platform.Arch,
		Version:    w.Tool.Version,
		Verdict:    Verdict{Status: w.Verdict.Status, Sentence: w.Verdict.Sentence, ExitCode: w.Verdict.ExitCode},
	}
	if w.Verdict.Layer != nil {
		r.Verdict.Layer = *w.Verdict.Layer
	}
	for _, l := range w.Layers {
		r.Layers = append(r.Layers, layerOf(l))
	}
	return r, nil
}

// layerOf reads one layer. A finding that carries a trust store is a row of
// the matrix and nothing else, because the matrix is how the window shows it.
func layerOf(l wireLayer) Layer {
	layer := Layer{ID: l.ID, Name: l.Name, Status: l.Status, Detail: l.Detail}
	if l.Reason != nil {
		layer.Reason = *l.Reason
	}
	for _, f := range l.Findings {
		if f.TrustStore != nil {
			layer.Stores = append(layer.Stores, storeOf(*f.TrustStore))
			continue
		}
		layer.Findings = append(layer.Findings, Finding{Kind: f.Kind, Summary: f.Summary})
	}
	return layer
}

// storeOf reads one row of the matrix. The store's answer has three states in
// the document - true, false and null - and keeps all three here.
func storeOf(s wireStore) Store {
	store := Store{Runtime: s.Runtime, Instance: s.Instance, Anchors: s.Anchors, ChosenBy: s.Selected}
	switch {
	case s.Trusts == nil:
		store.Trust = TrustNotAssessed
	case *s.Trusts:
		store.Trust = TrustYes
	default:
		store.Trust = TrustNo
	}
	if s.Fix != nil {
		store.Command = s.Fix.Command
		store.NeedsAdmin = s.Fix.Elevated
		if s.Fix.Elevation != nil {
			store.Elevation = *s.Fix.Elevation
		}
		if s.Fix.Caveat != nil {
			store.Caveat = *s.Fix.Caveat
		}
	}
	return store
}
