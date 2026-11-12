package spec

import (
	"encoding/base64"
	"fmt"
	"sort"
)

// The request document (ADR141 point 3) is how the window hands a tool its
// inputs - every tool, one input or five - and how a script can:
//
//	{"schema_version": "1.0", "tool": "jwt", "inputs": {"token": {"text": "eyJ..."}}}
//
// Each input is given exactly one way: "text" (a string), "base64" (bytes) or
// "path" (a file the command line reads, so the window never opens one). A
// secret never has to stand in an argument, and the window never writes a
// temporary file (inviolable rule 14).

// RequestInput is one input as a request gives it: Text, Bytes or Path.
type RequestInput struct {
	Text  *string
	Bytes []byte
	Path  string
}

// Request is a request document, read and checked against its tool.
type Request struct {
	Inputs map[string]RequestInput
}

// requestDocument is the request as written.
type requestDocument struct {
	SchemaVersion string                  `json:"schema_version"`
	Tool          string                  `json:"tool"`
	Inputs        map[string]requestValue `json:"inputs"`
}

// requestValue is one input as written - exactly one key of the three.
type requestValue struct {
	Text   *string `json:"text"`
	Base64 *string `json:"base64"`
	Path   *string `json:"path"`
}

// ReadRequest reads a request document for tool. The size of each input is
// the caller's to hold against its limit, once a path has been read too.
func ReadRequest(data []byte, tool Tool) (Request, error) {
	var doc requestDocument
	if err := strictly(data, &doc); err != nil {
		return Request{}, fmt.Errorf("the request: %w", err)
	}
	if doc.SchemaVersion != SchemaVersion {
		return Request{}, fmt.Errorf("the request has schema_version %q, and this program reads %q",
			doc.SchemaVersion, SchemaVersion)
	}
	if doc.Tool != tool.ID {
		return Request{}, fmt.Errorf("the request is for the tool %q, and this is %s", doc.Tool, tool.ID)
	}
	if err := knownInputs(doc.Inputs, tool); err != nil {
		return Request{}, err
	}
	r := Request{Inputs: map[string]RequestInput{}}
	for _, in := range tool.Inputs {
		v, ok := doc.Inputs[in.Name]
		if !ok {
			return Request{}, fmt.Errorf("the request gives no %q, which %s needs", in.Name, tool.ID)
		}
		got, err := v.read(in.Name)
		if err != nil {
			return Request{}, err
		}
		r.Inputs[in.Name] = got
	}
	return r, nil
}

// knownInputs refuses an input the tool does not take, naming the first in
// sorted order so the answer is the same on every run.
func knownInputs(given map[string]requestValue, tool Tool) error {
	var names []string
	for name := range given {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, ok := tool.Input(name); !ok {
			return fmt.Errorf("the request gives %q, which %s does not take", name, tool.ID)
		}
	}
	return nil
}

// read is the input given exactly one way.
func (v requestValue) read(name string) (RequestInput, error) {
	ways := 0
	for _, given := range []bool{v.Text != nil, v.Base64 != nil, v.Path != nil} {
		if given {
			ways++
		}
	}
	if ways != 1 {
		return RequestInput{}, fmt.Errorf("the request gives %q %d ways - give it as exactly one of text, base64 and path",
			name, ways)
	}
	switch {
	case v.Text != nil:
		return RequestInput{Text: v.Text}, nil
	case v.Path != nil:
		if *v.Path == "" {
			return RequestInput{}, fmt.Errorf("the request gives %q as an empty path", name)
		}
		return RequestInput{Path: *v.Path}, nil
	default:
		b, err := base64.StdEncoding.Strict().DecodeString(*v.Base64)
		if err != nil {
			return RequestInput{}, fmt.Errorf("the request gives %q as base64 that is not standard base64", name)
		}
		return RequestInput{Bytes: b}, nil
	}
}
