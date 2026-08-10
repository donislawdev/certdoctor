package render

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// The declared shape of the machine readable report.
//
// WHY THIS EXISTS AS DATA RATHER THAN AS A COMMENT. The regression surface has
// carried the line "--json validates against its declared schema" since before
// there was any JSON, with nothing behind it, because there was no schema to
// validate against. This is that schema. It is walked at test time against a
// real document, so the sentence stops being prose.
//
// WHY IT IS WRITTEN OUT BY HAND rather than derived from the struct tags in
// json.go. A schema generated from the structs would agree with the structs
// however wrong both were, which is the shape of a test that checks nothing.
// Two independent declarations mean a rename has to be made twice, and the day
// it is made once is the day this fails.
//
// WHAT IT DOES NOT CHECK, said here rather than discovered later: it knows
// nothing about the meaning of a value. A status outside the vocabulary, an
// exit code outside the table, a duration that is negative - all of those are
// well formed and all of them are caught somewhere else, by the core's own
// validation. This checks the shape a consumer parses against, and nothing
// more.
var schema = object(map[string]node{
	"schema_version": text(),
	"tool": object(map[string]node{
		"name":    text(),
		"version": text(),
	}),
	"run": object(map[string]node{
		"started_at":      text(),
		"duration_ms":     number(),
		"target":          text(),
		"privilege_level": text(),
		"platform": object(map[string]node{
			"os":   text(),
			"arch": text(),
			// Null means nothing established it. See the note carried in the
			// same report.
			"container": nullable(boolean()),
		}),
		"redacted":        boolean(),
		"budget_exceeded": boolean(),
	}),
	"verdict": object(map[string]node{
		"status":    text(),
		"sentence":  text(),
		"exit_code": number(),
	}),
	"layers": array(object(map[string]node{
		"id":     text(),
		"name":   text(),
		"status": text(),
		"reason": nullable(text()),
		"detail": nullable(text()),
		// Null means this layer never looked, an array means it did. The
		// difference is a claim about the machine, so it is in the contract
		// rather than left to a reader's charity.
		//
		// WHAT THIS DELIBERATELY DOES NOT ENCODE: that the body key has to match
		// the kind. That is the meaning of a value, and the paragraph at the top
		// of this file says this checks shape and nothing else. The union rule
		// itself is enforced twice on the other side - by the orchestrator when
		// a layer hands a finding over, and by the report validator before
		// anything is printed. The day a second kind exists, this declaration
		// grows a second nullable body next to the first, and that is a visible
		// edit rather than a silent gap.
		"findings": nullable(array(object(map[string]node{
			"kind":    text(),
			"summary": text(),
			"source":  text(),
			"environment_variable": nullable(object(map[string]node{
				"name": text(),
				// Null when the variable is not set. An empty string means it is
				// set to nothing, which switches proxying off in some tools.
				"value":               nullable(text()),
				"set":                 boolean(),
				"carried_credentials": boolean(),
			})),
			// The second body, and the paragraph above predicted this edit
			// exactly: the declaration grows a nullable body next to the first
			// rather than a gap appearing quietly.
			"name_resolution": nullable(object(map[string]node{
				"name": text(),
				"view": text(),
				// Null for the system view on all three: the operating system
				// resolves a name and reports neither which resolver replied, nor
				// which record type it asked for, nor what code came back.
				"resolver":      nullable(text()),
				"query_type":    nullable(text()),
				"response_code": nullable(text()),
				// Null whenever there WAS an answer, and one of the closed reasons
				// when there was not - ADR30. It sits beside response_code rather
				// than inside it because silence is a transport fact and a response
				// code is a DNS fact, and a consumer must not have to guess which
				// values came off the wire.
				"no_answer":   nullable(text()),
				"addresses":   array(text()),
				"duration_ms": number(),
			})),
		}))),
	})),
	"notes": array(object(map[string]node{
		"kind":   text(),
		"layer":  nullable(text()),
		"field":  nullable(text()),
		"reason": nullable(text()),
		"detail": text(),
	})),
})

// kind is the JSON type a node accepts.
type kind uint8

const (
	kindObject kind = iota
	kindArray
	kindString
	kindNumber
	kindBool
)

func (k kind) String() string {
	switch k {
	case kindObject:
		return "an object"
	case kindArray:
		return "an array"
	case kindString:
		return "a string"
	case kindNumber:
		return "a number"
	default:
		return "a boolean"
	}
}

// node is one declared position in the document.
//
// Every declared field is required. That is stricter than most schemas and it
// is the right default here: this program controls both ends, so a field that
// is sometimes absent is a field somebody forgot rather than a field that is
// optional. Optionality is expressed as a null value, which keeps the key in
// place and the consumer's parsing simple.
type node struct {
	kind     kind
	nullable bool
	fields   map[string]node
	item     *node
}

func object(fields map[string]node) node { return node{kind: kindObject, fields: fields} }
func array(item node) node               { return node{kind: kindArray, item: &item} }
func text() node                         { return node{kind: kindString} }
func number() node                       { return node{kind: kindNumber} }
func boolean() node                      { return node{kind: kindBool} }

func nullable(n node) node {
	n.nullable = true
	return n
}

// ValidateDocument checks bytes produced by this package against the declared
// schema and returns every problem it finds rather than the first.
//
// The caller is a test and, for the entry point, a last check before the
// document leaves the process. A document that does not match its own declared
// schema is an internal failure and must not be printed: whoever receives it
// would parse it against the contract we published and get a different answer
// than we did.
func ValidateDocument(document []byte) error {
	var decoded any
	if err := json.Unmarshal(document, &decoded); err != nil {
		return fmt.Errorf("the document is not valid JSON: %w", err)
	}
	problems := schema.check("", decoded)
	sort.Slice(problems, func(i, j int) bool { return problems[i].Error() < problems[j].Error() })
	return errors.Join(problems...)
}

func (n node) check(path string, value any) []error {
	where := path
	if where == "" {
		where = "the document"
	}

	if value == nil {
		if n.nullable {
			return nil
		}
		return []error{fmt.Errorf("%s is null and the schema does not allow that", where)}
	}

	switch n.kind {
	case kindObject:
		return n.checkObject(path, where, value)
	case kindArray:
		return n.checkArray(path, where, value)
	case kindString:
		return expect[string](where, value, n.kind)
	case kindNumber:
		return expect[float64](where, value, n.kind)
	default:
		return expect[bool](where, value, n.kind)
	}
}

func (n node) checkObject(path, where string, value any) []error {
	fields, ok := value.(map[string]any)
	if !ok {
		return mismatch(where, value, n.kind)
	}

	var problems []error
	for name, declared := range n.fields {
		present, found := fields[name]
		if !found {
			problems = append(problems, fmt.Errorf("%s has no %q, which the schema declares", where, name))
			continue
		}
		problems = append(problems, declared.check(join(path, name), present)...)
	}
	for name := range fields {
		if _, declared := n.fields[name]; !declared {
			problems = append(problems, fmt.Errorf(
				"%s carries %q, which the schema does not declare - a field nobody declared is a field nobody versioned", where, name))
		}
	}
	return problems
}

func (n node) checkArray(path, where string, value any) []error {
	items, ok := value.([]any)
	if !ok {
		return mismatch(where, value, n.kind)
	}
	var problems []error
	for i, item := range items {
		problems = append(problems, n.item.check(fmt.Sprintf("%s[%d]", path, i), item)...)
	}
	return problems
}

func expect[T any](where string, value any, want kind) []error {
	if _, ok := value.(T); ok {
		return nil
	}
	return mismatch(where, value, want)
}

func mismatch(where string, value any, want kind) []error {
	return []error{fmt.Errorf("%s is %T, the schema declares %s", where, value, want)}
}

func join(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}
