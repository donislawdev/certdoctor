// Package jsontext reads JSON written by somebody else and keeps what an
// ordinary decoder throws away: the order of an object's members, the names an
// object carries twice, and every number exactly as written.
//
// WHY A TOOL NEEDS ALL THREE. A person decoding a token compares it with what
// the issuer's documentation shows, member by member, so the order is how they
// find their way. A name carried twice is how one parser reads a token one way
// and another parser the other way (RFC 7515 section 4, RFC 7519 section 4:
// parsers MUST either reject duplicates or take the lexically last), so it is
// a finding rather than a detail to smooth over. And a number like 1e400 or
// 12345678901234567890 has no float64 that says it, so it is kept as text.
//
// THE INPUT IS HOSTILE, and the package is built on that: invalid UTF-8 is
// refused rather than replaced (encoding/json would quietly swap it for
// U+FFFD), nesting deeper than MaxDepth is refused before it costs anything,
// and an error says where, never what - the bytes may be a credential.
//
// ONE THING IT CANNOT SEE: an escaped lone surrogate (a backslash, u and d800)
// is read by encoding/json as U+FFFD, so such a string shows U+FFFD rather than
// its escape. It is not refused, and not reported.
//
// Shared by every tool that reads JSON (ADR141 point 7), so the rules above
// live once.
package jsontext

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// MaxDepth is the deepest nesting read. A token or a key set nests three or
// four levels, so this is far above anything real and far below what costs
// memory or time.
const MaxDepth = 64

// Kind is what a value is.
type Kind int

// The kinds of value.
const (
	Null Kind = iota
	Bool
	Number
	String
	Array
	Object
)

// Value is one JSON value.
type Value struct {
	Kind Kind
	// Text is a string's contents, a number exactly as written, or "true" and
	// "false".
	Text string
	// Members are an object's members in the order written, duplicates kept.
	Members []Member
	// Items are an array's items.
	Items []Value
}

// Member is one member of an object.
type Member struct {
	Name  string
	Value Value
}

// Duplicate is a name an object carries more than once.
type Duplicate struct {
	// Path is where the object is, as a JSON Pointer (RFC 6901) - "" for the
	// outermost one.
	Path string
	Name string
}

// Error says where the text stops being JSON this package reads, never what
// stands there.
type Error struct {
	// Offset is the position of the byte the reading stopped at, counted from
	// 1 - the count encoding/json's SyntaxError gives, kept for every problem
	// so one message does not count from 0 and the next from 1.
	Offset int64
	// Problem finishes the sentence "the text ...".
	Problem string
}

func (e *Error) Error() string { return fmt.Sprintf("%s at byte %d", e.Problem, e.Offset) }

// Parse reads data as exactly one JSON value.
func Parse(data []byte) (Value, []Duplicate, error) {
	if !utf8.Valid(data) {
		return Value{}, nil, &Error{Offset: int64(firstInvalid(data)) + 1, Problem: "is not valid UTF-8"}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	r := &reader{dec: dec, size: int64(len(data))}
	v, err := r.value("", 0)
	if err != nil {
		return Value{}, nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Value{}, nil, &Error{Offset: dec.InputOffset() + 1, Problem: "goes on after its JSON value"}
	}
	return v, r.duplicates, nil
}

// Get is the member of an object called name. When the name is there more
// than once it is the last one, which is the reading RFC 7515 and RFC 7519
// allow a parser that does not refuse.
func (v Value) Get(name string) (Value, bool) {
	for i := len(v.Members) - 1; i >= 0; i-- {
		if v.Members[i].Name == name {
			return v.Members[i].Value, true
		}
	}
	return Value{}, false
}

// reader walks the decoder's tokens.
type reader struct {
	dec        *json.Decoder
	size       int64
	duplicates []Duplicate
}

// value reads one value, at path and depth.
func (r *reader) value(path string, depth int) (Value, error) {
	offset := r.dec.InputOffset()
	tok, err := r.dec.Token()
	if err != nil {
		return Value{}, r.broken(offset, err)
	}
	switch t := tok.(type) {
	case json.Delim:
		if depth >= MaxDepth {
			return Value{}, &Error{Offset: offset, Problem: fmt.Sprintf("nests deeper than %d levels", MaxDepth)}
		}
		if t == '{' {
			return r.object(path, depth+1)
		}
		return r.array(path, depth+1)
	case string:
		return Value{Kind: String, Text: t}, nil
	case json.Number:
		return Value{Kind: Number, Text: t.String()}, nil
	case bool:
		return Value{Kind: Bool, Text: fmt.Sprint(t)}, nil
	default:
		return Value{Kind: Null}, nil
	}
}

// object reads the members of an object whose opening brace was read.
func (r *reader) object(path string, depth int) (Value, error) {
	v := Value{Kind: Object}
	seen := map[string]bool{}
	for r.dec.More() {
		offset := r.dec.InputOffset()
		tok, err := r.dec.Token()
		if err != nil {
			return Value{}, r.broken(offset, err)
		}
		name, _ := tok.(string)
		if seen[name] {
			r.duplicates = append(r.duplicates, Duplicate{Path: path, Name: name})
		}
		seen[name] = true
		member, err := r.value(path+"/"+pointerToken(name), depth)
		if err != nil {
			return Value{}, err
		}
		v.Members = append(v.Members, Member{Name: name, Value: member})
	}
	return v, r.close()
}

// array reads the items of an array whose opening bracket was read.
func (r *reader) array(path string, depth int) (Value, error) {
	v := Value{Kind: Array}
	for r.dec.More() {
		item, err := r.value(fmt.Sprintf("%s/%d", path, len(v.Items)), depth)
		if err != nil {
			return Value{}, err
		}
		v.Items = append(v.Items, item)
	}
	return v, r.close()
}

// close reads the brace or bracket that ends an object or an array.
func (r *reader) close() error {
	offset := r.dec.InputOffset()
	if _, err := r.dec.Token(); err != nil {
		return r.broken(offset, err)
	}
	return nil
}

// broken turns a decoder's error into this package's, which says where and not
// what: encoding/json names the character it stopped at, and that character is
// a byte of the input.
//
// Text that stops halfway is told apart by WHERE the decoder stopped - at the
// end - rather than by its error: Token answers it with io.EOF before the
// first byte and with a SyntaxError after it, measured on Go 1.27.4.
func (r *reader) broken(offset int64, err error) error {
	var syntax *json.SyntaxError
	if errors.As(err, &syntax) {
		offset = syntax.Offset
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || offset >= r.size {
		return &Error{Offset: r.size, Problem: "ends before its JSON value does"}
	}
	return &Error{Offset: offset, Problem: "is not valid JSON"}
}

// pointerToken escapes a name for a JSON Pointer (RFC 6901 section 3): "~" as
// "~0" and "/" as "~1", in that order.
func pointerToken(name string) string {
	var b bytes.Buffer
	for _, r := range name {
		switch r {
		case '~':
			b.WriteString("~0")
		case '/':
			b.WriteString("~1")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// firstInvalid is the offset of the first byte of data that is not UTF-8.
func firstInvalid(data []byte) int {
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		if r == utf8.RuneError && size == 1 {
			return i
		}
		i += size
	}
	return len(data)
}
