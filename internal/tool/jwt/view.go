package jwt

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/donislawdev/certdoctor/internal/core/status"
	"github.com/donislawdev/certdoctor/internal/tool/jsontext"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// view is what a person is shown, in the order they read a token: what it is,
// when it holds, then its two halves as written.
func (d *decoded) view() []spec.Block {
	blocks := []spec.Block{d.tokenBlock()}
	if b, ok := d.timesBlock(); ok {
		blocks = append(blocks, b)
	}
	blocks = append(blocks, spec.Block{Kind: spec.Code, Title: "Header", Language: "json", Body: d.header.Indent()})
	return append(blocks, d.payloadBlock())
}

// tokenBlock is what kind of token this is and what its header names.
func (d *decoded) tokenBlock() spec.Block {
	fields := []spec.Field{{Label: "Form", Value: d.formWords()}}
	for _, h := range []struct{ name, label string }{
		{"alg", "Algorithm"}, {"enc", "Encryption"}, {"typ", "Type"}, {"cty", "Content type"}, {"kid", "Key ID"},
	} {
		if v, ok := d.header.Get(h.name); ok {
			fields = append(fields, spec.Field{Label: h.label, Value: memberWords(v)})
		}
	}
	if d.tok.form == formJWS {
		fields = append(fields, spec.Field{Label: "Signature", Value: d.signatureWords()})
	}
	fields = append(fields, spec.Field{Label: "Length", Value: plural(int64(d.tok.length), "character")})
	return spec.Block{Kind: spec.Fields, Title: "Token", Fields: fields}
}

func (d *decoded) formWords() string {
	if d.tok.form == formJWE {
		return "Encrypted (JWE), 5 parts"
	}
	if alg, ok := stringMember(d.header, "alg"); ok && strings.EqualFold(alg, "none") {
		return "Unsigned (alg none), 3 parts"
	}
	return "Signed (JWS), 3 parts"
}

func (d *decoded) signatureWords() string {
	if len(d.signature) == 0 {
		return "none"
	}
	return plural(int64(len(d.signature)), "byte") + ", not checked"
}

// memberWords is a header value as a person reads it: a string as itself,
// anything else as JSON.
func memberWords(v jsontext.Value) string {
	if v.Kind == jsontext.String {
		return v.Text
	}
	return v.Compact()
}

// timesBlock is the token's times, each with how far it is from now and the
// verdict on it, when the token has any.
func (d *decoded) timesBlock() (spec.Block, bool) {
	if len(d.times) == 0 {
		return spec.Block{}, false
	}
	verdicts := map[string]status.Status{}
	for _, c := range d.checks {
		verdicts[c.ID] = c.Status
	}
	byClaim := map[string]string{"exp": "expiry", "nbf": "not_before", "iat": "issued_at"}
	var fields []spec.Field
	for _, m := range d.times {
		f := spec.Field{Label: fmt.Sprintf("%s (%s)", m.label, m.claim), Status: verdicts[byClaim[m.claim]]}
		if m.ok {
			f.Value, f.Note = clock(m.at), distance(d.now, m.at)
		} else {
			f.Value, f.Status = "not a time", status.Warn
		}
		fields = append(fields, f)
	}
	return spec.Block{Kind: spec.Fields, Title: "Times", Fields: fields}, true
}

// distance says when a time is, seen from now.
func distance(now, at time.Time) string {
	switch {
	case at.After(now):
		return "in " + span(now, at)
	case at.Before(now):
		return span(now, at) + " ago"
	default:
		return "now"
	}
}

// payloadBlock is the second half of the token, or why it cannot be shown.
func (d *decoded) payloadBlock() spec.Block {
	p := d.payload
	switch {
	case p.encrypted:
		return spec.Block{Kind: spec.Text, Title: "Payload",
			Body: "Encrypted - reading it needs the recipient's key, which this tool does not take."}
	case p.detached:
		return spec.Block{Kind: spec.Text, Title: "Payload",
			Body: "Detached - it travels apart from the token and is not part of it (RFC 7515 appendix F)."}
	case p.isClaims:
		return spec.Block{Kind: spec.Code, Title: "Payload", Language: "json", Body: p.claims.Indent()}
	case !utf8.Valid(p.bytes):
		return spec.Block{Kind: spec.Text, Title: "Payload",
			Body: fmt.Sprintf("%s that are not UTF-8 text, so they are not shown.", plural(int64(len(p.bytes)), "byte"))}
	case p.nested:
		return spec.Block{Kind: spec.Code, Title: "Payload - another token (cty JWT)", Language: "text",
			Body: string(p.bytes)}
	default:
		return spec.Block{Kind: spec.Code, Title: "Payload", Language: "text", Body: string(p.bytes)}
	}
}

// data is what a script reads.
func (d *decoded) data() Data {
	out := Data{Form: "jws"}
	if d.tok.form == formJWE {
		out.Form = "jwe"
	}
	if !d.hasDuplicates("header") {
		out.Header = json.RawMessage(d.header.Compact())
	}
	if d.payload.isClaims && !d.hasDuplicates("payload") {
		out.Payload = json.RawMessage(d.payload.claims.Compact())
	}
	if !d.payload.encrypted && !d.payload.detached {
		n := len(d.payload.bytes)
		out.PayloadBytes = &n
	}
	if d.tok.form == formJWS {
		n := len(d.signature)
		out.SignatureBytes = &n
	}
	for _, m := range d.times {
		if m.ok {
			out.Times.set(m.claim, m.at.Format(time.RFC3339Nano))
		}
	}
	return out
}

func (t *Times) set(claim, at string) {
	switch claim {
	case "iat":
		t.IssuedAt = &at
	case "nbf":
		t.NotBefore = &at
	case "exp":
		t.Expires = &at
	}
}

func (d *decoded) hasDuplicates(in string) bool {
	for _, dup := range d.duplicates {
		if dup.in == in {
			return true
		}
	}
	return false
}

// mostNames is how many duplicated names a warning lists before it counts the
// rest: a hostile token can carry thousands.
const mostNames = 5

// duplicateCheck names the names a token carries twice. RFC 7515 section 4
// and RFC 7519 section 4 let a parser either refuse such a token or take the
// last one, so two libraries can read the same token two ways.
func duplicateCheck(dups []duplicate) (spec.Check, bool) {
	if len(dups) == 0 {
		return spec.Check{}, false
	}
	var names []string
	for i, d := range dups {
		if i == mostNames {
			names = append(names, fmt.Sprintf("%d more", len(dups)-mostNames))
			break
		}
		names = append(names, fmt.Sprintf("%q in the %s%s", d.dup.Name, d.in, at(d.dup.Path)))
	}
	return spec.Check{ID: "duplicate_names", Status: status.Warn,
		Summary: "Carried twice: " + joinNames(names) + ". A library may refuse such a token or take the " +
			"last one (RFC 7515 section 4, RFC 7519 section 4), so two libraries can read it differently."}, true
}

// at says where inside a part an object is, when it is not the part itself.
func at(path string) string {
	if path == "" {
		return ""
	}
	return fmt.Sprintf(" (at %s)", path)
}

// checkOrder is the order checks are listed in after their status: what
// decides whether a token is accepted first.
var checkOrder = []string{
	"algorithm", "signature", "signature_shape", "encrypted", "expiry", "not_before", "issued_at",
	"time_order", "times", "claims", "encoding", "unencoded", "duplicate_names",
}

// sortChecks lists the worst first, and within a status in checkOrder.
func sortChecks(checks []spec.Check) []spec.Check {
	rank := func(c spec.Check) (int, int) {
		severity := len(status.All)
		for i, s := range status.All {
			if s == c.Status {
				severity = i
			}
		}
		for i, id := range checkOrder {
			if id == c.ID {
				return severity, i
			}
		}
		return severity, len(checkOrder)
	}
	sort.SliceStable(checks, func(i, j int) bool {
		si, oi := rank(checks[i])
		sj, oj := rank(checks[j])
		return si < sj || si == sj && oi < oj
	})
	return checks
}
