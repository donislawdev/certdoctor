package jwt

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/donislawdev/certdoctor/internal/core/status"
	"github.com/donislawdev/certdoctor/internal/tool/jsontext"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// form is which of the two compact forms a token is in.
type form int

const (
	formJWS form = iota
	formJWE
)

// token is the text of a token cut into its parts, with what was done to the
// text first and what was loose about the parts' encoding.
type token struct {
	form   form
	parts  []string
	length int
	notes  []string
	issues []partIssue
}

// partIssue is what one part's base64 does that base64url in a JWS does not.
type partIssue struct {
	part     int
	padded   bool
	standard bool
	loose    bool
}

// refuse is a refusal of the input, said after "the token".
func refuse(format string, args ...any) error {
	return &spec.Refusal{Reason: "the token " + fmt.Sprintf(format, args...)}
}

// prepare takes off what people paste around a token, checks that what is
// left is made of the characters a token is made of, and cuts it into parts.
func prepare(raw []byte) (token, error) {
	text, notes := unwrap(string(raw))
	if text == "" {
		return token{}, refuse("is empty - there is nothing to decode")
	}
	if err := checkCharacters(text); err != nil {
		return token{}, err
	}
	t := token{parts: strings.Split(text, "."), length: len(text), notes: notes}
	switch len(t.parts) {
	case 3:
		t.form = formJWS
	case 5:
		t.form = formJWE
	default:
		return token{}, refuse("has %d part(s) separated by dots - a signed token has 3 "+
			"(RFC 7515 section 7.1) and an encrypted one 5 (RFC 7516 section 9)", len(t.parts))
	}
	return t, nil
}

// unwrap takes off a header name, the word Bearer and quotes - the three
// things a token is most often copied with - and says which it took off.
func unwrap(s string) (string, []string) {
	var notes []string
	s = strings.TrimSpace(s)
	if rest, ok := cutPrefixFold(s, "authorization:"); ok {
		s = strings.TrimSpace(rest)
		notes = append(notes, `Took off "Authorization:" in front of the token.`)
	}
	if rest, ok := cutPrefixFold(s, "bearer"); ok && rest != "" && (rest[0] == ' ' || rest[0] == '\t') {
		s = strings.TrimSpace(rest)
		notes = append(notes, `Took off "Bearer" in front of the token.`)
	}
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		s = s[1 : len(s)-1]
		notes = append(notes, "Took off the quotes around the token.")
	}
	return s, notes
}

// cutPrefixFold is strings.CutPrefix, ignoring the case of ASCII letters.
func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) < len(prefix) || !strings.EqualFold(s[:len(prefix)], prefix) {
		return s, false
	}
	return s[len(prefix):], true
}

// checkCharacters refuses a byte no token has. A token is base64url and dots;
// + / and = are let through here so that standard base64 and padding can be
// named for what they are rather than refused as strangers.
func checkCharacters(s string) error {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case tokenByte(c):
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			return refuse("has a space or a line break at byte %d - a token has none (RFC 7515 section 2)", i+1)
		default:
			return refuse("has a byte at position %d that no token has - only letters, digits, - and _, "+
				"with dots between the parts", i+1)
		}
	}
	return nil
}

func tokenByte(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' ||
		c == '-' || c == '_' || c == '.' || c == '+' || c == '/' || c == '='
}

// decodePart decodes part i, counted from zero, and remembers what was loose
// about it. Standard base64 and padding are read and named rather than
// refused: libraries differ on them, and naming that is the point.
func (t *token) decodePart(i int) ([]byte, error) {
	issue := partIssue{part: i + 1}
	text := strings.TrimRight(t.parts[i], "=")
	issue.padded = len(text) != len(t.parts[i])
	if strings.Contains(text, "=") {
		return nil, refuse("has '=' inside part %d - padding can only end a part", i+1)
	}
	issue.standard = strings.ContainsAny(text, "+/")
	if issue.standard && strings.ContainsAny(text, "-_") {
		return nil, refuse("mixes the URL-safe alphabet with the one of standard base64 in part %d - "+
			"no base64 reads both", i+1)
	}
	enc := base64.RawURLEncoding
	if issue.standard {
		enc = base64.RawStdEncoding
	}
	b, err := enc.Strict().DecodeString(text)
	if err != nil {
		b, err = enc.DecodeString(text)
		issue.loose = err == nil
	}
	if err != nil {
		return nil, refuse("has part %d that is not base64url%s", i+1, where(err))
	}
	if issue.padded || issue.standard || issue.loose {
		t.issues = append(t.issues, issue)
	}
	return b, nil
}

// where says at which character of a part base64 stopped.
func where(err error) string {
	var corrupt base64.CorruptInputError
	if errors.As(err, &corrupt) {
		return fmt.Sprintf(" (it stops at character %d)", int64(corrupt)+1)
	}
	return ""
}

// encodingChecks is one warning naming every part whose base64 a strict
// library refuses.
func (t token) encodingChecks() []spec.Check {
	if len(t.issues) == 0 {
		return nil
	}
	var said []string
	for _, is := range t.issues {
		said = append(said, is.words())
	}
	return []spec.Check{{
		ID:     "encoding",
		Status: status.Warn,
		Summary: "The token " + strings.Join(said, ", and ") + ". A JWS is base64url without padding " +
			"(RFC 7515 section 2), so a strict library refuses this token and a lenient one reads it.",
	}}
}

// words is what one part does, after "the token".
func (is partIssue) words() string {
	var what []string
	if is.padded {
		what = append(what, "is padded with =")
	}
	if is.standard {
		what = append(what, "uses + or / of standard base64")
	}
	if is.loose {
		what = append(what, "ends in bits that should be zero")
	}
	return fmt.Sprintf("has part %d that %s", is.part, strings.Join(what, " and "))
}

// readHeader decodes and reads the first part, which in both forms is the
// header as a JSON object (RFC 7515 section 7.1, RFC 7516 section 7.1).
func (t *token) readHeader() (jsontext.Value, []jsontext.Duplicate, error) {
	raw, err := t.decodePart(0)
	if err != nil {
		return jsontext.Value{}, nil, err
	}
	v, dups, err := jsontext.Parse(raw)
	if err != nil {
		return jsontext.Value{}, nil, refuse("has a header (part 1) that %s", err)
	}
	if v.Kind != jsontext.Object {
		return jsontext.Value{}, nil, refuse("has a header (part 1) that is JSON but not an object")
	}
	return v, dups, nil
}
