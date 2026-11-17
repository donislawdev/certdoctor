// Package derinput reads the bytes a tool is handed as the DER objects in
// them, the way a person hands such an object over: PEM blocks, perhaps with
// other blocks and text around them, else base64 of one object, else its DER.
// More than one tool reads that shape - the certificate decoder and the CSR
// decoder - so the reading, its notes and its refusals have this one place
// (ADR154).
//
// IT DECODES NOTHING. Which PEM types a tool reads, and what the DER means, is
// the tool's: this package finds the bytes, says what it did to get them, and
// names what it left out by kind and position - never by content, because the
// input may be a credential (ADR141 point 9). A private key that came along is
// never decoded and never shown.
package derinput

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/donislawdev/certdoctor/internal/core/status"
	"github.com/donislawdev/certdoctor/internal/tool/prose"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// The forms an input is read in, as a tool's data names them.
const (
	FormPEM    = "pem"
	FormBase64 = "base64"
	FormDER    = "der"
)

// Kind is what one tool reads.
type Kind struct {
	// Thing names the object in a refusal, without an article: "certificate",
	// "certificate request".
	Thing string
	// Header is the PEM line a person is told to look for:
	// "-----BEGIN CERTIFICATE-----".
	Header string
	// Reads says whether the tool reads a PEM block, and gives the DER it
	// reads in it with a note when it read only part of the block. Every
	// block it does not read is listed as skipped.
	Reads func(block int, b *pem.Block) (der []byte, note string, ok bool)
	// Bare reads text that has no PEM block in a form only this tool knows -
	// the certificate decoder's x5c array - and says whether it did. It is
	// asked after the quotes are off and before base64 is tried.
	Bare func(text []byte) (Input, bool, error)
}

// Input is what was found in the bytes handed over.
type Input struct {
	Form string
	// Objects are the DER of the objects the tool reads, in input order.
	Objects [][]byte
	// Skipped are the PEM blocks the tool does not read, private keys among
	// them - by block number and type, never by content.
	Skipped []Skipped
	Notes   []string
}

// Skipped is a PEM block that was not read, by its number among the blocks
// and its type.
type Skipped struct {
	Block int    `json:"block"`
	Type  string `json:"type"`
}

// Read finds the objects of k in raw. A refusal is a *spec.Refusal.
func (k Kind) Read(raw []byte) (Input, error) {
	if bytes.Contains(raw, []byte("-----BEGIN ")) {
		return k.readPEM(raw)
	}
	text, notes := Unquote(bytes.TrimSpace(raw))
	var in Input
	var err error
	handled := false
	if len(text) == 0 {
		return Input{}, Refuse(fmt.Sprintf("The input is empty - give it a %s in PEM, base64 or DER.", k.Thing))
	}
	if k.Bare != nil {
		in, handled, err = k.Bare(text)
	}
	switch {
	case handled:
	case IsBase64(text):
		in, err = k.readBase64(text)
	case raw[0] == 0x30:
		in = Input{Form: FormDER, Objects: [][]byte{raw}}
	default:
		return Input{}, Refuse(fmt.Sprintf("The input is not a %s: it has no PEM block (%s), it is not base64 "+
			"and it is not DER.", k.Thing, k.Header))
	}
	in.Notes = append(notes, in.Notes...)
	return in, err
}

// Unquote takes off one pair of double quotes around the input - a value
// copied out of JSON - and says so.
func Unquote(text []byte) ([]byte, []string) {
	if len(text) >= 2 && text[0] == '"' && text[len(text)-1] == '"' {
		return bytes.TrimSpace(text[1 : len(text)-1]), []string{"Took off the quotes around the input."}
	}
	return text, nil
}

// readPEM reads every PEM block of raw, in order. A PEM copied out of JSON
// carries \n as two characters rather than as line breaks; when nothing reads
// as written, it is read again with them turned into line breaks.
func (k Kind) readPEM(raw []byte) (Input, error) {
	in, err := k.readBlocks(raw)
	escaped := []byte(`\n`)
	if err != nil && bytes.Contains(raw, escaped) {
		if again, againErr := k.readBlocks(bytes.ReplaceAll(raw, escaped, []byte("\n"))); againErr == nil {
			again.Notes = append([]string{`Read each \n written in the text as a line break.`}, again.Notes...)
			return again, nil
		}
	}
	return in, err
}

// readBlocks reads the PEM blocks of raw.
func (k Kind) readBlocks(raw []byte) (Input, error) {
	in := Input{Form: FormPEM}
	rest, block, outside := raw, 0, false
	for {
		b, next := pem.Decode(rest)
		if b == nil {
			break
		}
		block++
		consumed := rest[:len(rest)-len(next)]
		start := bytes.Index(consumed, []byte("-----BEGIN "+b.Type+"-----"))
		outside = outside || start > 0 && len(bytes.TrimSpace(consumed[:start])) > 0
		k.add(&in, block, b)
		rest = next
	}
	broken := bytes.Count(raw, []byte("-----BEGIN ")) - block
	outside = outside || broken == 0 && len(bytes.TrimSpace(rest)) > 0
	if outside {
		in.Notes = append(in.Notes, "Text outside the PEM blocks was not read.")
	}
	if broken > 0 {
		in.Notes = append(in.Notes, fmt.Sprintf("%s that start%s like PEM could not be read: an END line is "+
			"missing or the base64 inside is broken.", prose.Plural(int64(broken), "block"), verbS(broken)))
	}
	if len(in.Objects) == 0 {
		return in, k.nothingToRead(in, broken)
	}
	return in, nil
}

func verbS(n int) string {
	if n == 1 {
		return "s"
	}
	return ""
}

// add takes one PEM block: an object the tool reads is kept, anything else is
// noted by its number and type and not decoded.
func (k Kind) add(in *Input, block int, b *pem.Block) {
	if der, note, ok := k.Reads(block, b); ok {
		in.Objects = append(in.Objects, der)
		if note != "" {
			in.Notes = append(in.Notes, note)
		}
		return
	}
	in.Skipped = append(in.Skipped, Skipped{Block: block, Type: b.Type})
	in.Notes = append(in.Notes, fmt.Sprintf("Block %d of the input, %s, was not read%s.", block,
		KindOf(b.Type), elsewhere(b.Type)))
}

// IsPrivateKey says a PEM block holds a private key, whatever its flavour:
// PRIVATE KEY, RSA PRIVATE KEY, EC PRIVATE KEY, ENCRYPTED PRIVATE KEY and the
// rest all end so. Such a block is never decoded and never shown.
func IsPrivateKey(blockType string) bool { return strings.HasSuffix(blockType, "PRIVATE KEY") }

// kindsOfBlock are the PEM types a person may paste beside the object a tool
// reads, in words. A type not here is not repeated: it came from the input.
// NEW CERTIFICATE REQUEST is the label RFC 7468 section 7 calls "in wide use"
// and lets a parser read as CERTIFICATE REQUEST; X509 CERTIFICATE is the old
// name OpenSSL still reads.
var kindsOfBlock = map[string]string{
	"CERTIFICATE":             "a certificate",
	"X509 CERTIFICATE":        "a certificate",
	"TRUSTED CERTIFICATE":     "a certificate",
	"CERTIFICATE REQUEST":     "a certificate request (CSR)",
	"NEW CERTIFICATE REQUEST": "a certificate request (CSR)",
	"X509 CRL":                "a revocation list (CRL)",
	"PUBLIC KEY":              "a public key",
	"RSA PUBLIC KEY":          "a public key",
	"PKCS7":                   "a PKCS #7 bundle",
	"CMS":                     "a PKCS #7 bundle",
	"DH PARAMETERS":           "key parameters",
	"EC PARAMETERS":           "key parameters",
}

// ReadBy names the tool that reads a block of each type another tool skips,
// so a person who pasted a request into the certificate decoder is told where
// it goes. Every id here is a tool of spec.All - a test holds that.
var ReadBy = map[string]string{
	"CERTIFICATE":             "cert",
	"X509 CERTIFICATE":        "cert",
	"TRUSTED CERTIFICATE":     "cert",
	"CERTIFICATE REQUEST":     "csr",
	"NEW CERTIFICATE REQUEST": "csr",
}

// KindOf is a PEM type in words.
func KindOf(blockType string) string {
	if IsPrivateKey(blockType) {
		return "a private key"
	}
	if words, ok := kindsOfBlock[blockType]; ok {
		return words
	}
	return "a block of a kind this tool does not read"
}

// elsewhere ends a note on a skipped block: a private key is not shown, and
// an object another tool reads is sent to it.
func elsewhere(blockType string) string {
	if IsPrivateKey(blockType) {
		return " and is not shown"
	}
	if tool, ok := ReadBy[blockType]; ok {
		return " - certdoctor tool " + tool + " reads it"
	}
	return ""
}

// nothingToRead is the refusal for PEM that held nothing the tool reads.
func (k Kind) nothingToRead(in Input, broken int) error {
	if len(in.Skipped) == 0 {
		return Refuse(fmt.Sprintf("The input has %s that start%s like PEM, and none could be read: an END "+
			"line is missing or the base64 inside is broken.", prose.Plural(int64(broken), "block"), verbS(broken)))
	}
	var kinds, sent []string
	seen := map[string]bool{}
	for _, s := range in.Skipped {
		kinds = append(kinds, KindOf(s.Type))
		if tool, ok := ReadBy[s.Type]; ok && !seen[tool] {
			seen[tool] = true
			sent = append(sent, fmt.Sprintf(" certdoctor tool %s reads %s.", tool, KindOf(s.Type)))
		}
	}
	return Refuse(fmt.Sprintf("The input holds no %s - its PEM %s %s.%s", k.Thing,
		pluralWord(len(kinds), "block is", "blocks are"), prose.List(kinds), strings.Join(sent, "")))
}

func pluralWord(n int, one, more string) string {
	if n == 1 {
		return one
	}
	return more
}

// IsBase64 says text is made of base64 characters and line breaks alone, in
// either alphabet. A space is not one of them: base64 of an object is broken
// into lines, never into words, and words are not an object.
func IsBase64(text []byte) bool {
	for _, c := range text {
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9':
		case c == '+', c == '/', c == '-', c == '_', c == '=', c == '\r', c == '\n':
		default:
			return false
		}
	}
	return true
}

// readBase64 reads one object given as base64, padded or not, in either
// alphabet - a .cer saved without its lines, or a value copied out of a form.
func (k Kind) readBase64(text []byte) (Input, error) {
	der, ok := DecodeBase64(string(text))
	if !ok {
		return Input{}, Refuse(fmt.Sprintf("The input has no PEM block (%s) and does not decode as base64.",
			k.Header))
	}
	return Input{Form: FormBase64, Objects: [][]byte{der}}, nil
}

// DecodeBase64 decodes base64 in any of its four spellings, white space
// ignored.
func DecodeBase64(text string) ([]byte, bool) {
	clean := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, text)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding,
		base64.RawURLEncoding} {
		if der, err := enc.Strict().DecodeString(clean); err == nil {
			return der, true
		}
	}
	return nil, false
}

// PrivateKeyCheck is the check private_key of a tool reading this shape: a
// warning naming the blocks that held a private key, which were never read,
// and nothing when there were none.
func PrivateKeyCheck(skipped []Skipped) (spec.Check, bool) {
	var blocks []string
	for _, s := range skipped {
		if IsPrivateKey(s.Type) {
			blocks = append(blocks, fmt.Sprint(s.Block))
		}
	}
	if len(blocks) == 0 {
		return spec.Check{}, false
	}
	return spec.Check{ID: "private_key", Status: status.Warn, Summary: fmt.Sprintf("%s %s of the input %s a "+
		"private key. It was not read and is not shown here - a private key belongs on the machine that uses it, "+
		"and a file that carries one should not be handed around.", pluralWord(len(blocks), "Block", "Blocks"),
		prose.List(blocks), pluralWord(len(blocks), "is", "are each"))}, true
}

// Refuse is a tool's refusal of its input.
func Refuse(reason string) error { return &spec.Refusal{Reason: reason} }
