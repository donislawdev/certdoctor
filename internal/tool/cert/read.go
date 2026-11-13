package cert

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/donislawdev/certdoctor/internal/tool/prose"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// The forms an input is read in, as Data.Form names them.
const (
	formPEM    = "pem"
	formBase64 = "base64"
	formDER    = "der"
	formX5C    = "x5c"
)

// input is what was found in the bytes handed over.
type input struct {
	form    string
	entries []entry
	// skipped are the PEM blocks that are not certificates, private keys
	// among them - by block number and type, never by content.
	skipped []Skipped
	notes   []string
}

// entry is one certificate of the input, read or not.
type entry struct {
	// number counts the certificates of the input from 1, read or not.
	number int
	der    []byte
	cert   *x509.Certificate
	// err is why the library did not read it, when cert is nil.
	err error
}

// isPrivateKey says a PEM block holds a private key, whatever its flavour:
// PRIVATE KEY, RSA PRIVATE KEY, EC PRIVATE KEY, ENCRYPTED PRIVATE KEY and the
// rest all end so. Such a block is never decoded and never shown.
func isPrivateKey(blockType string) bool { return strings.HasSuffix(blockType, "PRIVATE KEY") }

// certificateTypes are the PEM types that hold a certificate. X509
// CERTIFICATE is the old name OpenSSL still reads.
var certificateTypes = map[string]bool{"CERTIFICATE": true, "X509 CERTIFICATE": true, "TRUSTED CERTIFICATE": true}

// read finds the certificates in raw: PEM blocks, a JSON array of base64 (an
// x5c), base64 of one certificate, or DER.
func read(raw []byte) (input, error) {
	if bytes.Contains(raw, []byte("-----BEGIN ")) {
		return readPEM(raw)
	}
	text, notes := unquote(bytes.TrimSpace(raw))
	var in input
	var err error
	switch {
	case len(text) == 0:
		return input{}, refuse("The input is empty - give it a certificate in PEM, base64 or DER.")
	case text[0] == '[':
		in, err = readX5C(text)
	case isBase64(text):
		in, err = readBase64(text)
	case raw[0] == 0x30:
		in = input{form: formDER, entries: []entry{parsed(1, raw)}}
	default:
		return input{}, refuse("The input is not a certificate: it has no PEM block " +
			"(-----BEGIN CERTIFICATE-----), it is not base64 and it is not DER.")
	}
	in.notes = append(notes, in.notes...)
	return in, err
}

// unquote takes off one pair of double quotes around the input - a value
// copied out of JSON - and says so.
func unquote(text []byte) ([]byte, []string) {
	if len(text) >= 2 && text[0] == '"' && text[len(text)-1] == '"' {
		return bytes.TrimSpace(text[1 : len(text)-1]), []string{"Took off the quotes around the input."}
	}
	return text, nil
}

// readPEM reads every PEM block of raw, in order. A PEM copied out of JSON
// carries \n as two characters rather than as line breaks; when nothing reads
// as written, it is read again with them turned into line breaks.
func readPEM(raw []byte) (input, error) {
	in, err := readBlocks(raw)
	escaped := []byte(`\n`)
	if err != nil && bytes.Contains(raw, escaped) {
		if again, againErr := readBlocks(bytes.ReplaceAll(raw, escaped, []byte("\n"))); againErr == nil {
			again.notes = append([]string{`Read each \n written in the text as a line break.`}, again.notes...)
			return again, nil
		}
	}
	return in, err
}

// readBlocks reads the PEM blocks of raw.
func readBlocks(raw []byte) (input, error) {
	in := input{form: formPEM}
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
		in.add(block, b)
		rest = next
	}
	broken := bytes.Count(raw, []byte("-----BEGIN ")) - block
	outside = outside || broken == 0 && len(bytes.TrimSpace(rest)) > 0
	if outside {
		in.notes = append(in.notes, "Text outside the PEM blocks was not read.")
	}
	if broken > 0 {
		in.notes = append(in.notes, fmt.Sprintf("%s that start%s like PEM could not be read: an END line is "+
			"missing or the base64 inside is broken.", prose.Plural(int64(broken), "block"), verbS(broken)))
	}
	if len(in.entries) == 0 {
		return in, nothingToRead(in, broken)
	}
	return in, nil
}

func verbS(n int) string {
	if n == 1 {
		return "s"
	}
	return ""
}

// add takes one PEM block: a certificate is read, anything else is noted by
// its number and type and not decoded.
func (in *input) add(block int, b *pem.Block) {
	switch {
	case certificateTypes[b.Type]:
		der := b.Bytes
		if b.Type == "TRUSTED CERTIFICATE" {
			der = in.trusted(block, der)
		}
		in.entries = append(in.entries, parsed(len(in.entries)+1, der))
	default:
		in.skipped = append(in.skipped, Skipped{Block: block, Type: b.Type})
		in.notes = append(in.notes, fmt.Sprintf("Block %d of the input, %s, was not read%s.", block,
			kindOf(b.Type), shownWords(b.Type)))
	}
}

func shownWords(blockType string) string {
	if isPrivateKey(blockType) {
		return " and is not shown"
	}
	return ""
}

// trusted is the certificate of OpenSSL's TRUSTED CERTIFICATE: the DER of a
// certificate with OpenSSL's trust settings after it, which are not read.
func (in *input) trusted(block int, der []byte) []byte {
	var first asn1.RawValue
	after, err := asn1.Unmarshal(der, &first)
	if err != nil {
		return der
	}
	if len(after) > 0 {
		in.notes = append(in.notes, fmt.Sprintf("Block %d of the input is a TRUSTED CERTIFICATE: its "+
			"certificate was read, and the trust settings OpenSSL keeps after it were not.", block))
	}
	return first.FullBytes
}

// kindsOfBlock are the PEM types a person may paste beside a certificate, in
// words. A type not here is not repeated: it came from the input.
var kindsOfBlock = map[string]string{
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

func kindOf(blockType string) string {
	if isPrivateKey(blockType) {
		return "a private key"
	}
	if words, ok := kindsOfBlock[blockType]; ok {
		return words
	}
	return "a block of a kind this tool does not read"
}

// nothingToRead is the refusal for PEM that held no certificate.
func nothingToRead(in input, broken int) error {
	if len(in.skipped) == 0 {
		return refuse(fmt.Sprintf("The input has %s that start%s like PEM, and none could be read: an END "+
			"line is missing or the base64 inside is broken.", prose.Plural(int64(broken), "block"), verbS(broken)))
	}
	var kinds []string
	for _, s := range in.skipped {
		kinds = append(kinds, kindOf(s.Type))
	}
	return refuse(fmt.Sprintf("The input holds no certificate - its PEM %s %s.",
		pluralWord(len(kinds), "block is", "blocks are"), prose.List(kinds)))
}

func pluralWord(n int, one, more string) string {
	if n == 1 {
		return one
	}
	return more
}

// isBase64 says text is made of base64 characters and line breaks alone, in
// either alphabet. A space is not one of them: base64 of a certificate is
// broken into lines, never into words, and words are not a certificate.
func isBase64(text []byte) bool {
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

// readBase64 reads one certificate given as base64, padded or not, in either
// alphabet - the value of an x5c member, or a .cer saved without its lines.
func readBase64(text []byte) (input, error) {
	der, ok := decodeBase64(string(text))
	if !ok {
		return input{}, refuse("The input has no PEM block (-----BEGIN CERTIFICATE-----) and does not decode " +
			"as base64.")
	}
	return input{form: formBase64, entries: []entry{parsed(1, der)}}, nil
}

func decodeBase64(text string) ([]byte, bool) {
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

// readX5C reads a JSON array of base64 certificates - the x5c member of a
// JWK or a JWT header (RFC 7517 section 4.7, standard base64, first the one
// that holds the key).
func readX5C(text []byte) (input, error) {
	var values []string
	if err := json.Unmarshal(text, &values); err != nil || len(values) == 0 {
		return input{}, refuse("The input starts with [ but is not a JSON array of base64 certificates " +
			"(an x5c), or the array is empty.")
	}
	in := input{form: formX5C}
	for i, v := range values {
		der, ok := decodeBase64(v)
		if !ok {
			in.entries = append(in.entries, entry{number: i + 1, err: errNotBase64})
			continue
		}
		in.entries = append(in.entries, parsed(i+1, der))
	}
	return in, nil
}

// errNotBase64 is why an x5c member was not read.
var errNotBase64 = errors.New("it is not base64")

// parsed is the entry for der, read by the library or with why it was not.
func parsed(number int, der []byte) entry {
	c, err := x509.ParseCertificate(der)
	return entry{number: number, der: der, cert: c, err: err}
}

func refuse(reason string) error { return &spec.Refusal{Reason: reason} }
