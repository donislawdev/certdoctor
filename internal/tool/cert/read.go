package cert

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/donislawdev/certdoctor/internal/tool/derinput"
)

// The forms an input is read in, as Data.Form names them. Three are the
// shared reader's, x5c is this tool's own.
const (
	formPEM    = derinput.FormPEM
	formBase64 = derinput.FormBase64
	formDER    = derinput.FormDER
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

// certificateTypes are the PEM types that hold a certificate. X509
// CERTIFICATE is the old name OpenSSL still reads.
var certificateTypes = map[string]bool{"CERTIFICATE": true, "X509 CERTIFICATE": true, "TRUSTED CERTIFICATE": true}

// certificateKind is what this tool reads, for the shared reader: PEM blocks,
// a JSON array of base64 (an x5c), base64 of one certificate, or DER.
var certificateKind = derinput.Kind{
	Thing:  "certificate",
	Header: "-----BEGIN CERTIFICATE-----",
	Reads: func(block int, b *pem.Block) ([]byte, string, bool) {
		if !certificateTypes[b.Type] {
			return nil, "", false
		}
		if b.Type == "TRUSTED CERTIFICATE" {
			der, note := trusted(block, b.Bytes)
			return der, note, true
		}
		return b.Bytes, "", true
	},
	Bare: func(text []byte) (derinput.Input, bool, error) {
		if text[0] != '[' {
			return derinput.Input{}, false, nil
		}
		in, err := readX5C(text)
		return in, true, err
	},
}

// read finds the certificates in raw and reads each one.
func read(raw []byte) (input, error) {
	found, err := certificateKind.Read(raw)
	in := input{form: found.Form, notes: found.Notes}
	for _, s := range found.Skipped {
		in.skipped = append(in.skipped, Skipped(s))
	}
	if err != nil {
		return in, err
	}
	for i, der := range found.Objects {
		if der == nil {
			in.entries = append(in.entries, entry{number: i + 1, err: errNotBase64})
			continue
		}
		in.entries = append(in.entries, parsed(i+1, der))
	}
	return in, nil
}

// trusted is the certificate of OpenSSL's TRUSTED CERTIFICATE: the DER of a
// certificate with OpenSSL's trust settings after it, which are not read.
func trusted(block int, der []byte) ([]byte, string) {
	var first asn1.RawValue
	after, err := asn1.Unmarshal(der, &first)
	if err != nil {
		return der, ""
	}
	if len(after) > 0 {
		return first.FullBytes, fmt.Sprintf("Block %d of the input is a TRUSTED CERTIFICATE: its certificate was "+
			"read, and the trust settings OpenSSL keeps after it were not.", block)
	}
	return first.FullBytes, ""
}

// readX5C reads a JSON array of base64 certificates - the x5c member of a
// JWK or a JWT header (RFC 7517 section 4.7, standard base64, first the one
// that holds the key). A member that is not base64 is kept as nil, so it is
// counted and named as unreadable.
func readX5C(text []byte) (derinput.Input, error) {
	var values []string
	if err := json.Unmarshal(text, &values); err != nil || len(values) == 0 {
		return derinput.Input{}, derinput.Refuse("The input starts with [ but is not a JSON array of base64 " +
			"certificates (an x5c), or the array is empty.")
	}
	in := derinput.Input{Form: formX5C}
	for _, v := range values {
		der, ok := derinput.DecodeBase64(v)
		if !ok {
			der = nil
		}
		in.Objects = append(in.Objects, der)
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

// isRequest says der is a certificate request this program's X.509 library
// reads - asked only of bytes it did not read as a certificate, so a request
// handed to this tool is sent to the one that reads it, by its structure and
// never by its text.
func isRequest(der []byte) bool {
	_, err := x509.ParseCertificateRequest(der)
	return err == nil
}

func refuse(reason string) error { return derinput.Refuse(reason) }
