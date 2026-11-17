// Package csr is the certificate request decoder (ADR154): it shows what a
// PKCS #10 certificate signing request asks for - its subject and names, its
// key, the extensions it requests - and judges what can be judged from the
// request alone: whether its own key verifies its signature, and what in it a
// public authority refuses or ignores.
//
// IT CONNECTS TO NOTHING AND ASKS NO AUTHORITY. Which names an authority
// issues for depends on who controls them, which only the authority finds
// out; the rules here are the spelling and shape the CA/Browser Forum's
// Baseline Requirements set for a public authority's TLS certificates, and
// each sentence says so, because a private authority may issue what a public
// one may not (the owner's decision in ADR154).
//
// THE INPUT IS HOSTILE. A refusal names what it found by kind and position,
// never by content. A private key that came along is not read, and a
// challenge password inside the request is noticed by its identifier and its
// value is never decoded (RFC 2985 section 5.4.1 calls it a password).
package csr

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/donislawdev/certdoctor/internal/tool/derinput"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// Data is what the decoder found, for a script to read.
type Data struct {
	// Form is how the input was read: pem, base64 or der.
	Form    string             `json:"form"`
	Request Request            `json:"request"`
	Skipped []derinput.Skipped `json:"skipped"`
}

// Request is the request as Data carries it. The names the certificate
// decoder uses - subject, dns_names, public_key, spki_sha256 and the rest -
// mean the same here; every list is an empty array rather than null.
type Request struct {
	// Version is the version field as written: 0 for PKCS #10 version 1.
	Version        int      `json:"version"`
	Subject        string   `json:"subject"`
	DNSNames       []string `json:"dns_names"`
	IPAddresses    []string `json:"ip_addresses"`
	EmailAddresses []string `json:"email_addresses"`
	URIs           []string `json:"uris"`
	// PublicKey is the key a certificate issued for the request carries.
	PublicKey  PublicKey `json:"public_key"`
	SPKISHA256 string    `json:"spki_sha256"`
	// SignatureAlgorithm is the algorithm's name, or its identifier when the
	// library does not know it.
	SignatureAlgorithm string `json:"signature_algorithm"`
	// SignatureValid says the request's own key verifies its signature, and is
	// null when the signature was not checked.
	SignatureValid *bool `json:"signature_valid"`
	// KeyUsage, ExtendedKeyUsage, IsCA and MaxPathLength are what the request
	// asks for, which an authority may grant or not.
	KeyUsage         []string `json:"key_usage"`
	ExtendedKeyUsage []string `json:"extended_key_usage"`
	IsCA             bool     `json:"is_ca"`
	MaxPathLength    *int     `json:"max_path_length"`
	// Extensions are the extensions the request asks for, by identifier.
	Extensions []Extension `json:"extensions"`
	// Attributes are the identifiers of the request's attributes, in order -
	// never their values.
	Attributes []string `json:"attributes"`
	// ChallengePassword says the request carries a challenge password, and is
	// null when its attributes could not all be read.
	ChallengePassword *bool `json:"challenge_password"`
}

// Extension is one requested extension, by identifier.
type Extension struct {
	ID       string `json:"id"`
	Critical bool   `json:"critical"`
}

// Decode reads raw as a certificate request and judges it. A refusal is a
// *spec.Refusal and means raw holds no request this can read.
func Decode(raw []byte) (spec.Outcome, error) {
	in, err := read(raw)
	if err != nil {
		return spec.Outcome{}, err
	}
	j := judge(in)
	return spec.Outcome{Notes: j.notes(), Checks: spec.SortChecks(j.checks(), checkOrder), Data: j.data(),
		View: j.view()}, nil
}

// checkOrder is the order checks of one status are listed in: the signature
// and the key, then the names, then what the request carries beside them.
var checkOrder = []string{
	"signature", "key_size", "key_type", "subject_alt_name", "names", "common_name", "challenge_password",
	"private_key", "version",
}

// requestTypes are the PEM types that hold a request. NEW CERTIFICATE REQUEST
// is the label RFC 7468 section 7 calls "in wide use" - Windows' certreq and
// Java's keytool write it - and lets a parser read as CERTIFICATE REQUEST.
var requestTypes = map[string]bool{"CERTIFICATE REQUEST": true, "NEW CERTIFICATE REQUEST": true}

// requests is what this tool reads, for the shared reader.
var requests = derinput.Kind{
	Thing:  "certificate request",
	Header: "-----BEGIN CERTIFICATE REQUEST-----",
	Reads: func(_ int, b *pem.Block) ([]byte, string, bool) {
		return b.Bytes, "", requestTypes[b.Type]
	},
}

// input is the request found, and what came with it.
type input struct {
	form    string
	der     []byte
	csr     *x509.CertificateRequest
	skipped []derinput.Skipped
	notes   []string
}

// read finds the first request in raw and reads it.
func read(raw []byte) (input, error) {
	found, err := requests.Read(raw)
	if err != nil {
		return input{}, err
	}
	in := input{form: found.Form, der: found.Objects[0], skipped: found.Skipped, notes: found.Notes}
	if n := len(found.Objects); n > 1 {
		in.notes = append(in.notes, fmt.Sprintf("The input holds %d certificate requests. The first was read - "+
			"this tool reads one request at a time.", n))
	}
	c, err := x509.ParseCertificateRequest(in.der)
	if err != nil {
		return input{}, unreadable(in, err)
	}
	in.csr = c
	return in, nil
}

// unreadable is the refusal for a request the library does not read, in its
// words, which describe the request's shape.
//
// ONLY WHAT SAYS IT IS A REQUEST IS CALLED ONE, as in the certificate decoder:
// base64 and DER are named by how they were read, because a word typed by
// mistake gets that far too. A certificate handed over instead is sent to the
// tool that reads it - known by the library reading it as one, never by text.
func unreadable(in input, err error) error {
	if in.form != derinput.FormPEM {
		if _, certErr := x509.ParseCertificate(in.der); certErr == nil {
			return derinput.Refuse("The input is a certificate, not a certificate request - certdoctor tool cert " +
				"reads it.")
		}
	}
	words := libraryWords(err)
	switch in.form {
	case derinput.FormBase64:
		return derinput.Refuse(fmt.Sprintf("The input decodes as base64, but not to a certificate request this "+
			"program's X.509 library can read: %s.", words))
	case derinput.FormDER:
		return derinput.Refuse(fmt.Sprintf("The input starts like DER, but is not a certificate request this "+
			"program's X.509 library can read: %s.", words))
	}
	return derinput.Refuse(fmt.Sprintf("The input holds a certificate request this program's X.509 library "+
		"cannot read: %s.", words))
}
