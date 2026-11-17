package csr

import (
	"fmt"
	"strings"

	"github.com/donislawdev/certdoctor/internal/core/status"
	"github.com/donislawdev/certdoctor/internal/tool/certfacts"
	"github.com/donislawdev/certdoctor/internal/tool/derinput"
	"github.com/donislawdev/certdoctor/internal/tool/prose"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// PublicKey is the request's key - the shape the tools share.
type PublicKey = certfacts.PublicKey

// data is what was found, for a script.
func (j judged) data() Data {
	c := j.c
	r := Request{
		Version:            c.Version,
		Subject:            certfacts.Name(c.Subject),
		DNSNames:           append([]string{}, c.DNSNames...),
		IPAddresses:        addresses(c),
		EmailAddresses:     append([]string{}, c.EmailAddresses...),
		URIs:               uris(c),
		PublicKey:          certfacts.Key(c.PublicKey, c.PublicKeyAlgorithm),
		SPKISHA256:         certfacts.SPKIPin(c.RawSubjectPublicKeyInfo),
		SignatureAlgorithm: certfacts.SignatureAlgorithm(c.Raw, c.SignatureAlgorithm),
		SignatureValid:     j.valid,
		KeyUsage:           certfacts.KeyUsages(j.req.keyUsage),
		ExtendedKeyUsage:   certfacts.ExtendedKeyUsages(j.req.known, j.req.unknown),
		IsCA:               j.req.isCA,
		MaxPathLength:      j.req.pathLength(),
		Extensions:         []Extension{},
		Attributes:         []string{},
	}
	for _, e := range c.Extensions {
		r.Extensions = append(r.Extensions, Extension{ID: e.Id.String(), Critical: e.Critical})
	}
	for _, oid := range j.attrs.oids {
		r.Attributes = append(r.Attributes, oid.String())
	}
	if j.attrs.readable {
		password := j.attrs.password
		r.ChallengePassword = &password
	}
	return Data{Form: j.in.form, Request: r, Skipped: append([]derinput.Skipped{}, j.in.skipped...)}
}

// formWords says how the input was read.
var formWords = map[string]string{
	derinput.FormPEM:    "PEM",
	derinput.FormBase64: "base64 of one request",
	derinput.FormDER:    "DER, one request",
}

// view is what a person is shown: the input as a whole, then the request.
func (j judged) view() []spec.Block {
	input := []spec.Field{{Label: "Read as", Value: formWords[j.in.form]}}
	if len(j.in.skipped) > 0 {
		var left []string
		for _, s := range j.in.skipped {
			left = append(left, fmt.Sprintf("block %d, %s", s.Block, derinput.KindOf(s.Type)))
		}
		input = append(input, spec.Field{Label: "Not read", Value: strings.Join(left, "; ")})
	}
	fields := append(j.identity(), j.key()...)
	fields = append(fields, j.asked()...)
	return []spec.Block{
		{Kind: spec.Fields, Title: "Input", Fields: input},
		// The title is plain: a surface may set titles in capitals, and the
		// Subject row names the request.
		{Kind: spec.Fields, Title: "Request", Fields: fields},
	}
}

// identity is who the request is for and the names it asks for.
func (j judged) identity() []spec.Field {
	c := j.c
	checks := j.byID()
	fields := []spec.Field{{Label: "Subject", Value: orNone(certfacts.Name(c.Subject)),
		Status: notPass(checks["common_name"])}}
	if len(c.DNSNames) > 0 || j.tls {
		fields = append(fields, spec.Field{Label: "Host names", Value: orNone(strings.Join(c.DNSNames, ", ")),
			Status: worse(checks["subject_alt_name"], checks["names"])})
	}
	for _, more := range []struct {
		label  string
		values []string
	}{{"Addresses", addresses(c)}, {"E-mail", c.EmailAddresses}, {"URIs", uris(c)}} {
		if len(more.values) > 0 {
			fields = append(fields, spec.Field{Label: more.label, Value: strings.Join(more.values, ", ")})
		}
	}
	return fields
}

// key is the request's key, the pin a certificate for it will share, and
// what came of its signature.
func (j judged) key() []spec.Field {
	checks := j.byID()
	signature := spec.Field{Label: "Signature", Value: certfacts.SignatureAlgorithm(j.c.Raw, j.c.SignatureAlgorithm),
		Status: notPass(checks["signature"])}
	switch {
	case j.valid == nil:
		signature.Note = "not checked"
	case *j.valid:
		signature.Note = "verified with its own key"
	default:
		signature.Note = "does not verify with its own key"
	}
	return []spec.Field{
		{Label: "Key", Value: keyOf(j.c).Words(), Status: worse(checks["key_size"], checks["key_type"])},
		{Label: "SPKI pin", Value: certfacts.SPKIPin(j.c.RawSubjectPublicKeyInfo),
			Note: "SHA-256, the same in the certificate issued"},
		signature,
		{Label: "Version", Value: fmt.Sprint(j.c.Version), Status: notPass(checks["version"])},
	}
}

// asked is what the request asks for beyond its names, and what it carries.
func (j judged) asked() []spec.Field {
	var fields []spec.Field
	if j.req.basic {
		fields = append(fields, spec.Field{Label: "Authority", Value: authorityWords(j.req)})
	}
	if u := certfacts.KeyUsages(j.req.keyUsage); len(u) > 0 {
		fields = append(fields, spec.Field{Label: "Key usage", Value: strings.Join(u, ", ")})
	}
	if u := certfacts.ExtendedKeyUsages(j.req.known, j.req.unknown); len(u) > 0 {
		fields = append(fields, spec.Field{Label: "Extended key usage", Value: strings.Join(u, ", ")})
	}
	var extensions []string
	for _, e := range j.c.Extensions {
		name := e.Id.String()
		if words, ok := extensionNames[name]; ok {
			name = words
		}
		if e.Critical {
			name += " (critical)"
		}
		extensions = append(extensions, name)
	}
	if len(extensions) > 0 {
		fields = append(fields, spec.Field{Label: "Extensions asked for", Value: strings.Join(extensions, ", ")})
	}
	var attributes []string
	for _, oid := range j.attrs.oids {
		name := oid.String()
		if words, ok := attributeNames[name]; ok {
			name = words
		}
		if oid.Equal(oidChallengePassword) {
			name += " (present, not shown)"
		}
		attributes = append(attributes, name)
	}
	if len(attributes) > 0 {
		checks := j.byID()
		fields = append(fields, spec.Field{Label: "Attributes", Value: strings.Join(attributes, ", "),
			Status: notPass(checks["challenge_password"])})
	}
	return fields
}

// authorityWords says what the request asks about being an authority (RFC
// 5280 section 4.2.1.9).
func authorityWords(r requested) string {
	below := r.pathLength()
	switch {
	case !r.isCA:
		return "asks not to be one"
	case below == nil:
		return "asks to be one, with no limit on authorities below it"
	case *below == 0:
		return "asks to be one, with no authority below it"
	}
	return fmt.Sprintf("asks to be one, with at most %s below it", prose.Plural(int64(*below), "authority"))
}

// byID is the status of each check, for the rows that carry one.
func (j judged) byID() map[string]status.Status {
	out := map[string]status.Status{"signature": j.signature.Status}
	for _, c := range j.checks() {
		out[c.ID] = c.Status
	}
	return out
}

// notPass is a row's mark: nothing on a pass, the status otherwise.
func notPass(s status.Status) status.Status {
	if s == status.Pass {
		return ""
	}
	return s
}

// worse is the worse of two checks' marks, by the order of status.All.
func worse(a, b status.Status) status.Status {
	for _, s := range status.All {
		if s == a || s == b {
			return notPass(s)
		}
	}
	return ""
}

func orNone(value string) string {
	if value == "" {
		return "none"
	}
	return value
}
