package probe

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"strings"
)

// subjectOf reads the subject of a certificate the Go library would not parse,
// on its own - ADR136. RFC 5280 section 4.1 puts it sixth in the
// TBSCertificate, after the optional version, the serial number, the signature
// algorithm, the issuer and the validity.
//
// IT READS NOTHING THE PARSER REFUSED. A negative serial number or an RSA
// modulus Go will not take - the two shapes measured, EC-ACC on macOS 27.2 and
// CN=Root Agency in the Windows store - sit in fields this walk only steps over.
// It answers false when even this much cannot be read, and the caller then
// counts the certificate as one that could be anywhere.
func subjectOf(der []byte) (string, bool) {
	var certificate struct {
		TBS       asn1.RawValue
		Algorithm asn1.RawValue
		Signature asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &certificate); err != nil {
		return "", false
	}
	rest := certificate.TBS.Bytes
	var fields []asn1.RawValue
	for len(rest) > 0 && len(fields) < 6 {
		var field asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &field); err != nil {
			return "", false
		}
		fields = append(fields, field)
	}
	at := 4
	if len(fields) > 0 && fields[0].Class == asn1.ClassContextSpecific && fields[0].Tag == 0 {
		at = 5
	}
	if len(fields) <= at {
		return "", false
	}
	return foldedName(fields[at].FullBytes)
}

// foldedName is a distinguished name in the form OpenSSL compares names in, so
// two names are one name here exactly when they would be one there - ADR136.
//
// X509_NAME_cmp COMPARES CANONICAL ENCODINGS, read 2026-11-12 in x509_name_canon
// and asn1_string_canon at
// https://github.com/openssl/openssl/blob/openssl-3.5/crypto/x509/x_name.c: every
// string type is turned into UTF-8, leading and trailing spaces are dropped,
// runs of spaces inside become one, and ASCII letters are lowered - anything
// else is copied as it is. The attributes of one RDN keep their order.
//
// IT ANSWERS FALSE FOR A VALUE THAT IS NOT A STRING, rather than guessing at its
// canonical form: the caller then treats every certificate it could not read as
// one that may be on the path, which is the safe direction.
func foldedName(raw []byte) (string, bool) {
	var rdns pkix.RDNSequence
	if rest, err := asn1.Unmarshal(raw, &rdns); err != nil || len(rest) != 0 {
		return "", false
	}
	var folded strings.Builder
	for _, set := range rdns {
		folded.WriteByte(0x01)
		for _, attribute := range set {
			value, ok := attribute.Value.(string)
			if !ok {
				return "", false
			}
			folded.WriteString(attribute.Type.String())
			folded.WriteByte(0x00)
			folded.WriteString(foldedValue(value))
			folded.WriteByte(0x00)
		}
	}
	return folded.String(), true
}

// foldedValue is asn1_string_canon on a value already in UTF-8.
func foldedValue(value string) string {
	words := strings.FieldsFunc(value, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\v' || r == '\f' || r == '\r'
	})
	for i, word := range words {
		words[i] = strings.Map(func(r rune) rune {
			if r >= 'A' && r <= 'Z' {
				return r + ('a' - 'A')
			}
			return r
		}, word)
	}
	return strings.Join(words, " ")
}
