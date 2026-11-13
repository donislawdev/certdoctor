package cert

import (
	"fmt"
	"strings"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/status"
	"github.com/donislawdev/certdoctor/internal/tool/certfacts"
	"github.com/donislawdev/certdoctor/internal/tool/prose"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// view is what a person is shown: the input as a whole, then each
// certificate in the order the input has them.
func (j judged) view() []spec.Block {
	blocks := []spec.Block{j.inputBlock()}
	for _, e := range j.in.entries {
		blocks = append(blocks, j.certificateBlock(e))
	}
	return blocks
}

// formWords says how the input was read.
var formWords = map[string]string{
	formPEM:    "PEM",
	formBase64: "base64 of one certificate",
	formDER:    "DER, one certificate",
	formX5C:    "x5c, a JSON array of base64",
}

// inputBlock is the input as a whole: how it was read, the chain, and what
// was left out.
func (j judged) inputBlock() spec.Block {
	ch := j.chain
	fields := []spec.Field{
		{Label: "Read as", Value: fmt.Sprintf("%s - %s", formWords[j.in.form],
			prose.Plural(int64(len(j.in.entries)), "certificate"))},
		{Label: "Chain", Value: ch.words(), Status: ch.chainCheck().Status},
	}
	if len(ch.Outside) > 0 {
		f := spec.Field{Label: "Outside the chain", Value: upper(certificates(ch.Outside))}
		if c, ok := ch.unrelatedCheck(); ok {
			f.Status = c.Status
		} else {
			f.Note = "read as a set of authorities"
		}
		fields = append(fields, f)
	}
	if c, ok := ch.duplicateCheck(); ok {
		fields = append(fields, spec.Field{Label: "Given twice", Value: duplicateWords(ch.Duplicates), Status: c.Status})
	}
	if len(j.in.skipped) > 0 {
		var left []string
		for _, s := range j.in.skipped {
			left = append(left, fmt.Sprintf("block %d, %s", s.Block, kindOf(s.Type)))
		}
		fields = append(fields, spec.Field{Label: "Not read", Value: strings.Join(left, "; ")})
	}
	return spec.Block{Kind: spec.Fields, Title: "Input", Fields: fields}
}

// words is the path in a few words: "1, issued by 2, issued by 3, which
// issued itself".
func (ch chained) words() string {
	out := fmt.Sprint(ch.Path[0])
	for _, n := range ch.Path[1:] {
		out += fmt.Sprintf(", issued by %d", n)
	}
	if ch.End == endSelfSigned {
		return out + ", which issued itself"
	}
	return out + ", whose issuer is not in the input"
}

func duplicateWords(groups [][]int) string {
	var out []string
	for _, g := range groups {
		out = append(out, numbers(g))
	}
	return strings.Join(out, "; ")
}

// certificateBlock is one certificate: who, when, what key, which purposes,
// and the values a person compares against another tool's.
func (j judged) certificateBlock(e entry) spec.Block {
	if e.cert == nil {
		return spec.Block{Kind: spec.Fields, Title: fmt.Sprintf("Certificate %d", e.number), Fields: []spec.Field{
			{Label: "Read", Value: "no - " + libraryWords(e.err), Status: status.Unknown},
		}}
	}
	fields := append(j.identity(e), j.dates(e)...)
	fields = append(fields, j.key(e)...)
	fields = append(fields, fingerprints(e)...)
	fields = append(fields, places(e)...)
	// The title is the number alone: a surface may set titles in capitals,
	// and a name in capitals is another name - the Subject row says it.
	return spec.Block{Kind: spec.Fields, Title: fmt.Sprintf("Certificate %d", e.number), Fields: fields}
}

// identity is who the certificate is for and who issued it.
func (j judged) identity(e entry) []spec.Field {
	c := e.cert
	issuer := spec.Field{Label: "Issuer", Value: certfacts.Name(c.Issuer)}
	if certfacts.SelfSigned(c) {
		issuer.Note = "itself - self-signed"
	}
	fields := []spec.Field{{Label: "Subject", Value: orNone([]string{certfacts.Name(c.Subject)})}, issuer}
	// Host names are shown where a host could be matched against them: when
	// the certificate has some, or when it is the one a server would present.
	v, judgedNames := j.namesOf(e)
	if len(c.DNSNames) > 0 || judgedNames {
		hosts := spec.Field{Label: "Host names", Value: orNone(c.DNSNames)}
		if judgedNames && v.status != status.Pass {
			hosts.Status = v.status
		}
		fields = append(fields, hosts)
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

// noEnd is the notAfter RFC 5280 section 4.1.2.5 gives a certificate that has
// no well-defined end: 99991231235959Z.
var noEnd = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)

// dates is when the certificate holds, each end with how far it is from now.
func (j judged) dates(e entry) []spec.Field {
	c := e.cert
	v := j.validityOf(e)
	from := spec.Field{Label: "Valid from", Value: prose.Clock(c.NotBefore), Note: prose.Distance(j.now, c.NotBefore)}
	until := spec.Field{Label: "Valid until", Value: prose.Clock(c.NotAfter), Note: prose.Distance(j.now, c.NotAfter)}
	if c.NotAfter.Equal(noEnd) {
		until.Note = "no end date (RFC 5280 section 4.1.2.5)"
	}
	if v.status != status.Pass && j.now.Before(c.NotBefore) {
		from.Status = v.status
	} else if v.status != status.Pass {
		until.Status = v.status
	}
	return []spec.Field{from, until}
}

// key is the certificate's key, signature, authority and purposes.
func (j judged) key(e entry) []spec.Field {
	c := e.cert
	fields := []spec.Field{
		{Label: "Key", Value: keyWords(publicKey(c)), Status: notPass(keyOf(e))},
		{Label: "Signature", Value: c.SignatureAlgorithm.String(), Status: notPass(signatureOf(e))},
		{Label: "Authority", Value: authorityWords(c.IsCA, pathLength(c))},
		{Label: "Serial number", Value: serialHex(c)},
	}
	if u := keyUsages(c.KeyUsage); len(u) > 0 {
		fields = append(fields, spec.Field{Label: "Key usage", Value: strings.Join(u, ", ")})
	}
	if u := extendedKeyUsages(c); len(u) > 0 {
		fields = append(fields, spec.Field{Label: "Extended key usage", Value: strings.Join(u, ", ")})
	}
	return fields
}

func notPass(v verdict) status.Status {
	if v.status == status.Pass {
		return ""
	}
	return v.status
}

// keyWords names a key: "RSA, 2048 bits", "ECDSA, P-256", "Ed25519".
func keyWords(k PublicKey) string {
	switch {
	case k.Curve != nil:
		return k.Algorithm + ", " + *k.Curve
	case k.Bits != nil:
		return fmt.Sprintf("%s, %d bits", k.Algorithm, *k.Bits)
	}
	return k.Algorithm
}

// authorityWords says whether the certificate may issue others (RFC 5280
// section 4.2.1.9).
func authorityWords(isCA bool, below *int) string {
	switch {
	case !isCA:
		return "no"
	case below == nil:
		return "yes - may issue certificates, with no limit on authorities below it"
	case *below == 0:
		return "yes - may issue certificates, but no authority below it"
	}
	return fmt.Sprintf("yes - may issue certificates, with at most %s below it", prose.Plural(int64(*below), "authority"))
}

// fingerprints are the values a person compares against another tool's: the
// SHA-256 the report prints, the SHA-1 Windows calls the thumbprint
// (X509Certificate2.Thumbprint), and the SPKI pin of RFC 7469 section 2.4.
func fingerprints(e entry) []spec.Field {
	c := e.cert
	fields := []spec.Field{
		{Label: "SHA-256", Value: certfacts.FingerprintSHA256(c.Raw)},
		{Label: "SHA-1", Value: thumbprint(c), Note: "the thumbprint Windows shows"},
		{Label: "SPKI pin", Value: spkiPin(c), Note: "SHA-256, for pinning"},
	}
	if id := hexOrNull(c.SubjectKeyId); id != nil {
		fields = append(fields, spec.Field{Label: "Subject key ID", Value: *id})
	}
	if id := hexOrNull(c.AuthorityKeyId); id != nil {
		fields = append(fields, spec.Field{Label: "Authority key ID", Value: *id})
	}
	return fields
}

// places are the addresses the certificate names for its issuer, its OCSP
// responder and its revocation list - shown, never opened.
func places(e entry) []spec.Field {
	c := e.cert
	var fields []spec.Field
	for _, p := range []struct {
		label string
		urls  []string
	}{{"Issuer's certificate", c.IssuingCertificateURL}, {"OCSP", c.OCSPServer}, {"CRL", c.CRLDistributionPoints}} {
		if len(p.urls) > 0 {
			fields = append(fields, spec.Field{Label: p.label, Value: strings.Join(p.urls, ", ")})
		}
	}
	return fields
}

func orNone(values []string) string {
	if len(values) == 0 || len(values) == 1 && values[0] == "" {
		return "none"
	}
	return strings.Join(values, ", ")
}
