package cert

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/donislawdev/certdoctor/internal/core/status"
	"github.com/donislawdev/certdoctor/internal/tool/certfacts"
	"github.com/donislawdev/certdoctor/internal/tool/prose"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// soon is how close to its end a certificate is said to be near it - this
// program's line, not a standard's.
const soon = 30 * 24 * time.Hour

// named is how many certificates a sentence names before it says how many
// more there are.
const named = 5

// judged is an input on its way to an outcome.
type judged struct {
	in    input
	read  []entry
	now   time.Time
	chain chained
}

// verdict is what one rule says about one certificate: the status and the
// clause naming it, or a pass with no clause.
type verdict struct {
	status status.Status
	clause string
}

var pass = verdict{status: status.Pass}

// validityOf: a certificate holds from notBefore through notAfter, both
// included (RFC 5280 section 4.1.2.5), and a client checks the time against
// them on every certificate of the path (section 6.1.3).
func (j judged) validityOf(e entry) verdict {
	c := e.cert
	switch {
	case j.now.Before(c.NotBefore):
		return verdict{status.Fail, fmt.Sprintf("%s is not valid yet - for %s more, until %s", label(e),
			prose.Span(j.now, c.NotBefore), prose.Clock(c.NotBefore))}
	case j.now.After(c.NotAfter):
		return verdict{status.Fail, fmt.Sprintf("%s expired %s ago, at %s", label(e),
			prose.Span(j.now, c.NotAfter), prose.Clock(c.NotAfter))}
	case c.NotAfter.Sub(j.now) < soon:
		return verdict{status.Warn, fmt.Sprintf("%s ends in %s, at %s", label(e),
			prose.Span(j.now, c.NotAfter), prose.Clock(c.NotAfter))}
	}
	return pass
}

// weakSignatures are the signature algorithms a client should not accept a
// certificate under: MD2 and MD5, which Go's CheckSignature rejects outright,
// and SHA-1, which Go's Verify does not build a chain through and which the
// CA/Browser Forum ended in certificates (Baseline Requirements 7.1.3.2,
// ballot SC097) - crypto/x509 of Go 1.27, read 2026-11-13.
var weakSignatures = map[x509.SignatureAlgorithm]status.Status{
	x509.MD2WithRSA:    status.Fail,
	x509.MD5WithRSA:    status.Fail,
	x509.SHA1WithRSA:   status.Warn,
	x509.DSAWithSHA1:   status.Warn,
	x509.ECDSAWithSHA1: status.Warn,
}

// signatureOf: a root's own signature is not what a client checks - it trusts
// the root's name and key as given (RFC 5280 section 6.1.1) - so a
// certificate that issued itself passes whatever it is signed with. "Issued
// itself" is certfacts.IssuedBy of the certificate by itself: its name, and a
// signature its key verifies or that cannot be checked at all - an MD5 root
// names itself and Go will not check what it signed.
func signatureOf(e entry) verdict {
	s, weak := weakSignatures[e.cert.SignatureAlgorithm]
	if !weak || certfacts.IssuedBy(e.cert, e.cert) {
		return pass
	}
	return verdict{s, fmt.Sprintf("%s is signed with %s", label(e), e.cert.SignatureAlgorithm)}
}

// keyOf: Go refuses to verify with an RSA key under 1024 bits (crypto/rsa of
// Go 1.27, read 2026-11-13), and the CA/Browser Forum requires 2048 bits of a
// public authority (Baseline Requirements 6.1.5).
func keyOf(e entry) verdict {
	k, ok := e.cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return pass
	}
	switch bits := k.N.BitLen(); {
	case bits < 1024:
		return verdict{status.Fail, fmt.Sprintf("%s has an RSA key of %d bits", label(e), bits)}
	case bits < 2048:
		return verdict{status.Warn, fmt.Sprintf("%s has an RSA key of %d bits", label(e), bits)}
	}
	return pass
}

// namesOf judges the names of the first certificate when it may be a TLS
// server's: an authority, or a certificate whose purposes leave out serving
// TLS, is not matched against a host name. RFC 6125 section 6.4.4 makes the
// subjectAltName what a client matches on; Go's VerifyHostname ignores the
// common name, and Chrome stopped reading it in version 58 - the reading L4
// gives a server's certificate (ADR106).
func (j judged) namesOf(e entry) (verdict, bool) {
	c := e.cert
	if e.number != j.read[0].number || c.IsCA || !servesTLS(c) {
		return verdict{}, false
	}
	switch {
	case !certfacts.HasSubjectAltName(c):
		return verdict{status.Warn, fmt.Sprintf("%s has no subject alternative name", label(e))}, true
	case len(c.DNSNames)+len(c.IPAddresses) == 0:
		return verdict{status.Warn, fmt.Sprintf("%s has a subject alternative name with no host name and no "+
			"address in it", label(e))}, true
	}
	return pass, true
}

// checks is every judgement of the input.
func (j judged) checks() []spec.Check {
	out := []spec.Check{
		j.collect("validity", j.validityOf, validityWords),
		j.collect("signature", signatureOf, signatureWords),
		j.collect("key_size", keyOf, keySizeWords),
		j.chain.chainCheck(),
	}
	for _, more := range []func() (spec.Check, bool){
		j.namesCheck, j.chain.orderCheck, j.chain.unrelatedCheck, j.chain.duplicateCheck, j.keyCheck,
		j.unreadableCheck,
	} {
		if c, ok := more(); ok {
			out = append(out, c)
		}
	}
	return out
}

// sentences says, for one rule, what follows the clauses of the worst status
// found, and what is said when everything passed.
type sentences struct {
	fail, warn string
	pass       func(j judged) string
}

// collect runs one rule over every certificate read: the worst status found,
// the clauses of that status and the rule's words for it.
func (j judged) collect(id string, rule func(entry) verdict, words sentences) spec.Check {
	worst := status.Pass
	var clauses []string
	for _, e := range j.read {
		v := rule(e)
		if v.status == status.Pass {
			continue
		}
		if v.status == status.Fail && worst != status.Fail {
			worst, clauses = status.Fail, nil
		}
		if v.status == worst || worst == status.Pass {
			worst, clauses = v.status, append(clauses, v.clause)
		}
	}
	switch worst {
	case status.Fail:
		return spec.Check{ID: id, Status: worst, Summary: upper(capped(clauses)) + " - " + words.fail}
	case status.Warn:
		return spec.Check{ID: id, Status: worst, Summary: upper(capped(clauses)) + " - " + words.warn}
	}
	return spec.Check{ID: id, Status: status.Pass, Summary: words.pass(j)}
}

var validityWords = sentences{
	fail: "a client refuses a certificate outside its dates (RFC 5280 section 6.1.3).",
	warn: "less than 30 days left.",
	pass: func(j judged) string {
		first := j.read[0]
		for _, e := range j.read {
			if e.cert.NotAfter.Before(first.cert.NotAfter) {
				first = e
			}
		}
		if len(j.read) == 1 {
			return fmt.Sprintf("Valid now, for %s more, until %s.", prose.Span(j.now, first.cert.NotAfter),
				prose.Clock(first.cert.NotAfter))
		}
		return fmt.Sprintf("All %d are valid now. The first to end is %s, in %s, at %s.", len(j.read),
			label(first), prose.Span(j.now, first.cert.NotAfter), prose.Clock(first.cert.NotAfter))
	},
}

var signatureWords = sentences{
	fail: "Go rejects an MD5 or MD2 signature outright (crypto/x509), so no client should trust it.",
	warn: "Go does not build a chain through a SHA-1 signature (crypto/x509), and public authorities stopped " +
		"issuing them (CA/Browser Forum Baseline Requirements 7.1.3.2).",
	pass: func(judged) string {
		return "No certificate is signed with MD5 or SHA-1, apart from any root's signature on itself, which a " +
			"client does not check (RFC 5280 section 6.1.1)."
	},
}

var keySizeWords = sentences{
	fail: "Go refuses to verify with an RSA key under 1024 bits (crypto/rsa).",
	warn: "a public authority issues no RSA key under 2048 bits (CA/Browser Forum Baseline Requirements 6.1.5).",
	pass: func(judged) string { return "No RSA key is shorter than 2048 bits." },
}

// namesCheck is the verdict on the first certificate's names, with the names.
func (j judged) namesCheck() (spec.Check, bool) {
	first := j.read[0]
	v, ok := j.namesOf(first)
	if !ok {
		return spec.Check{}, false
	}
	if v.status != status.Pass {
		return spec.Check{ID: "subject_alt_name", Status: v.status, Summary: upper(v.clause) + ", so a client " +
			"matching a host name finds nothing to match: those names are the ones a client matches (RFC 6125 " +
			"section 6.4.4), and Go and Chrome since version 58 ignore the common name."}, true
	}
	c := first.cert
	all := append(append([]string{}, c.DNSNames...), addresses(c)...)
	return spec.Check{ID: "subject_alt_name", Status: status.Pass, Summary: fmt.Sprintf("%s is for %s.",
		upper(label(first)), capped(all))}, true
}

// keyCheck warns about a private key in the input, which is never read.
func (j judged) keyCheck() (spec.Check, bool) {
	var blocks []string
	for _, s := range j.in.skipped {
		if isPrivateKey(s.Type) {
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

// unreadableCheck names the certificates the library could not read.
func (j judged) unreadableCheck() (spec.Check, bool) {
	var clauses []string
	for _, e := range j.in.entries {
		if e.cert == nil {
			clauses = append(clauses, fmt.Sprintf("certificate %d (%s)", e.number, libraryWords(e.err)))
		}
	}
	if len(clauses) == 0 {
		return spec.Check{}, false
	}
	return spec.Check{ID: "unreadable", Status: status.Unknown, Summary: fmt.Sprintf("This program's X.509 "+
		"library could not read %s, so nothing is said about %s.", prose.List(clauses),
		pluralWord(len(clauses), "it", "them"))}, true
}

// label names a certificate in a sentence: "certificate 2 (leaf.example.test)".
func label(e entry) string {
	name := shortName(e.cert)
	if name == "" {
		return fmt.Sprintf("certificate %d", e.number)
	}
	return fmt.Sprintf("certificate %d (%s)", e.number, name)
}

// shortName is what a person calls a certificate: its common name, else its
// first host name, else its whole subject - cut to 60 characters.
func shortName(c *x509.Certificate) string {
	name := c.Subject.CommonName
	if name == "" && len(c.DNSNames) > 0 {
		name = c.DNSNames[0]
	}
	if name == "" {
		name = certfacts.Name(c.Subject)
	}
	if utf8.RuneCountInString(name) > 60 {
		name = string([]rune(name)[:59]) + "..."
	}
	return name
}

// libraryWords is why the library refused, in its own words, cut short.
func libraryWords(err error) string {
	words := err.Error()
	if utf8.RuneCountInString(words) > 160 {
		words = string([]rune(words)[:159]) + "..."
	}
	return words
}

// capped lists clauses, naming at most a few and counting the rest.
func capped(clauses []string) string {
	if len(clauses) <= named {
		return prose.List(clauses)
	}
	return strings.Join(clauses[:named], ", ") + fmt.Sprintf(" and %d more", len(clauses)-named)
}

// upper starts a sentence with a capital.
func upper(s string) string {
	if s != "" && 'a' <= s[0] && s[0] <= 'z' {
		return string(s[0]-'a'+'A') + s[1:]
	}
	return s
}
