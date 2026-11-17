package csr

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/donislawdev/certdoctor/internal/core/status"
	"github.com/donislawdev/certdoctor/internal/tool/certfacts"
	"github.com/donislawdev/certdoctor/internal/tool/derinput"
	"github.com/donislawdev/certdoctor/internal/tool/prose"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// named is how many names a sentence lists before it says how many more
// there are.
const named = 5

// judged is a request on its way to an outcome.
type judged struct {
	in    input
	c     *x509.CertificateRequest
	attrs attributes
	req   requested
	// tls says the request may be for a TLS server's certificate: it names no
	// purpose, or names serverAuth or any purpose, and does not ask to be an
	// authority. The rules a public authority keeps for such certificates are
	// asked of it, and of no other request.
	tls bool
	// signature is the check of the signature, worked out once - the view and
	// the data say what it found.
	signature spec.Check
	valid     *bool
}

func judge(in input) judged {
	j := judged{in: in, c: in.csr, attrs: attributesOf(in.csr.RawTBSCertificateRequest),
		req: requestedOf(in.csr.Extensions)}
	j.tls = certfacts.ServesTLS(j.req.known, j.req.unknown) && !j.req.isCA
	j.signature, j.valid = j.signatureCheck()
	return j
}

// checks is every judgement of the request.
func (j judged) checks() []spec.Check {
	out := []spec.Check{j.signature, j.keySizeCheck()}
	if j.tls {
		out = append(out, j.keyTypeCheck(), j.namesCheck())
		if c, ok := j.namesSpellingCheck(); ok {
			out = append(out, c)
		}
		if c, ok := j.commonNameCheck(); ok {
			out = append(out, c)
		}
	}
	out = append(out, j.passwordCheck())
	if c, ok := derinput.PrivateKeyCheck(j.in.skipped); ok {
		out = append(out, c)
	}
	return append(out, j.versionCheck())
}

// notes are the reader's notes, then what this tool did not judge and why.
func (j judged) notes() []string {
	notes := append([]string{}, j.in.notes...)
	if len(j.req.broken) > 0 {
		notes = append(notes, fmt.Sprintf("The request's %s could not be read, so it is taken as not asked for.",
			prose.List(j.req.broken)))
	}
	if !j.tls {
		why := "asks to be an authority"
		if !j.req.isCA {
			why = "asks for purposes that leave out serving TLS"
		}
		notes = append(notes, fmt.Sprintf("The request %s, so its names and its kind of key are not judged by "+
			"the rules for a TLS server's certificate.", why))
	}
	return notes
}

// signatureCheck: RFC 2986 section 3 has a request signed with the private
// key of the key it carries, "to prevent an entity from requesting a
// certificate with another party's public key" - so a signature that key does
// not verify means the request was changed after it was signed, or damaged.
// FAIL only when the library ran the check and it failed: a signature it
// cannot check at all is UNKNOWN, never FAIL.
func (j judged) signatureCheck() (spec.Check, *bool) {
	c := j.c
	algorithm := certfacts.SignatureAlgorithm(c.Raw, c.SignatureAlgorithm)
	unknown := func(why string) (spec.Check, *bool) {
		return spec.Check{ID: "signature", Status: status.Unknown, Summary: why + " - the signature is not checked."}, nil
	}
	if s, weak := certfacts.WeakSignature(c.SignatureAlgorithm); weak && s == status.Fail {
		return spec.Check{ID: "signature", Status: status.Fail, Summary: fmt.Sprintf("The request is signed with "+
			"%s, which Go refuses to check (crypto/x509) and Let's Encrypt refuses in a request.", algorithm)}, nil
	}
	if k, ok := c.PublicKey.(*rsa.PublicKey); ok && k.N.BitLen() < 1024 {
		return unknown(fmt.Sprintf("Go does not compute with an RSA key under 1024 bits (crypto/rsa), and the "+
			"request's has %d", k.N.BitLen()))
	}
	if !certfacts.Checkable(c.PublicKey) {
		return unknown(fmt.Sprintf("The request's RSA key has %d bits, more than the %d this program checks a "+
			"signature with (OpenSSL's largest)", c.PublicKey.(*rsa.PublicKey).N.BitLen(), certfacts.MaxCheckedRSABits))
	}
	err := c.CheckSignature()
	valid := err == nil
	switch {
	case err == nil:
		if s, weak := certfacts.WeakSignature(c.SignatureAlgorithm); weak {
			return spec.Check{ID: "signature", Status: s, Summary: fmt.Sprintf("The request's own key verifies "+
				"its signature, but the signature is %s - Let's Encrypt refuses a request signed with SHA-1.",
				algorithm)}, &valid
		}
		return spec.Check{ID: "signature", Status: status.Pass, Summary: "The request's own key verifies its " +
			"signature, so the request is as the holder of that key signed it."}, &valid
	case errors.Is(err, x509.ErrUnsupportedAlgorithm):
		return unknown(fmt.Sprintf("This program's X.509 library does not check a signature made with %s and a "+
			"key of %s", algorithm, keyOf(c).Words()))
	}
	return spec.Check{ID: "signature", Status: status.Fail, Summary: "The request's own key does not verify its " +
		"signature, so the request was changed after it was signed, or is damaged - a request is signed with the " +
		"key it carries so that it cannot be changed (RFC 2986 section 3), and an authority that checks the " +
		"signature refuses it."}, &valid
}

// keySizeCheck is the rule the certificate decoder keeps for an RSA key.
func (j judged) keySizeCheck() spec.Check {
	s, bits := certfacts.RSAKeyStatus(j.c.PublicKey)
	switch s {
	case status.Fail:
		return spec.Check{ID: "key_size", Status: s, Summary: fmt.Sprintf("The request has an RSA key of %d bits - %s",
			bits, certfacts.KeySizeFailWords)}
	case status.Warn:
		return spec.Check{ID: "key_size", Status: s, Summary: fmt.Sprintf("The request has an RSA key of %d bits - %s",
			bits, certfacts.KeySizeWarnWords)}
	}
	return spec.Check{ID: "key_size", Status: status.Pass, Summary: certfacts.KeySizePassWords}
}

// keyOf is the request's key, named.
func keyOf(c *x509.CertificateRequest) certfacts.PublicKey {
	k := certfacts.Key(c.PublicKey, c.PublicKeyAlgorithm)
	if k.Algorithm == "unknown" {
		var spki struct {
			Algorithm pkix.AlgorithmIdentifier
			Key       asn1.BitString
		}
		if _, err := asn1.Unmarshal(c.RawSubjectPublicKeyInfo, &spki); err == nil {
			k.Algorithm = "unknown (" + spki.Algorithm.Algorithm.String() + ")"
		}
	}
	return k
}

// publicCurves are the curves a public authority issues an ECDSA key on.
var publicCurves = map[string]bool{"P-256": true, "P-384": true, "P-521": true}

// keyTypeCheck: "For RSA key pairs ... the modulus size, in bits, is evenly
// divisible by 8. For ECDSA key pairs ... NIST P-256, NIST P-384 or NIST
// P-521 ... No other algorithms or key sizes are permitted" - Baseline
// Requirements 6.1.5.
func (j judged) keyTypeCheck() spec.Check {
	const source = " (CA/Browser Forum Baseline Requirements 6.1.5)."
	k := keyOf(j.c)
	warn := func(clause string) spec.Check {
		return spec.Check{ID: "key_type", Status: status.Warn, Summary: clause + source}
	}
	switch key := j.c.PublicKey.(type) {
	case *rsa.PublicKey:
		if bits := key.N.BitLen(); bits%8 != 0 {
			return warn(fmt.Sprintf("The request's RSA key has %d bits, not a multiple of 8 - a public authority "+
				"issues an RSA key only when its size is", bits))
		}
		return spec.Check{ID: "key_type", Status: status.Pass, Summary: "The key is RSA, a kind a public " +
			"authority issues for" + source}
	case *ecdsa.PublicKey:
		curve := key.Curve.Params().Name
		if !publicCurves[curve] {
			return warn(fmt.Sprintf("The request's ECDSA key is on %s - a public authority issues an ECDSA key "+
				"only on P-256, P-384 or P-521", curve))
		}
		return spec.Check{ID: "key_type", Status: status.Pass, Summary: fmt.Sprintf("The key is ECDSA on %s, a "+
			"kind a public authority issues for%s", curve, source)}
	case nil:
		return spec.Check{ID: "key_type", Status: status.Unknown, Summary: fmt.Sprintf("This program's X.509 "+
			"library does not read the request's key, %s, so its kind is not judged.", k.Algorithm)}
	}
	return warn(fmt.Sprintf("The request's key is %s - a public authority issues TLS certificates only for RSA "+
		"and ECDSA keys", k.Words()))
}

// hosts are the host names and addresses the request asks for.
func (j judged) hosts() []string {
	return append(append([]string{}, j.c.DNSNames...), addresses(j.c)...)
}

// namesCheck: the subject alternative name is what a client matches (RFC
// 6125 section 6.4.4) - Go's VerifyHostname ignores the common name and Chrome
// stopped reading it in version 58 - and a public authority puts one in every
// certificate (Baseline Requirements 7.1.2.7.12). The same id and reading as
// the certificate decoder's.
func (j judged) namesCheck() spec.Check {
	const check = "subject_alt_name"
	switch {
	case !j.req.names && j.attrs.msNames:
		return spec.Check{ID: check, Status: status.Unknown, Summary: "The request carries its names in " +
			"Microsoft's older extension request (msExtReq), which this program's X.509 library does not read, so " +
			"they are not judged."}
	case !j.req.names:
		return spec.Check{ID: check, Status: status.Warn, Summary: "The request asks for no subject alternative " +
			"name, so unless the authority adds names itself the certificate has none a client matches: those " +
			"names are the ones a client matches (RFC 6125 section 6.4.4), Go and Chrome since version 58 ignore " +
			"the common name, and a public authority puts them in every certificate (CA/Browser Forum Baseline " +
			"Requirements 7.1.2.7.12)."}
	case len(j.hosts()) == 0:
		return spec.Check{ID: check, Status: status.Warn, Summary: "The request's subject alternative name has no " +
			"host name and no address in it, so a client matching a host name finds nothing to match - a public " +
			"authority requires one (CA/Browser Forum Baseline Requirements 7.1.2.7.12)."}
	}
	return spec.Check{ID: check, Status: status.Pass, Summary: fmt.Sprintf("The request asks for %s.",
		prose.Capped(j.hosts(), named))}
}

// namesSpellingCheck judges every name the request asks for by the spelling a
// public authority requires, when it asks for any.
func (j judged) namesSpellingCheck() (spec.Check, bool) {
	if !j.req.names || len(j.hosts())+len(j.c.EmailAddresses)+len(j.c.URIs) == 0 {
		return spec.Check{}, false
	}
	var clauses []string
	for _, name := range j.c.DNSNames {
		if problem := nameProblem(name); problem != "" {
			clauses = append(clauses, fmt.Sprintf("%s (%s)", name, problem))
		}
	}
	var others []string
	if n := len(j.c.EmailAddresses); n > 0 {
		others = append(others, prose.Plural(int64(n), "e-mail address"))
	}
	if n := len(j.c.URIs); n > 0 {
		others = append(others, prose.Plural(int64(n), "URI"))
	}
	if len(others) > 0 {
		clauses = append(clauses, fmt.Sprintf("%s, which a public authority does not put in a TLS certificate and "+
			"Let's Encrypt refuses in a request", prose.List(others)))
	}
	if len(clauses) > 0 {
		return spec.Check{ID: "names", Status: status.Warn, Summary: fmt.Sprintf("The request asks for %s - a "+
			"public authority does not issue for such a name (CA/Browser Forum Baseline Requirements 7.1.2.7.12).",
			prose.Capped(clauses, named))}, true
	}
	if len(j.c.DNSNames) == 0 {
		return spec.Check{ID: "names", Status: status.Pass, Summary: "The request asks for addresses only, which " +
			"a public authority may issue for (CA/Browser Forum Baseline Requirements 7.1.2.7.12)."}, true
	}
	return spec.Check{ID: "names", Status: status.Pass, Summary: "Every host name is spelled as a public " +
		"authority requires: labels of letters, digits and hyphens, a wildcard only as the whole first label, more " +
		"than one label, no dot at the end (CA/Browser Forum Baseline Requirements 7.1.2.7.12)."}, true
}

// oidCommonName is id-at-commonName, RFC 5280 appendix A.
var oidCommonName = asn1.ObjectIdentifier{2, 5, 4, 3}

// commonNameCheck: a public authority's certificate carries at most one
// common name, and only one that is also in its subject alternative name
// (Baseline Requirements 7.1.4.3). Asked only when the request asks for a
// name or an address - without one, namesCheck already says so, and one
// problem gets one warning. A host name is compared without regard to case,
// as DNS compares it; an address by its value.
func (j judged) commonNameCheck() (spec.Check, bool) {
	if len(j.hosts()) == 0 {
		return spec.Check{}, false
	}
	const source = " (CA/Browser Forum Baseline Requirements 7.1.4.3)."
	count := 0
	for _, attribute := range j.c.Subject.Names {
		if attribute.Type.Equal(oidCommonName) {
			count++
		}
	}
	cn := j.c.Subject.CommonName
	switch {
	case count > 1:
		return spec.Check{ID: "common_name", Status: status.Warn, Summary: fmt.Sprintf("The request's subject has "+
			"%d common names - a public authority's certificate has at most one%s", count, source)}, true
	case cn == "":
		return spec.Check{ID: "common_name", Status: status.Pass, Summary: "The subject has no common name - the " +
			"names are in the subject alternative name, where a client looks."}, true
	case j.amongHosts(cn):
		return spec.Check{ID: "common_name", Status: status.Pass, Summary: fmt.Sprintf("The common name %s is one "+
			"of the names the request asks for.", cn)}, true
	}
	return spec.Check{ID: "common_name", Status: status.Warn, Summary: fmt.Sprintf("The common name %s is not one "+
		"of the names in the subject alternative name, so a client never matches it - a public authority's "+
		"certificate carries a common name only when it is one of them%s", cn, source)}, true
}

// amongHosts says the common name is one of the requested names or
// addresses.
func (j judged) amongHosts(cn string) bool {
	if address, err := netip.ParseAddr(cn); err == nil {
		for _, ip := range j.c.IPAddresses {
			if other, ok := netip.AddrFromSlice(ip); ok && other.Unmap() == address.Unmap() {
				return true
			}
		}
		return false
	}
	for _, name := range j.c.DNSNames {
		if strings.EqualFold(name, cn) {
			return true
		}
	}
	return false
}

// passwordCheck: a challenge password "specifies a password by which an
// entity may request certificate revocation" (RFC 2985 section 5.4.1) and
// travels in the request as written - anyone with the file reads it.
func (j judged) passwordCheck() spec.Check {
	switch {
	case !j.attrs.readable:
		return spec.Check{ID: "challenge_password", Status: status.Unknown, Summary: "Not every attribute of the " +
			"request could be read, so whether it carries a challenge password is not known."}
	case j.attrs.password:
		return spec.Check{ID: "challenge_password", Status: status.Warn, Summary: "The request carries a " +
			"challenge password (RFC 2985 section 5.4.1). It was not read and is not shown here - it travels in the " +
			"request as written, so anyone who has this file can read it, and the file should not be handed around."}
	}
	return spec.Check{ID: "challenge_password", Status: status.Pass, Summary: "The request carries no challenge " +
		"password."}
}

// versionCheck: the version "shall be 0 for this version of the standard"
// (RFC 2986 section 4.1). The library reads any.
func (j judged) versionCheck() spec.Check {
	if v := j.c.Version; v != 0 {
		return spec.Check{ID: "version", Status: status.Warn, Summary: fmt.Sprintf("The request's version field is "+
			"%d, and PKCS #10 defines only 0 (RFC 2986 section 4.1).", v)}
	}
	return spec.Check{ID: "version", Status: status.Pass, Summary: "The request's version field is 0, as PKCS #10 " +
		"defines (RFC 2986 section 4.1)."}
}

// addresses are the requested addresses as text.
func addresses(c *x509.CertificateRequest) []string {
	out := []string{}
	for _, ip := range c.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

// uris are the requested URIs as text.
func uris(c *x509.CertificateRequest) []string {
	out := []string{}
	for _, u := range c.URIs {
		out = append(out, u.String())
	}
	return out
}

// libraryWords is why the library refused, in its own words, cut short.
func libraryWords(err error) string { return prose.Cut(err.Error(), 160) }
