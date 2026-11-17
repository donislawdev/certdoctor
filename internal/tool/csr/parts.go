package csr

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/donislawdev/certdoctor/internal/tool/certfacts"
)

// The attributes of a request this tool names (RFC 2985 appendix A, and
// Microsoft's MS-WCCE 2.2.2.7.7 for its own extension request).
var (
	oidChallengePassword  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}
	oidUnstructuredName   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 2}
	oidExtensionRequest   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}
	oidMSExtensionRequest = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 14}
)

// attributeNames are those attributes in words.
var attributeNames = map[string]string{
	oidChallengePassword.String():  "challengePassword",
	oidUnstructuredName.String():   "unstructuredName",
	oidExtensionRequest.String():   "extensionRequest",
	oidMSExtensionRequest.String(): "Microsoft extension request (msExtReq)",
}

// The extensions this tool reads out of a request itself (RFC 5280 section
// 4.2.1), because the library reads only the subject alternative name of a
// request (crypto/x509 of Go 1.27.4, parseCertificateRequest).
var (
	oidSubjectAltName    = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidKeyUsage          = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtKeyUsage       = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidBasicConstraints  = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidSubjectKeyID      = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidCertificatePolicy = asn1.ObjectIdentifier{2, 5, 29, 32}
)

// extensionNames are the extensions a request commonly asks for, in the
// words of RFC 5280 section 4.2.1.
var extensionNames = map[string]string{
	oidSubjectAltName.String():    "subject alternative name",
	oidKeyUsage.String():          "key usage",
	oidExtKeyUsage.String():       "extended key usage",
	oidBasicConstraints.String():  "basic constraints",
	oidSubjectKeyID.String():      "subject key identifier",
	oidCertificatePolicy.String(): "certificate policies",
}

// attributes is what the request's attributes say, read from its raw bytes.
//
// THE LIBRARY SKIPS WHAT MATTERS HERE WITHOUT A WORD: a challenge password,
// and Microsoft's older extension request - parseRawAttributes and
// parseCSRExtensions of crypto/x509 in Go 1.27.4 ignore both. So the request's
// own bytes are read again, with the structure RFC 2986 section 4.1 gives
// them. A password is noticed by its identifier, and its value is not decoded.
type attributes struct {
	oids []asn1.ObjectIdentifier
	// readable says every attribute had the shape of RFC 2986: an identifier
	// and a set of values. When one did not, what it was is not known.
	readable bool
	password bool
	// msNames says Microsoft's extension request carries a subject
	// alternative name, which the library does not read.
	msNames bool
}

// attributesOf reads the attributes of a request's signed part.
func attributesOf(rawTBS []byte) attributes {
	var tbs struct {
		Version    int
		Subject    asn1.RawValue
		PublicKey  asn1.RawValue
		Attributes []asn1.RawValue `asn1:"tag:0"`
	}
	if rest, err := asn1.Unmarshal(rawTBS, &tbs); err != nil || len(rest) > 0 {
		return attributes{}
	}
	out := attributes{readable: true}
	for _, raw := range tbs.Attributes {
		var a struct {
			ID     asn1.ObjectIdentifier
			Values []asn1.RawValue `asn1:"set"`
		}
		if rest, err := asn1.Unmarshal(raw.FullBytes, &a); err != nil || len(rest) > 0 {
			out.readable = false
			continue
		}
		out.oids = append(out.oids, a.ID)
		switch {
		case a.ID.Equal(oidChallengePassword):
			out.password = true
		case a.ID.Equal(oidMSExtensionRequest) && len(a.Values) > 0:
			out.msNames = out.msNames || asksForNames(a.Values[0].FullBytes)
		}
	}
	return out
}

// asksForNames says a list of extensions - the value of an extension request,
// whose format MS-WCCE 2.2.2.7.7 gives as RFC 2985 section 5.4.2 - holds a
// subject alternative name.
func asksForNames(raw []byte) bool {
	var extensions []pkix.Extension
	if _, err := asn1.Unmarshal(raw, &extensions); err != nil {
		return false
	}
	for _, e := range extensions {
		if e.Id.Equal(oidSubjectAltName) {
			return true
		}
	}
	return false
}

// requested is what the request asks for in the extensions the library leaves
// raw: the key usage, the purposes and whether to be an authority.
type requested struct {
	keyUsage x509.KeyUsage
	known    []x509.ExtKeyUsage
	unknown  []asn1.ObjectIdentifier
	// basic says the request carries basic constraints at all.
	basic bool
	isCA  bool
	// maxPathLen is -1 when no limit is asked for.
	maxPathLen int
	// broken names the extensions whose value could not be read.
	broken []string
	// names says a subject alternative name is asked for.
	names bool
}

// requestedOf reads the extensions the request asks for, the way crypto/x509
// reads them in a certificate: the bits of key usage from the first nine
// (RFC 5280 section 4.2.1.3), the purposes as identifiers (section
// 4.2.1.12), basic constraints with an absent limit as none (section 4.2.1.9).
func requestedOf(extensions []pkix.Extension) requested {
	out := requested{maxPathLen: -1}
	for _, e := range extensions {
		switch {
		case e.Id.Equal(oidSubjectAltName):
			out.names = true
		case e.Id.Equal(oidKeyUsage):
			usage, ok := keyUsageOf(e.Value)
			if !ok {
				out.broken = append(out.broken, "key usage")
			}
			out.keyUsage = usage
		case e.Id.Equal(oidExtKeyUsage):
			var oids []asn1.ObjectIdentifier
			if rest, err := asn1.Unmarshal(e.Value, &oids); err != nil || len(rest) > 0 {
				out.broken = append(out.broken, "extended key usage")
				continue
			}
			out.known, out.unknown = certfacts.ExtKeyUsagesOf(oids)
		case e.Id.Equal(oidBasicConstraints):
			var bc struct {
				IsCA       bool `asn1:"optional"`
				MaxPathLen int  `asn1:"optional,default:-1"`
			}
			if rest, err := asn1.Unmarshal(e.Value, &bc); err != nil || len(rest) > 0 {
				out.broken = append(out.broken, "basic constraints")
				continue
			}
			out.basic, out.isCA, out.maxPathLen = true, bc.IsCA, bc.MaxPathLen
		}
	}
	return out
}

// keyUsageOf reads key usage the way crypto/x509 reads it in a certificate:
// bit i of the first nine sets bit i of x509.KeyUsage.
func keyUsageOf(value []byte) (x509.KeyUsage, bool) {
	var bits asn1.BitString
	if rest, err := asn1.Unmarshal(value, &bits); err != nil || len(rest) > 0 {
		return 0, false
	}
	var usage x509.KeyUsage
	for i := 0; i < 9; i++ {
		if bits.At(i) != 0 {
			usage |= 1 << uint(i)
		}
	}
	return usage, true
}

// pathLength is the limit asked for, null when the request does not ask to be
// an authority or asks for no limit - as the certificate decoder says it.
func (r requested) pathLength() *int {
	if !r.isCA || r.maxPathLen < 0 {
		return nil
	}
	n := r.maxPathLen
	return &n
}
