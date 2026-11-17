package csr

import (
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"crypto/x509/pkix"
)

// The requests of these tests are put together by hand, here, out of the
// keys in fixtures_keys_test.go - every shape a rule is asked about, with a
// junk signature, since only the signature rule reads the signature and it
// has requests that are truly signed (fixtureServer, fixtureSHA1). The tools'
// tests may not make a key or sign (their closed list of the standard
// library holds the tests too), and this keeps the hand-made bytes few.

var (
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidMD5WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	oidSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidEd448           = asn1.ObjectIdentifier{1, 3, 101, 113}
	oidServerAuth      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidClientAuth      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
)

// request is a request to put together. extensions go into an extension
// request attribute when there are any; attributes come after it.
type request struct {
	version    int
	subject    pkix.Name
	spki       string
	extensions []pkix.Extension
	attributes []asn1.RawValue
	algorithm  asn1.ObjectIdentifier
}

// server is the shape of fixtureServer, unsigned: a P-256 key, two names, the
// common name among them, digitalSignature and serverAuth.
func server(t *testing.T) request {
	return request{
		subject: pkix.Name{CommonName: "www.example.test", Organization: []string{"Example"}},
		spki:    spkiP256,
		extensions: []pkix.Extension{san(t, dns("www.example.test"), dns("example.test")), keyUsage(t),
			purposes(t, oidServerAuth)},
	}
}

// withNames is server with no subject and these host names.
func withNames(t *testing.T, names ...string) request {
	r := server(t)
	r.subject = pkix.Name{}
	var general []asn1.RawValue
	for _, n := range names {
		general = append(general, dns(n))
	}
	r.extensions[0] = san(t, general...)
	return r
}

// der is the request, put together and given a junk signature.
func (r request) der(t *testing.T) []byte {
	t.Helper()
	subject, err := asn1.Marshal(r.subject.ToRDNSequence())
	if err != nil {
		t.Fatal(err)
	}
	attributes := []asn1.RawValue{}
	if len(r.extensions) > 0 {
		attributes = append(attributes, attribute(t, oidExtensionRequest, r.extensions))
	}
	attributes = append(attributes, r.attributes...)
	tbs, err := asn1.Marshal(struct {
		Version    int
		Subject    asn1.RawValue
		PublicKey  asn1.RawValue
		Attributes []asn1.RawValue `asn1:"tag:0"`
	}{r.version, asn1.RawValue{FullBytes: subject}, asn1.RawValue{FullBytes: b64(t, r.spki)}, attributes})
	if err != nil {
		t.Fatal(err)
	}
	algorithm := r.algorithm
	if algorithm == nil {
		algorithm = oidECDSAWithSHA256
	}
	out, err := asn1.Marshal(struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}{asn1.RawValue{FullBytes: tbs}, pkix.AlgorithmIdentifier{Algorithm: algorithm},
		asn1.BitString{Bytes: []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}, BitLength: 64}})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func b64(t *testing.T, text string) []byte {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// derOf is the DER of a PEM fixture.
func derOf(t *testing.T, fixture string) []byte {
	t.Helper()
	b, _ := pem.Decode([]byte(fixture))
	if b == nil {
		t.Fatal("a fixture is not PEM")
	}
	return b.Bytes
}

// asPEM wraps DER in a PEM block of the given type.
func asPEM(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

// attribute is one attribute of RFC 2986 section 4.1.
func attribute(t *testing.T, id asn1.ObjectIdentifier, values ...any) asn1.RawValue {
	t.Helper()
	var raws []asn1.RawValue
	for _, v := range values {
		der, err := asn1.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		raws = append(raws, asn1.RawValue{FullBytes: der})
	}
	der, err := asn1.Marshal(struct {
		ID     asn1.ObjectIdentifier
		Values []asn1.RawValue `asn1:"set"`
	}{id, raws})
	if err != nil {
		t.Fatal(err)
	}
	return asn1.RawValue{FullBytes: der}
}

func extension(t *testing.T, id asn1.ObjectIdentifier, value any) pkix.Extension {
	t.Helper()
	der, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: id, Value: der}
}

// The kinds of name of RFC 5280 section 4.2.1.6, by their tags.
func dns(name string) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte(name)}
}
func mail(address string) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, Bytes: []byte(address)}
}
func uri(u string) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(u)}
}
func ip(address ...byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 7, Bytes: address}
}

// san is a subject alternative name holding names.
func san(t *testing.T, names ...asn1.RawValue) pkix.Extension {
	return extension(t, oidSubjectAltName, names)
}

// keyUsage asks for digitalSignature.
func keyUsage(t *testing.T) pkix.Extension {
	return extension(t, oidKeyUsage, asn1.BitString{Bytes: []byte{0x80}, BitLength: 1})
}

func purposes(t *testing.T, oids ...asn1.ObjectIdentifier) pkix.Extension {
	return extension(t, oidExtKeyUsage, oids)
}

// authority asks to be an authority with no authority below it. A limit of 0
// is written only beside a default of -1, as crypto/x509 writes it - an
// optional field at its zero value is left out.
func authority(t *testing.T) pkix.Extension {
	return extension(t, oidBasicConstraints, struct {
		IsCA       bool `asn1:"optional"`
		MaxPathLen int  `asn1:"optional,default:-1"`
	}{true, 0})
}

// unknownSPKI is a key of an algorithm the library does not read, in base64.
func unknownSPKI(t *testing.T) string {
	t.Helper()
	der, err := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		Key       asn1.BitString
	}{pkix.AlgorithmIdentifier{Algorithm: oidEd448}, asn1.BitString{Bytes: make([]byte, 57), BitLength: 57 * 8}})
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}
