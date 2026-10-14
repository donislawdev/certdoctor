package systemstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// The fixtures every test in this package builds on: certificates generated in
// memory, and a program list encoded the way the copy in the registry was
// measured to be encoded on 2026-10-14. Nothing here touches a store, a file or
// the network.

// issued is a certificate and the key that signs what it issues.
type issued struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
}

// testClock is the moment every fixture is valid at.
var testClock = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// anAuthority is a self-signed root nobody has heard of, valid around the fixed
// test clock.
func anAuthority(t *testing.T, name string) issued {
	t.Helper()
	return anAuthorityValid(t, name, testClock.Add(-time.Hour), testClock.Add(24*time.Hour))
}

// anAuthorityValid is the same root with its validity named outright.
//
// IT EXISTS BECAUSE THE FIRST RUN AGAINST THE REAL LIBRARY WENT RED FOR IT, on
// 2026-10-14: a root valid around the fixed test clock and a leaf valid around
// the real one, and Windows - correctly - called the root out of date. A test
// that asks crypt32 has to build every certificate around the clock it hands it.
func anAuthorityValid(t *testing.T, name string, from, until time.Time) issued {
	t.Helper()
	key := mustKey(t)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: from, NotAfter: until,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return issued{certificate, key}
}

// leafOptions shapes one leaf.
type leafOptions struct {
	notBefore, notAfter time.Time
	issuerAddress       []string
}

// aLeaf is a server certificate the authority signed.
func aLeaf(t *testing.T, by issued, o leafOptions) *x509.Certificate {
	t.Helper()
	if o.notBefore.IsZero() {
		o.notBefore = testClock.Add(-2 * time.Hour)
	}
	if o.notAfter.IsZero() {
		o.notAfter = testClock.Add(time.Hour)
	}
	key := mustKey(t)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "leaf.test"}, DNSNames: []string{"leaf.test"},
		NotBefore: o.notBefore, NotAfter: o.notAfter,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IssuingCertificateURL: o.issuerAddress,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, by.certificate, &key.PublicKey, by.key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

// listEntry is one root as the program list records it.
type listEntry struct {
	identifier []byte
	properties map[string][]byte
}

// entryFor records a root the way the registry copy does: its SHA1, its key
// identifier as property 20 and the MD5 of its subject as property 29.
func entryFor(root *x509.Certificate) listEntry {
	fingerprint := sha1.Sum(root.Raw)
	name := md5.Sum(root.RawSubject)
	return listEntry{
		identifier: fingerprint[:],
		properties: map[string][]byte{"20": root.SubjectKeyId, "29": name[:]},
	}
}

// listOptions shapes the envelope, so a test can move one thing at a time.
type listOptions struct {
	outer, content asn1.ObjectIdentifier
	// optional adds the CTL_INFO fields the measured copy left out: a version,
	// a list identifier and a next update.
	optional bool
}

// encodeList builds the bytes the registry would hold.
func encodeList(t *testing.T, entries []listEntry, o listOptions) []byte {
	t.Helper()
	if o.outer == nil {
		o.outer = signedData
	}
	if o.content == nil {
		o.content = certificateTrustList
	}
	var fields []asn1.RawValue
	add := func(v any, params string) {
		der, err := asn1.MarshalWithParams(v, params)
		if err != nil {
			t.Fatal(err)
		}
		fields = append(fields, asn1.RawValue{FullBytes: der})
	}
	if o.optional {
		add(1, "")
	}
	add([]asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 311, 10, 3, 9}}, "")
	if o.optional {
		add([]byte{1, 2, 3}, "")
	}
	add(42, "")
	add(testClock.Add(-30*24*time.Hour), "utc")
	if o.optional {
		add(testClock.Add(30*24*time.Hour), "utc")
	}
	add(struct{ Algorithm asn1.ObjectIdentifier }{asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}}, "")
	fields = append(fields, raw(t, asn1.TagSequence, subjects(t, entries)...))
	return envelope(t, raw(t, asn1.TagSequence, fields...), o)
}

// subjects encodes the entries.
func subjects(t *testing.T, entries []listEntry) []asn1.RawValue {
	t.Helper()
	var out []asn1.RawValue
	for _, e := range entries {
		identifier := asn1.RawValue{Tag: asn1.TagOctetString, Bytes: e.identifier}
		var attributes []asn1.RawValue
		for property, value := range e.properties {
			kind, err := asn1.Marshal(oid(t, propertyPrefix+property))
			if err != nil {
				t.Fatal(err)
			}
			attributes = append(attributes, raw(t, asn1.TagSequence,
				asn1.RawValue{FullBytes: kind},
				raw(t, asn1.TagSet, asn1.RawValue{Tag: asn1.TagOctetString, Bytes: value})))
		}
		if len(attributes) == 0 {
			out = append(out, raw(t, asn1.TagSequence, identifier))
			continue
		}
		out = append(out, raw(t, asn1.TagSequence, identifier, raw(t, asn1.TagSet, attributes...)))
	}
	return out
}

// envelope wraps the list in PKCS #7 SignedData.
func envelope(t *testing.T, list asn1.RawValue, o listOptions) []byte {
	t.Helper()
	listDER := encoded(t, list)
	content, err := asn1.Marshal(o.content)
	if err != nil {
		t.Fatal(err)
	}
	signed := raw(t, asn1.TagSequence,
		asn1.RawValue{FullBytes: mustMarshal(t, 1)},
		raw(t, asn1.TagSet),
		raw(t, asn1.TagSequence, asn1.RawValue{FullBytes: content}, explicit(listDER)))
	outer, err := asn1.Marshal(o.outer)
	if err != nil {
		t.Fatal(err)
	}
	return encoded(t, raw(t, asn1.TagSequence, asn1.RawValue{FullBytes: outer}, explicit(encoded(t, signed))))
}

func raw(t *testing.T, tag int, children ...asn1.RawValue) asn1.RawValue {
	t.Helper()
	var body []byte
	for _, child := range children {
		body = append(body, encoded(t, child)...)
	}
	return asn1.RawValue{Tag: tag, IsCompound: true, Bytes: body}
}

func explicit(inner []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner}
}

func encoded(t *testing.T, v asn1.RawValue) []byte {
	t.Helper()
	if v.FullBytes != nil {
		return v.FullBytes
	}
	return mustMarshal(t, v)
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	der, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func oid(t *testing.T, dotted string) asn1.ObjectIdentifier {
	t.Helper()
	var out asn1.ObjectIdentifier
	value := 0
	for i := 0; i <= len(dotted); i++ {
		if i == len(dotted) || dotted[i] == '.' {
			out = append(out, value)
			value = 0
			continue
		}
		value = value*10 + int(dotted[i]-'0')
	}
	return out
}

// aListHolding parses a list naming these roots, synchronised at the given
// moment.
func aListHolding(t *testing.T, synced time.Time, roots ...*x509.Certificate) programList {
	t.Helper()
	var entries []listEntry
	for _, root := range roots {
		entries = append(entries, entryFor(root))
	}
	list, err := parseProgramList(encodeList(t, entries, listOptions{}), synced)
	if err != nil {
		t.Fatalf("the fixture list did not parse: %v", err)
	}
	return list
}
