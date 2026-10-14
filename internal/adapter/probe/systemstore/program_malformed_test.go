package systemstore

import (
	"encoding/asn1"
	"strings"
	"testing"
)

// A LIST THAT IS THE WRONG SHAPE ANYWHERE IS REFUSED, AND SAYS WHERE. Every case
// here is a value somebody else wrote reaching a parser that would otherwise
// read the wrong field as the entries - and the only safe outcome of that is a
// list nobody consults, which can turn a FAIL into an undetermined and never the
// other way round. The positive twin for every case is in program_test.go.

func TestAListMalformedAtAnyLevelIsRefused(t *testing.T) {
	usage := asn1.RawValue{FullBytes: mustMarshal(t, []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 311, 10, 3, 9}})}
	date := asn1.RawValue{FullBytes: func() []byte {
		der, err := asn1.MarshalWithParams(testClock, "utc")
		if err != nil {
			t.Fatal(err)
		}
		return der
	}()}
	algorithm := asn1.RawValue{FullBytes: mustMarshal(t, struct{ Algorithm asn1.ObjectIdentifier }{asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}})}
	identifier := asn1.RawValue{Tag: asn1.TagOctetString, Bytes: []byte{1, 2, 3}}
	attribute := func(kind asn1.RawValue, values asn1.RawValue) []byte {
		entry := raw(t, asn1.TagSequence, identifier, raw(t, asn1.TagSet, raw(t, asn1.TagSequence, kind, values)))
		return trustList(t, usage, date, algorithm, raw(t, asn1.TagSequence, entry))
	}
	nameProperty := asn1.RawValue{FullBytes: mustMarshal(t, oid(t, propertyPrefix+subjectNameMD5Property))}
	contentType := asn1.RawValue{FullBytes: mustMarshal(t, certificateTrustList)}
	signedType := asn1.RawValue{FullBytes: mustMarshal(t, signedData)}

	cases := []struct {
		name string
		der  []byte
		says string
	}{
		{"an envelope that is not a sequence", mustMarshal(t, 42), "is not a sequence"},
		{"signed data with no content",
			encoded(t, raw(t, asn1.TagSequence, signedType, explicit(encoded(t, raw(t, asn1.TagSequence,
				asn1.RawValue{FullBytes: mustMarshal(t, 1)}))))), "carries no content"},
		{"content with a type and nothing in it",
			encoded(t, raw(t, asn1.TagSequence, signedType, explicit(encoded(t, raw(t, asn1.TagSequence,
				asn1.RawValue{FullBytes: mustMarshal(t, 1)}, raw(t, asn1.TagSet),
				raw(t, asn1.TagSequence, contentType)))))), "not a certificate trust list"},
		{"a trust list that is not a sequence",
			envelope(t, asn1.RawValue{FullBytes: mustMarshal(t, 7)}, listOptions{outer: signedData, content: certificateTrustList}),
			"is not a sequence"},
		{"a trust list with no subject usage", trustList(t), "no subject usage"},
		{"a trust list with no date", trustList(t, usage), "no date"},
		{"a trust list with no algorithm", trustList(t, usage, date), "no subject algorithm"},
		{"a trust list with no entries", trustList(t, usage, date, algorithm), "no entries"},
		{"a property whose value is not an octet string",
			attribute(nameProperty, raw(t, asn1.TagSet, asn1.RawValue{FullBytes: mustMarshal(t, 5)})), "carries no value"},
		{"a property with no value at all",
			attribute(nameProperty, raw(t, asn1.TagSet)), "carries no value"},
		{"an attribute whose type is not an identifier",
			attribute(asn1.RawValue{FullBytes: mustMarshal(t, 5)}, raw(t, asn1.TagSet)), "could not be read"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseProgramList(c.der, testClock)
			if err == nil {
				t.Fatalf("%s was accepted", c.name)
			}
			if !strings.Contains(err.Error(), c.says) {
				t.Errorf("the refusal %q does not say %q", err, c.says)
			}
		})
	}
}

// trustList wraps the given CTL_INFO fields in the envelope the registry uses.
func trustList(t *testing.T, fields ...asn1.RawValue) []byte {
	t.Helper()
	return envelope(t, raw(t, asn1.TagSequence, fields...), listOptions{outer: signedData, content: certificateTrustList})
}
