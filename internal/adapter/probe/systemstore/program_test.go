package systemstore

import (
	"crypto/md5"
	"encoding/asn1"
	"strings"
	"testing"
)

// The program list parser. It reads a value somebody else wrote, so every
// refusal below has a positive twin on the same fixture - OBS56 - and the
// direction of every refusal is the safe one: no list means "undetermined",
// never "refused".

func TestAListIsReadAndAnswersByFingerprintKeyAndName(t *testing.T) {
	onList := anAuthority(t, "on the list")
	offList := anAuthority(t, "off the list")
	list := aListHolding(t, testClock, onList.certificate)

	if !list.available() {
		t.Fatalf("a well formed list is unavailable: %s", list.unreadable)
	}
	if !list.holdsRoot(onList.certificate.Raw) {
		t.Error("the root on the list is not found by its fingerprint")
	}
	if list.holdsRoot(offList.certificate.Raw) {
		t.Error("a root the list does not name is found by its fingerprint")
	}
	if !list.namesIssuerOf(aLeaf(t, onList, leafOptions{})) {
		t.Error("a leaf signed by the root on the list is not matched to it")
	}
	if list.namesIssuerOf(aLeaf(t, offList, leafOptions{})) {
		t.Error("a leaf signed by a root the list does not name is matched anyway")
	}
}

// EITHER MATCH IS ENOUGH, and each one is tested alone - a lookup that only
// ever asked one of them would pass a test that asked both at once.
func TestTheIssuerIsMatchedByKeyAloneAndByNameAlone(t *testing.T) {
	root := anAuthority(t, "the issuer")
	leaf := aLeaf(t, root, leafOptions{})

	byKey := entryFor(root.certificate)
	delete(byKey.properties, subjectNameMD5Property)
	keyOnly, err := parseProgramList(encodeList(t, []listEntry{byKey}, listOptions{}), testClock)
	if err != nil {
		t.Fatal(err)
	}
	if !keyOnly.namesIssuerOf(leaf) {
		t.Error("a list carrying only the key identifier did not match the issuer by key")
	}

	byName := entryFor(root.certificate)
	delete(byName.properties, keyIdentifierProperty)
	nameOnly, err := parseProgramList(encodeList(t, []listEntry{byName}, listOptions{}), testClock)
	if err != nil {
		t.Fatal(err)
	}
	if !nameOnly.namesIssuerOf(leaf) {
		t.Error("a list carrying only the subject name hash did not match the issuer by name")
	}

	// A leaf with no authority key identifier can still be matched by name -
	// and the key lookup must not match an empty identifier to anything.
	noKey := *leaf
	noKey.AuthorityKeyId = nil
	if keyOnly.namesIssuerOf(&noKey) {
		t.Error("a leaf with no authority key identifier matched a list holding only keys")
	}
	if !nameOnly.namesIssuerOf(&noKey) {
		t.Error("a leaf with no authority key identifier was not matched by name")
	}
}

// EVERY ENTRY IS KEPT, NOT THE FIRST - measured 2026-10-13, several roots share
// a key or a name. Two entries with one name, and the second is the one asked.
func TestEveryEntryIsKeptWhenSeveralShareAName(t *testing.T) {
	first := anAuthority(t, "shared name")
	second := anAuthority(t, "shared name")
	list := aListHolding(t, testClock, first.certificate, second.certificate)
	if !list.holdsRoot(first.certificate.Raw) || !list.holdsRoot(second.certificate.Raw) {
		t.Error("two roots sharing a name were not both kept")
	}
	if !list.namesIssuerOf(aLeaf(t, second, leafOptions{})) {
		t.Error("the second root sharing a name was not matched")
	}
}

// THE OPTIONAL FIELDS ARE SKIPPED BY WHAT THEY ARE. The copy measured here
// carried no version, no list identifier and no next update - a list that does
// carry them must still be read, and read at the right field.
func TestAListCarryingTheOptionalFieldsIsStillRead(t *testing.T) {
	root := anAuthority(t, "root")
	list, err := parseProgramList(encodeList(t, []listEntry{entryFor(root.certificate)}, listOptions{optional: true}), testClock)
	if err != nil {
		t.Fatalf("a list carrying the optional fields was refused: %v", err)
	}
	if !list.holdsRoot(root.certificate.Raw) {
		t.Error("a list carrying the optional fields was read at the wrong field")
	}
}

// An attribute that is not a property is not a reason to refuse the list, and
// it must not be read as one either.
func TestAnAttributeThatIsNotAPropertyIsPassedOver(t *testing.T) {
	attribute := func(kind asn1.ObjectIdentifier) asn1.RawValue {
		return raw(t, asn1.TagSequence,
			asn1.RawValue{FullBytes: mustMarshal(t, kind)},
			raw(t, asn1.TagSet, asn1.RawValue{Tag: asn1.TagOctetString, Bytes: []byte{9}}))
	}
	property, value, err := propertyOf(attribute(oid(t, propertyPrefix+subjectNameMD5Property)))
	if err != nil || property != subjectNameMD5Property || len(value) != 1 {
		t.Fatalf("the positive twin read as property %q value %v error %v", property, value, err)
	}
	property, value, err = propertyOf(attribute(asn1.ObjectIdentifier{1, 2, 3, 4}))
	if err != nil || property != "" || value != nil {
		t.Errorf("a foreign attribute read as property %q value %v error %v", property, value, err)
	}
}

func TestAListThatIsNotWhatItShouldBeIsRefused(t *testing.T) {
	root := anAuthority(t, "root")
	good := []listEntry{entryFor(root.certificate)}
	if _, err := parseProgramList(encodeList(t, good, listOptions{}), testClock); err != nil {
		t.Fatalf("the positive twin was refused (%v), so every case below proves nothing", err)
	}

	noIdentifier := entryFor(root.certificate)
	noIdentifier.identifier = nil
	name := md5.Sum(root.certificate.RawSubject)

	cases := []struct {
		name string
		der  []byte
		says string
	}{
		{"not ASN.1 at all", []byte("not a list"), "could not be read"},
		{"an envelope that is not signed data",
			encodeList(t, good, listOptions{outer: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}}), "not a signed"},
		{"signed content that is not a trust list",
			encodeList(t, good, listOptions{content: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}}), "not a certificate trust list"},
		{"a list naming nothing", encodeList(t, nil, listOptions{}), "names no root"},
		{"an entry with no identifier", encodeList(t, []listEntry{noIdentifier}, listOptions{}), "no subject identifier"},
		{"attributes that are not a set", attributesAsASequence(t, root, name[:]), "not a set"},
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

// attributesAsASequence is a list whose one entry carries its attributes in a
// SEQUENCE where a SET belongs - the shape a parser that reads one as the other
// would accept without noticing.
func attributesAsASequence(t *testing.T, root issued, name []byte) []byte {
	t.Helper()
	entry := entryFor(root.certificate)
	identifier := asn1.RawValue{Tag: asn1.TagOctetString, Bytes: entry.identifier}
	attribute := raw(t, asn1.TagSequence,
		asn1.RawValue{FullBytes: mustMarshal(t, oid(t, propertyPrefix+subjectNameMD5Property))},
		raw(t, asn1.TagSet, asn1.RawValue{Tag: asn1.TagOctetString, Bytes: name}))
	subject := raw(t, asn1.TagSequence, identifier, raw(t, asn1.TagSequence, attribute))
	fields := []asn1.RawValue{
		{FullBytes: mustMarshal(t, []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 311, 10, 3, 9}})},
		{FullBytes: mustMarshal(t, 42)},
		{FullBytes: func() []byte {
			der, err := asn1.MarshalWithParams(testClock, "utc")
			if err != nil {
				t.Fatal(err)
			}
			return der
		}()},
		{FullBytes: mustMarshal(t, struct{ Algorithm asn1.ObjectIdentifier }{asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}})},
		raw(t, asn1.TagSequence, subject),
	}
	return envelope(t, raw(t, asn1.TagSequence, fields...), listOptions{outer: signedData, content: certificateTrustList})
}

// THE ABSENCE OF A LIST CAN ONLY EVER BE UNDETERMINED. An unavailable list
// holds nothing and says why, and nothing it answers can become a refusal.
func TestAnUnavailableListSaysWhyAndHoldsNothing(t *testing.T) {
	list := unavailableList("could not be read from the registry (gone)")
	if list.available() {
		t.Error("a list with a reason for its absence calls itself available")
	}
	root := anAuthority(t, "root")
	if list.holdsRoot(root.certificate.Raw) || list.namesIssuerOf(aLeaf(t, root, leafOptions{})) {
		t.Error("an unavailable list claimed to know a root")
	}
	if why := list.cannotRuleOut(testClock); !strings.Contains(why, "gone") {
		t.Errorf("an unavailable list does not say why it cannot rule anything out: %q", why)
	}
}
