package systemstore

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// programList is this machine's local copy of the list of roots in Microsoft's
// root program - the one thing that tells "a public root Windows has not fetched
// yet" from "an authority nobody here installed" without asking the network.
//
// SOURCES, inviolable rule 18, read 2026-10-13 and 2026-10-14:
//
//   - the list lives in the registry, beside the list of distrusted roots -
//     https://learn.microsoft.com/windows-server/identity/ad-cs/certificate-trust
//   - each entry's SubjectIdentifier is the SHA1 of the certificate, and each
//     property is an attribute whose type is szOID_CERT_PROP_ID_PREFIX followed by
//     the decimal property number -
//     https://learn.microsoft.com/windows/win32/api/wincrypt/nf-wincrypt-certcreatectlentryfromcertificatecontextproperties
//   - property 20 is the key identifier and property 29 the MD5 of the subject
//     name - https://learn.microsoft.com/windows/win32/api/certenroll/ne-certenroll-certenroll_propertyid
//
// MEASURED 2026-10-13 against the roots this machine already holds: 78 roots on
// the list, the key identifier matched in 72 of 72 that carry one, the name hash
// in 78 of 78, and not one disagreement.
//
// THE SIGNATURE ON THE LIST IS NOT CHECKED, AND THAT IS SAID RATHER THAN
// HIDDEN. Whoever can write this registry key already owns the machine, and
// could install a root into the store itself - so a forged list buys nothing a
// forged store does not. What it could buy is a wrong answer from THIS program,
// and the only answer the list can turn into a FAIL is "not on it", which a
// forger has no reason to fake.
type programList struct {
	// subjects are the SHA1 fingerprints of the roots on the list, hex encoded.
	subjects map[string]bool
	// keys and names are the two ways a certificate points at its issuer - the
	// authority key identifier and the issuer's name - turned into what the list
	// records for each root.
	//
	// EVERY ENTRY IS KEPT, NOT THE FIRST. Measured: 562 entries carry 553
	// distinct keys and 549 distinct name hashes, so several roots share one, and
	// a lookup that stopped at the first would only be right by luck.
	keys  map[string]bool
	names map[string]bool
	// synced is when Windows last brought the list up to date, and is zero when
	// the machine records no such time.
	synced time.Time
	// unreadable says why there is no list, and is empty when there is one.
	unreadable string
}

// unavailableList is the answer when there is no list to consult. It is a list
// that can rule nothing out, which is the honest direction - every question it
// is asked then comes back undetermined rather than refused.
func unavailableList(why string) programList {
	return programList{unreadable: why}
}

// available reports whether there is a list to consult at all.
func (l programList) available() bool { return l.unreadable == "" }

// holdsRoot reports whether this exact certificate is a root on the list.
func (l programList) holdsRoot(der []byte) bool {
	sum := sha1.Sum(der)
	return l.subjects[hex.EncodeToString(sum[:])]
}

// namesIssuerOf reports whether the issuer this certificate points at is a root
// on the list, matched by key or by name.
//
// EITHER MATCH IS ENOUGH, AND THE DIRECTION OF THAT CHOICE IS THE POINT. A match
// makes the answer "undetermined" and never "refused", so a match that should
// not have happened - two authorities sharing a name - costs a weaker report and
// never an accusation. Only the absence of BOTH can become a FAIL.
func (l programList) namesIssuerOf(c *x509.Certificate) bool {
	if len(c.AuthorityKeyId) > 0 && l.keys[hex.EncodeToString(c.AuthorityKeyId)] {
		return true
	}
	sum := md5.Sum(c.RawIssuer)
	return l.names[hex.EncodeToString(sum[:])]
}

// The identifiers the list is wrapped in. Both are checked, so that a value
// holding something else is refused rather than read as a list of roots.
var (
	// signedData is PKCS #7 SignedData, RFC 2315 section 9.
	signedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	// certificateTrustList is szOID_CTL, which the list carried when measured.
	certificateTrustList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 1}
)

// propertyPrefix is szOID_CERT_PROP_ID_PREFIX, and the two properties after it
// are the only ones read here.
const (
	propertyPrefix         = "1.3.6.1.4.1.311.10.11."
	keyIdentifierProperty  = "20"
	subjectNameMD5Property = "29"
)

// parseProgramList reads the list out of the bytes the registry holds.
//
// THE FIELD ORDER IS CTL_INFO's, AND THE ENCODING WAS MEASURED. CTL_INFO is
// documented at https://learn.microsoft.com/windows/win32/api/wincrypt/ns-wincrypt-ctl_info
// as version, subject usage, list identifier, sequence number, this update, next
// update, subject algorithm, entries and extensions - and the copy on this
// machine, read 2026-10-14, carried no version, no list identifier and NO NEXT
// UPDATE, which is why nothing in the list itself says when it goes stale. The
// optional fields are therefore skipped by what they ARE rather than counted by
// position, because counting would read the algorithm as the entries the day an
// optional field appears.
//
// ANY SURPRISE IS AN ERROR, and an error makes the list unavailable - which can
// only ever turn a FAIL into an undetermined, never the other way round.
func parseProgramList(der []byte, synced time.Time) (programList, error) {
	content, err := unwrap(der)
	if err != nil {
		return programList{}, err
	}
	entries, err := trustedSubjects(content)
	if err != nil {
		return programList{}, err
	}

	list := programList{subjects: map[string]bool{}, keys: map[string]bool{}, names: map[string]bool{}, synced: synced}
	for _, entry := range entries {
		if err := list.add(entry); err != nil {
			return programList{}, err
		}
	}
	if len(list.subjects) == 0 {
		// A list naming nothing would make every authority look absent from the
		// program, which is a FAIL manufactured out of an empty value.
		return programList{}, errors.New("the list names no root at all")
	}
	return list, nil
}

// unwrap takes the list out of its PKCS #7 envelope.
func unwrap(der []byte) (asn1.RawValue, error) {
	outer, err := sequenceOf(der, "the outer envelope")
	if err != nil {
		return asn1.RawValue{}, err
	}
	if len(outer) < 2 || !isObject(outer[0], signedData) || !isExplicit(outer[1]) {
		return asn1.RawValue{}, errors.New("the value is not a signed PKCS #7 message")
	}
	signed, err := sequenceOf(outer[1].Bytes, "the signed data")
	if err != nil {
		return asn1.RawValue{}, err
	}
	if len(signed) < 3 || !isSequence(signed[2]) {
		return asn1.RawValue{}, errors.New("the signed data carries no content")
	}
	encapsulated, err := elements(signed[2])
	if err != nil {
		return asn1.RawValue{}, err
	}
	if len(encapsulated) < 2 || !isObject(encapsulated[0], certificateTrustList) || !isExplicit(encapsulated[1]) {
		return asn1.RawValue{}, errors.New("the signed content is not a certificate trust list")
	}
	var content asn1.RawValue
	if _, err := asn1.Unmarshal(encapsulated[1].Bytes, &content); err != nil {
		return asn1.RawValue{}, fmt.Errorf("the certificate trust list could not be read: %w", err)
	}
	if !isSequence(content) {
		return asn1.RawValue{}, errors.New("the certificate trust list is not a sequence")
	}
	return content, nil
}

// trustedSubjects walks CTL_INFO to its list of entries.
func trustedSubjects(content asn1.RawValue) ([]asn1.RawValue, error) {
	fields, err := elements(content)
	if err != nil {
		return nil, err
	}
	at := 0
	next := func(want func(asn1.RawValue) bool) bool {
		if at < len(fields) && want(fields[at]) {
			at++
			return true
		}
		return false
	}
	next(isInteger) // version, absent when it is the default
	if !next(isSequence) {
		return nil, errors.New("the list carries no subject usage")
	}
	next(isOctets)  // list identifier
	next(isInteger) // sequence number
	if !next(isTime) {
		return nil, errors.New("the list carries no date")
	}
	next(isTime) // next update - absent on the copy measured here
	if !next(isSequence) {
		return nil, errors.New("the list carries no subject algorithm")
	}
	if at >= len(fields) || !isSequence(fields[at]) {
		return nil, errors.New("the list carries no entries")
	}
	return elements(fields[at])
}

// add records one entry: its fingerprint and the two properties read here.
func (l *programList) add(entry asn1.RawValue) error {
	parts, err := elements(entry)
	if err != nil {
		return err
	}
	if len(parts) == 0 || !isOctets(parts[0]) || len(parts[0].Bytes) == 0 {
		return errors.New("an entry carries no subject identifier")
	}
	l.subjects[hex.EncodeToString(parts[0].Bytes)] = true
	if len(parts) < 2 {
		return nil
	}
	if !isSet(parts[1]) {
		return errors.New("an entry carries attributes that are not a set")
	}
	attributes, err := elements(parts[1])
	if err != nil {
		return err
	}
	for _, attribute := range attributes {
		property, value, err := propertyOf(attribute)
		if err != nil {
			return err
		}
		switch property {
		case keyIdentifierProperty:
			l.keys[hex.EncodeToString(value)] = true
		case subjectNameMD5Property:
			l.names[hex.EncodeToString(value)] = true
		}
	}
	return nil
}

// propertyOf reads one attribute and answers which property it carries and its
// value, or an empty property for an attribute that is not a property at all.
func propertyOf(attribute asn1.RawValue) (string, []byte, error) {
	parts, err := elements(attribute)
	if err != nil {
		return "", nil, err
	}
	if len(parts) < 2 || !isSet(parts[1]) {
		return "", nil, errors.New("an attribute carries no set of values")
	}
	var kind asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(parts[0].FullBytes, &kind); err != nil {
		return "", nil, fmt.Errorf("an attribute type could not be read: %w", err)
	}
	property, isProperty := strings.CutPrefix(kind.String(), propertyPrefix)
	if !isProperty {
		return "", nil, nil
	}
	values, err := elements(parts[1])
	if err != nil {
		return "", nil, err
	}
	if len(values) == 0 || !isOctets(values[0]) {
		return "", nil, fmt.Errorf("property %s carries no value", property)
	}
	return property, values[0].Bytes, nil
}

// sequenceOf reads bytes that must hold one sequence and returns its elements.
func sequenceOf(der []byte, what string) ([]asn1.RawValue, error) {
	var value asn1.RawValue
	if _, err := asn1.Unmarshal(der, &value); err != nil {
		return nil, fmt.Errorf("%s could not be read: %w", what, err)
	}
	if !isSequence(value) {
		return nil, fmt.Errorf("%s is not a sequence", what)
	}
	return elements(value)
}

// elements splits a constructed value into the values inside it.
func elements(value asn1.RawValue) ([]asn1.RawValue, error) {
	var out []asn1.RawValue
	rest := value.Bytes
	for len(rest) > 0 {
		var element asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &element); err != nil {
			return nil, fmt.Errorf("the list could not be read: %w", err)
		}
		out = append(out, element)
	}
	return out, nil
}

func isSequence(v asn1.RawValue) bool {
	return v.Class == asn1.ClassUniversal && v.Tag == asn1.TagSequence && v.IsCompound
}

// isSet is a separate question from isSequence because the attribute values
// travel in a SET, and reading one as the other is how a parser accepts
// whatever it is handed.
func isSet(v asn1.RawValue) bool {
	return v.Class == asn1.ClassUniversal && v.Tag == asn1.TagSet && v.IsCompound
}

func isInteger(v asn1.RawValue) bool {
	return v.Class == asn1.ClassUniversal && v.Tag == asn1.TagInteger
}

func isOctets(v asn1.RawValue) bool {
	return v.Class == asn1.ClassUniversal && v.Tag == asn1.TagOctetString && !v.IsCompound
}

func isTime(v asn1.RawValue) bool {
	return v.Class == asn1.ClassUniversal && (v.Tag == asn1.TagUTCTime || v.Tag == asn1.TagGeneralizedTime)
}

func isExplicit(v asn1.RawValue) bool {
	return v.Class == asn1.ClassContextSpecific && v.Tag == 0 && v.IsCompound
}

func isObject(v asn1.RawValue, want asn1.ObjectIdentifier) bool {
	var got asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(v.FullBytes, &got); err != nil {
		return false
	}
	return got.Equal(want)
}
