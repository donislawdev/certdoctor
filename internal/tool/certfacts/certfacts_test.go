package certfacts

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func parse(t testing.TB, text string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		t.Fatal("a fixture is not PEM")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("a fixture does not parse: %v", err)
	}
	return c
}

// TestSelfSignedIsTheSignatureAndTheName holds the two parts of RFC 5280
// section 3.2: the name, and the key verifying the signature - whatever the CA
// flag says (OBS163).
func TestSelfSignedIsTheSignatureAndTheName(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fixture string
		want    bool
	}{
		{"a root", fixtureRoot, true},
		{"a server certificate that signed itself, CA:FALSE", fixtureSelfSignedServer, true},
		{"a certificate naming itself as issuer, signed by another key", fixtureNamesItself, false},
		{"an intermediate", fixtureIntermediate, false},
	} {
		c := parse(t, tc.fixture)
		if tc.name == "a certificate naming itself as issuer, signed by another key" && Name(c.Subject) != Name(c.Issuer) {
			t.Fatal("the fixture does not name itself as its issuer, so it proves nothing")
		}
		if got := SelfSigned(c); got != tc.want {
			t.Errorf("%s: SelfSigned = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestTheIssuerIsTheNameAndTheKey holds ADR114: a certificate of the issuer's
// name under another key is not the issuer, and a signature nothing can check
// leaves the name to decide.
func TestTheIssuerIsTheNameAndTheKey(t *testing.T) {
	root, inter, leaf := parse(t, fixtureRoot), parse(t, fixtureIntermediate), parse(t, fixtureLeaf)
	impostor, rsaRoot, md5 := parse(t, fixtureImpostor), parse(t, fixtureRSARoot), parse(t, fixtureMD5)
	if Name(impostor.Subject) != Name(inter.Subject) {
		t.Fatal("the impostor does not carry the intermediate's name, so it proves nothing")
	}
	if md5.SignatureAlgorithm != x509.MD5WithRSA {
		t.Fatalf("the MD5 fixture is signed with %v", md5.SignatureAlgorithm)
	}
	for _, tc := range []struct {
		name          string
		child, parent *x509.Certificate
		want          bool
	}{
		{"the leaf by its intermediate", leaf, inter, true},
		{"the intermediate by the root", inter, root, true},
		{"the leaf by a certificate of its issuer's name under another key", leaf, impostor, false},
		{"the leaf by a certificate of another name", leaf, root, false},
		{"an MD5 signature by the certificate its name points at", md5, rsaRoot, true},
		{"an MD5 signature by a certificate of another name", md5, root, false},
	} {
		if got := IssuedBy(tc.child, tc.parent); got != tc.want {
			t.Errorf("%s: IssuedBy = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestASubjectAltNameIsFoundByItsIdentifier holds ADR106: an extension holding
// only an e-mail address is still a subjectAltName, though it carries no DNS
// name and no address.
func TestASubjectAltNameIsFoundByItsIdentifier(t *testing.T) {
	mail := parse(t, fixtureEmailOnly)
	if len(mail.DNSNames)+len(mail.IPAddresses) != 0 || len(mail.EmailAddresses) != 1 {
		t.Fatal("the e-mail fixture is not an e-mail address alone, so it proves nothing")
	}
	for _, tc := range []struct {
		name    string
		fixture string
		want    bool
	}{
		{"names and an address", fixtureLeaf, true},
		{"an e-mail address alone", fixtureEmailOnly, true},
		{"no extension at all", fixtureCommonNameOnly, false},
	} {
		if got := HasSubjectAltName(parse(t, tc.fixture)); got != tc.want {
			t.Errorf("%s: HasSubjectAltName = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestTheNameAndTheFingerprintAreSpelledOneWay pins the two spellings the
// report and the tool both print.
func TestTheNameAndTheFingerprintAreSpelledOneWay(t *testing.T) {
	if got, want := Name(parse(t, fixtureLeaf).Subject), "CN=leaf.example.test,O=certdoctor tests"; got != want {
		t.Errorf("Name = %q, want %q", got, want)
	}
	// SHA-256 of "abc", FIPS 180-2 appendix B.1.
	if got, want := FingerprintSHA256([]byte("abc")),
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"; got != want {
		t.Errorf("FingerprintSHA256 = %q, want %q", got, want)
	}
}

// FuzzFacts holds that no certificate the library accepts makes a rule here
// fall over, alone or against the fixtures.
func FuzzFacts(f *testing.F) {
	for _, text := range []string{fixtureRoot, fixtureLeaf, fixtureMD5, fixtureEmailOnly, fixtureNamesItself} {
		block, _ := pem.Decode([]byte(text))
		f.Add(block.Bytes)
	}
	others := []*x509.Certificate{parse(f, fixtureRoot), parse(f, fixtureIntermediate), parse(f, fixtureRSARoot)}
	f.Fuzz(func(t *testing.T, der []byte) {
		if len(FingerprintSHA256(der)) != 64 {
			t.Fatal("a fingerprint is not 64 hex digits")
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return
		}
		_, _, _ = Name(c.Subject), SelfSigned(c), HasSubjectAltName(c)
		for _, o := range others {
			_, _ = IssuedBy(c, o), IssuedBy(o, c)
		}
	})
}
