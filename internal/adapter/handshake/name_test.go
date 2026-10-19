package handshake

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	core "github.com/donislawdev/certdoctor/internal/core/handshake"
)

// Whether the leaf covers the name this run asked for - ADR106, closing OBS162:
// wrong.host.badssl.com read "Everything assessed passed" because nothing in
// the program asked.

// issuedFor mints a self-signed leaf with exactly the identities given. The
// signature does not matter here: the name is a question about the leaf alone.
func issuedFor(t *testing.T, commonName string, dns []string, ips []net.IP, emails []string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	serial++
	template := &x509.Certificate{
		SerialNumber:   big.NewInt(serial),
		Subject:        pkix.Name{CommonName: commonName},
		DNSNames:       dns,
		IPAddresses:    ips,
		EmailAddresses: emails,
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("signing %q: %v", commonName, err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("reading back %q: %v", commonName, err)
	}
	return parsed
}

// TestTheNameIsMatchedByTheLibrarysRules walks the cases measured on Go 1.27.2
// before the code existed, plus the three that decide the common name.
func TestTheNameIsMatchedByTheLibrarysRules(t *testing.T) {
	badssl := []string{"*.badssl.com", "badssl.com"}
	address := []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")}
	for _, c := range []struct {
		name   string
		leaf   *x509.Certificate
		host   string
		want   core.NameMatch
		reason string
	}{
		{"two labels under a wildcard", issuedFor(t, "*.badssl.com", badssl, nil, nil), "wrong.host.badssl.com", core.NameNotCovered,
			"OBS162 itself: a wildcard covers one label"},
		{"one label under a wildcard", issuedFor(t, "*.badssl.com", badssl, nil, nil), "a.badssl.com", core.NameCovered, ""},
		{"upper case", issuedFor(t, "*.badssl.com", badssl, nil, nil), "A.BadSSL.COM", core.NameCovered,
			"names are compared without regard to case"},
		{"a trailing dot", issuedFor(t, "*.badssl.com", badssl, nil, nil), "a.badssl.com.", core.NameCovered,
			"a fully qualified name is the same name"},
		{"an address in the subjectAltName", issuedFor(t, "x", []string{"example.com"}, address, nil), "192.0.2.1", core.NameCovered, ""},
		{"an address that is not", issuedFor(t, "x", []string{"example.com"}, address, nil), "192.0.2.2", core.NameNotCovered, ""},
		{"an IPv6 address", issuedFor(t, "x", []string{"example.com"}, address, nil), "2001:db8::1", core.NameCovered, ""},
		{"only the common name, no subjectAltName", issuedFor(t, "legacy.example.com", nil, nil, nil), "legacy.example.com",
			core.NameInCommonNameOnly, "the one case RFC 6125 let a client fall back to"},
		{"a wildcard common name, no subjectAltName", issuedFor(t, "*.example.com", nil, nil, nil), "a.example.com",
			core.NameInCommonNameOnly, "the wildcard rule for it is the library's too"},
		{"a common name for another host", issuedFor(t, "legacy.example.com", nil, nil, nil), "other.example.com",
			core.NameNotCovered, ""},
		{"a common name beside a subjectAltName", issuedFor(t, "legacy.example.com", []string{"other.example.com"}, nil, nil),
			"legacy.example.com", core.NameNotCovered, "with a subjectAltName present nothing falls back to the common name"},
		{"a subjectAltName holding only an e-mail address", issuedFor(t, "legacy.example.com", nil, nil, []string{"ops@example.com"}),
			"legacy.example.com", core.NameNotCovered,
			"the extension is there, so the common name is not asked - empty DNS and address lists are not the same as no extension"},
		{"an address only in the common name", issuedFor(t, "192.0.2.9", nil, nil, nil), "192.0.2.9", core.NameNotCovered,
			"an address is matched against iPAddress entries only"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := nameMatch([]*x509.Certificate{c.leaf}, c.host); got != c.want {
				t.Errorf("%s against %v gave %v, want %v - %s", c.host, c.leaf.DNSNames, got, c.want, c.reason)
			}
		})
	}
}

// TestNothingToCheckIsNotAnAnswer pins the zero value's two producers. A
// missing leaf or a missing name answered as "covered" would be the false
// reassurance this whole check exists to remove, and answered as "not covered"
// it would accuse a server of a name nobody asked about.
func TestNothingToCheckIsNotAnAnswer(t *testing.T) {
	if got := nameMatch(nil, "partner.test"); got != core.NameUnchecked {
		t.Errorf("no certificate gave %v", got)
	}
	leaf := issuedFor(t, "partner.test", []string{"partner.test"}, nil, nil)
	if got := nameMatch([]*x509.Certificate{leaf}, ""); got != core.NameUnchecked {
		t.Errorf("no name gave %v", got)
	}
	// The positive twin on the same leaf - OBS56.
	if got := nameMatch([]*x509.Certificate{leaf}, "partner.test"); got != core.NameCovered {
		t.Errorf("the leaf's own name gave %v", got)
	}
}

// TestTheHandshakeSaysWhetherTheLeafFitsTheName is the wiring: what a real
// handshake hands to L4 carries the answer, for the name that went out in SNI.
func TestTheHandshakeSaysWhetherTheLeafFitsTheName(t *testing.T) {
	_, intermediate, leaf := bundle(t)

	for _, c := range []struct {
		sent string
		want core.NameMatch
	}{
		{"partner.test", core.NameCovered},
		{"other.test", core.NameNotCovered},
	} {
		host, port := serve(t, serverConfig(leaf, intermediate, true))
		shown, err := Shake(func(string) error { return nil })(context.Background(), host, port, c.sent)
		if err != nil {
			t.Fatalf("the handshake failed: %v", err)
		}
		if shown.Name != c.want {
			t.Errorf("asking for %s against a leaf for partner.test gave %v, want %v", c.sent, shown.Name, c.want)
		}
	}
}

// TestTheAddressesOfALeafAreSummarised feeds the sentence that lists what a
// certificate covers, so a target given as an address is not told the
// certificate names nothing.
func TestTheAddressesOfALeafAreSummarised(t *testing.T) {
	leaf := issuedFor(t, "x", nil, []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")}, nil)
	got := summarise(leaf).IPAddresses
	if len(got) != 2 || got[0] != "192.0.2.1" || got[1] != "2001:db8::1" {
		t.Errorf("the addresses came out as %v", got)
	}
	if none := summarise(issuedFor(t, "x", []string{"x.test"}, nil, nil)).IPAddresses; len(none) != 0 {
		t.Errorf("a leaf with no addresses summarised as %v", none)
	}
}
