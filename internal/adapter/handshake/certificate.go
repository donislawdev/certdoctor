package handshake

import (
	"crypto/x509"
	"fmt"

	core "github.com/donislawdev/certdoctor/internal/core/handshake"
	"github.com/donislawdev/certdoctor/internal/tool/certfacts"
)

// certificates turns what arrived on the wire into records with no code attached
// to them.
//
// PARSING SOMEBODY ELSE'S DATA BELONGS ON THIS SIDE - docs/22 row 3. The core
// never sees an x509.Certificate: it sees a struct of strings, times and
// booleans, which is why the whole of L4's grading can be tested on recorded
// evidence with no network anywhere near it.
func certificates(chain []*x509.Certificate) []core.Certificate {
	if chain == nil {
		return nil
	}
	out := make([]core.Certificate, 0, len(chain))
	for _, certificate := range chain {
		out = append(out, summarise(certificate))
	}
	if len(out) > 0 {
		out[0].IssuerSent = issuerSent(chain)
	}
	return out
}

// issuerSent says whether the issuer of the first certificate is among the
// others that arrived, by the rule certfacts.IssuedBy keeps for this layer and
// the cert tool alike: its subject is the leaf's issuer and its key verifies
// the leaf's signature - ADR114, ADR146.
//
// IN ANY POSITION, not only the next one. RFC 8446 section 4.4.2 asks
// receivers to cope with certificates in any order after the first.
func issuerSent(chain []*x509.Certificate) bool {
	for _, candidate := range chain[1:] {
		if certfacts.IssuedBy(chain[0], candidate) {
			return true
		}
	}
	return false
}

// summarise is one certificate, exactly as it was presented.
func summarise(certificate *x509.Certificate) core.Certificate {
	return core.Certificate{
		// BOTH NAMES GO THROUGH ONE FUNCTION, certfacts.Name, and the
		// completeness check is what makes that load bearing rather than tidy:
		// whether the issuer of the leaf arrived starts as a string comparison.
		// The same failure tcp.Target exists to prevent one layer down.
		Subject:   certfacts.Name(certificate.Subject),
		Issuer:    certfacts.Name(certificate.Issuer),
		NotBefore: certificate.NotBefore,
		NotAfter:  certificate.NotAfter,
		// Over the raw DER, by the one function the cert tool prints it with.
		FingerprintSHA256: certfacts.FingerprintSHA256(certificate.Raw),
		// EXACTLY AS PRESENTED, in the order presented, and never rebuilt from the
		// common name. RFC 6125 section 6.4.4 makes these the identity a client
		// matches on; inventing one from the subject would be this program
		// answering with the field the client is forbidden to use.
		DNSNames:    append([]string(nil), certificate.DNSNames...),
		IsCA:        certificate.IsCA,
		IPAddresses: addresses(certificate),
		// THE SAME BYTES THE FINGERPRINT WAS TAKEN OVER, copied rather than aliased
		// so nothing downstream can write into a buffer the parser still owns. L5
		// needs them to verify a path, which a summary cannot support.
		Raw: append([]byte(nil), certificate.Raw...),
		// FROM THE SIGNATURE, NOT FROM THE NAMES MATCHING ALONE - certfacts
		// says why. Treating a certificate that merely names itself as its
		// issuer as self-signed would call a broken chain complete, which is the
		// exact verdict this layer exists to get right.
		SelfSigned: certfacts.SelfSigned(certificate),
	}
}

// addresses renders the iPAddress entries the way the standard library spells
// an address, or nil when there are none.
func addresses(certificate *x509.Certificate) []string {
	var out []string
	for _, ip := range certificate.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

// nameMatch says whether the leaf covers the name this run asked for - ADR106.
//
// THE MATCHING RULES ARE THE STANDARD LIBRARY'S AND NEVER A COPY OF OURS.
// VerifyHostname carries the wildcard, case and address rules, and a second
// implementation here would be a claim about RFC 6125 that nothing keeps
// current. Measured 2026-10-19 on Go 1.27.2: a wildcard does not cover two
// labels (wrong.host.badssl.com against *.badssl.com), upper case matches, a
// trailing dot on the name matches, and an address is compared with iPAddress
// entries only, bracketed or not.
//
// THE NAME IS THE ONE THIS RUN SENT IN SNI, or the address when the target was
// given as one - the entry point hands the wire spelling, so an international
// name is compared in the A-label form a certificate carries. Go sends no SNI
// for an address (measured the same day), and the check still runs against it.
//
// THE COMMON NAME IS ASKED ABOUT ONLY WHEN THERE IS NO subjectAltName AT ALL,
// which is the one case RFC 6125 section 6.4.4 let a client fall back to it.
// It is asked through the same library function, handed a copy of the
// certificate whose only DNS name is that common name, so the wildcard and
// case rules stay the library's. Go's own error for this case names it in
// words, and recognising those words would be inviolable rule 19 broken.
func nameMatch(chain []*x509.Certificate, name string) core.NameMatch {
	if len(chain) == 0 || name == "" {
		return core.NameUnchecked
	}
	leaf := chain[0]
	if leaf.VerifyHostname(name) == nil {
		return core.NameCovered
	}
	if !certfacts.HasSubjectAltName(leaf) && leaf.Subject.CommonName != "" {
		legacy := *leaf
		legacy.DNSNames = []string{leaf.Subject.CommonName}
		if legacy.VerifyHostname(name) == nil {
			return core.NameInCommonNameOnly
		}
	}
	return core.NameNotCovered
}

// CertificateFrom summarises one certificate straight from its DER bytes.
//
// IT EXISTS SO THE SUMMARISING CAN BE FUZZED. Everything above runs on values
// crypto/x509 has already accepted, which means the parsing of somebody else's
// data - the row docs/22 names as its own failure mode - is reachable only
// through a real connection. This is the same path with the connection taken
// out, so a corpus of malformed certificates can be thrown at it directly.
//
// It is exported for that reason and for no other. Nothing in the program's own
// path calls it: the handshake hands over certificates the library has parsed.
func CertificateFrom(der []byte) (core.Certificate, error) {
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		// REFUSED, NEVER GUESSED AT. A record built out of a certificate nothing
		// could parse would be this program inventing a fact about somebody
		// else's server.
		return core.Certificate{}, fmt.Errorf("this is not a certificate anything could read: %w", err)
	}
	return summarise(parsed), nil
}
