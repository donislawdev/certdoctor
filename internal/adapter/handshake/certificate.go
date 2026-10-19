package handshake

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"

	core "github.com/donislawdev/certdoctor/internal/core/handshake"
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
	return out
}

// summarise is one certificate, exactly as it was presented.
func summarise(certificate *x509.Certificate) core.Certificate {
	return core.Certificate{
		// BOTH NAMES GO THROUGH ONE FUNCTION, and the completeness check is what
		// makes that load bearing rather than tidy. L4 asks whether the issuer of
		// the leaf is the subject of anything else that arrived, which is a STRING
		// COMPARISON: two spellings of one distinguished name would report a
		// complete chain as broken, and send somebody to fix a server that is
		// already correct. The same failure tcp.Target exists to prevent one layer
		// down.
		Subject:   distinguishedName(certificate.Subject),
		Issuer:    distinguishedName(certificate.Issuer),
		NotBefore: certificate.NotBefore,
		NotAfter:  certificate.NotAfter,
		// OVER THE RAW DER, which is what identifies a certificate exactly. A
		// fingerprint over anything we re-encoded would be a fingerprint of our
		// parser, and two programs would then disagree about the same bytes.
		FingerprintSHA256: fingerprint(certificate.Raw),
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
		// FROM THE SIGNATURE, NOT FROM THE NAMES MATCHING ALONE. A certificate can
		// name itself as its own issuer without having signed itself, and treating
		// that as self-signed would call a broken chain complete - which is the
		// exact verdict this layer exists to get right.
		SelfSigned: selfSigned(certificate),
	}
}

// selfSigned says whether a certificate issued itself: its issuer is its own
// subject, and its own key verifies its signature. RFC 5280 section 3.2 defines
// the term with exactly those two parts, for CA certificates. The same test is
// applied here whatever the CA flag says, because that flag is about what the
// key may sign for others - section 4.2.1.9 - and not about whether it signed
// this.
//
// NOT CheckSignatureFrom, AND THE REASON IS MEASURED. That function refuses a
// "parent" that is not an authority - crypto/x509/x509.go in Go 1.27.2, the
// RFC 5280 section 4.2.1.9 check at its top - so a self-signed SERVER
// certificate, which carries CA:FALSE like the one self-signed.badssl.com
// presents, came back as not self-signed, and L4 told the reader that the
// server had withheld an issuer which does not exist (OBS163, 2026-10-19).
// CheckSignature asks only whether the key verifies the bytes.
//
// THE NAMES GO THROUGH distinguishedName, the one function chain completeness
// compares by, so "issued itself" and "its issuer arrived" cannot disagree
// about the same two names.
func selfSigned(certificate *x509.Certificate) bool {
	if distinguishedName(certificate.Subject) != distinguishedName(certificate.Issuer) {
		return false
	}
	return certificate.CheckSignature(certificate.SignatureAlgorithm, certificate.RawTBSCertificate, certificate.Signature) == nil
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
	if !hasSubjectAltName(leaf) && leaf.Subject.CommonName != "" {
		legacy := *leaf
		legacy.DNSNames = []string{leaf.Subject.CommonName}
		if legacy.VerifyHostname(name) == nil {
			return core.NameInCommonNameOnly
		}
	}
	return core.NameNotCovered
}

// oidSubjectAltName is id-ce-subjectAltName, RFC 5280 section 4.2.1.6.
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// hasSubjectAltName asks whether the extension is present at all, by its
// identifier. Asking whether the parsed lists are empty instead would call a
// certificate whose subjectAltName holds only entries Go does not parse - a
// directory name, say - one that has none, and fall back to the common name
// RFC 6125 forbade in exactly that case.
func hasSubjectAltName(certificate *x509.Certificate) bool {
	for _, extension := range certificate.Extensions {
		if extension.Id.Equal(oidSubjectAltName) {
			return true
		}
	}
	return false
}

// distinguishedName renders one name, and it is the ONE function that does.
//
// It is a named function rather than a call to String() at each site precisely
// because there are two sites. A subject rendered one way and an issuer rendered
// another is not a formatting difference - it is a complete chain reported as
// broken, silently, on somebody else's working server.
func distinguishedName(name pkix.Name) string { return name.String() }

// fingerprint is the SHA-256 of the presented bytes, lower case hex.
//
// It is never masked and never shortened: it is the evidence inviolable rule 21
// requires beside any claim about interception, and half a fingerprint cannot be
// compared against anything.
func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
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
