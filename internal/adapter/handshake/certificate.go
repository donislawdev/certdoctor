package handshake

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
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
		DNSNames: append([]string(nil), certificate.DNSNames...),
		IsCA:     certificate.IsCA,
		// THE SAME BYTES THE FINGERPRINT WAS TAKEN OVER, copied rather than aliased
		// so nothing downstream can write into a buffer the parser still owns. L5
		// needs them to verify a path, which a summary cannot support.
		Raw: append([]byte(nil), certificate.Raw...),
		// FROM THE SIGNATURE, NOT FROM THE NAMES MATCHING. A certificate can name
		// itself as its own issuer without having signed itself, and treating that
		// as self-signed would call a broken chain complete - which is the exact
		// verdict this layer exists to get right.
		SelfSigned: certificate.CheckSignatureFrom(certificate) == nil,
	}
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
