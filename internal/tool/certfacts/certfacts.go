// Package certfacts holds the facts about a parsed certificate that more than
// one part of this program reads: the diagnosis's L4, which describes the
// chain a server sent, and the cert tool, which describes a chain somebody
// pastes (ADR146 decision 2). Each rule here has this one place, so the report
// and the tool cannot spell a name differently or disagree about which
// certificate issued which.
//
// It is a package of the tools because its rules are pure functions of a
// certificate's bytes - the tools' closed list of the standard library holds
// it - and the adapter of L4 imports it through a door of its own in the layer
// map, beside the tools' contract.
//
// NOT EVERY RULE ABOUT A CERTIFICATE BELONGS HERE. internal/adapter/probe has
// its own "self-signed" for the trust stores, which compares the names as raw
// bytes rather than as rendered strings (OBS232). Folding it in would change
// what L5 answers without a measurement, so it stays where it is until one is
// made.
package certfacts

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
)

// Name renders one distinguished name, and it is the ONE function that does.
//
// THE SUBJECT AND THE ISSUER GO THROUGH THE SAME FUNCTION, and whether a chain
// is complete is decided by that: it starts as a STRING COMPARISON, the issuer
// of one certificate against the subject of another, before any key is asked.
// Two spellings of one name would report a complete chain as broken and send
// somebody to fix a server that is already correct.
func Name(n pkix.Name) string { return n.String() }

// FingerprintSHA256 is the SHA-256 of a certificate's bytes as presented,
// lower case hex.
//
// OVER THE RAW DER, which is what identifies a certificate exactly. A
// fingerprint over anything re-encoded would be a fingerprint of a parser, and
// two programs would then disagree about the same bytes. It is never masked and
// never shortened: it is the evidence inviolable rule 21 requires beside any
// claim about interception, and half a fingerprint cannot be compared.
func FingerprintSHA256(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// SelfSigned says whether a certificate issued itself: its issuer is its own
// subject, and its own key verifies its signature. RFC 5280 section 3.2
// defines the term with exactly those two parts, for CA certificates. The same
// test is applied whatever the CA flag says, because that flag is about what
// the key may sign for others - section 4.2.1.9 - and not about whether it
// signed this.
//
// FROM THE SIGNATURE, NOT FROM THE NAMES ALONE. A certificate can name itself
// as its own issuer without having signed itself, and treating that as
// self-signed would call a broken chain complete.
//
// NOT CheckSignatureFrom, AND THE REASON IS MEASURED. That function refuses a
// "parent" that is not an authority - crypto/x509/x509.go in Go 1.27.2, the RFC
// 5280 section 4.2.1.9 check at its top - so a self-signed SERVER certificate,
// which carries CA:FALSE like the one self-signed.badssl.com presents, came
// back as not self-signed, and L4 told the reader that the server had withheld
// an issuer which does not exist (OBS163, 2026-10-19). CheckSignature asks
// only whether the key verifies the bytes.
func SelfSigned(c *x509.Certificate) bool {
	if Name(c.Subject) != Name(c.Issuer) {
		return false
	}
	return c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

// IssuedBy says whether parent issued child: parent's subject is child's
// issuer, by the one function both names are rendered by, and parent's key
// verifies child's signature - ADR114.
//
// NOT CheckSignatureFrom, for the reason SelfSigned gives: that function also
// refuses a parent that is not an authority, and the question here is which
// certificate issued which. Whether a client will accept it as an issuer is a
// path question, asked with a store.
//
// A SIGNATURE THAT CANNOT BE CHECKED AT ALL leaves the name to decide. MD5, or
// an algorithm Go does not know, says nothing about the key, and "this is not
// its issuer" would be a claim this program cannot make.
func IssuedBy(child, parent *x509.Certificate) bool {
	if Name(parent.Subject) != Name(child.Issuer) {
		return false
	}
	err := parent.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature)
	var insecure x509.InsecureAlgorithmError
	return err == nil || errors.As(err, &insecure) || errors.Is(err, x509.ErrUnsupportedAlgorithm)
}

// oidSubjectAltName is id-ce-subjectAltName, RFC 5280 section 4.2.1.6.
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// HasSubjectAltName asks whether the extension is present at all, by its
// identifier. Asking whether the parsed lists are empty instead would call a
// certificate whose subjectAltName holds only entries Go does not parse - a
// directory name, say - one that has none, and fall back to the common name
// RFC 6125 section 6.4.4 forbids in exactly that case (ADR106).
func HasSubjectAltName(c *x509.Certificate) bool {
	for _, extension := range c.Extensions {
		if extension.Id.Equal(oidSubjectAltName) {
			return true
		}
	}
	return false
}
