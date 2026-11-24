package certfacts

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"

	"github.com/donislawdev/certdoctor/internal/core/status"
)

// PublicKey is a key as the tools' data carries it: its algorithm, and its
// size or curve where the algorithm has one. The certificate decoder and the
// CSR decoder carry the same shape, so a script reads a key one way (ADR154).
type PublicKey struct {
	Algorithm string  `json:"algorithm"`
	Bits      *int    `json:"bits"`
	Curve     *string `json:"curve"`
}

// Key names a key. Ed25519 has one size and no curve to name; an algorithm
// the library does not read is "unknown".
func Key(pub any, algorithm x509.PublicKeyAlgorithm) PublicKey {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		bits := k.N.BitLen()
		return PublicKey{Algorithm: "RSA", Bits: &bits}
	case *ecdsa.PublicKey:
		bits, curve := k.Curve.Params().BitSize, k.Curve.Params().Name
		return PublicKey{Algorithm: "ECDSA", Bits: &bits, Curve: &curve}
	}
	if algorithm == x509.UnknownPublicKeyAlgorithm {
		return PublicKey{Algorithm: "unknown"}
	}
	return PublicKey{Algorithm: algorithm.String()}
}

// Words names a key in a row: "RSA, 2048 bits", "ECDSA, P-256", "Ed25519".
func (k PublicKey) Words() string {
	switch {
	case k.Curve != nil:
		return k.Algorithm + ", " + *k.Curve
	case k.Bits != nil:
		return fmt.Sprintf("%s, %d bits", k.Algorithm, *k.Bits)
	}
	return k.Algorithm
}

// SPKIPin is the pin of RFC 7469 section 2.4: the SHA-256 of the DER of a
// SubjectPublicKeyInfo, in base64 - what certificate pinning compares. A
// request and the certificate issued for it carry the same key, so the two
// decoders showing the same pin lets a person match them at a glance.
func SPKIPin(rawSubjectPublicKeyInfo []byte) string {
	sum := sha256.Sum256(rawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// MaxCheckedRSABits is the largest RSA key a signature is checked with -
// OpenSSL's OPENSSL_RSA_MAX_MODULUS_BITS (include/openssl/rsa.h, read
// 2026-11-17).
//
// MEASURED, NOT CAUTION. crypto/rsa of Go 1.27.4 sets no upper bound on the
// modulus, and the cost of one check grows with its square: 16 384 bits took
// 3 ms, 262 144 bits 1 s and 500 000 bits 4.3 s on the owner's machine, and a
// certificate with a key of 1.4 million bits - 237 KB of PEM, within the
// certificate decoder's limit - kept certdoctor tool cert busy for 23.3 s
// (2026-11-17, ADR154). L4 never meets such a key: Go's TLS refuses an RSA key
// over 8192 bits before the handshake hands a certificate over.
const MaxCheckedRSABits = 16384

// Checkable says a signature made with pub is one this program checks: any
// key but an RSA key over MaxCheckedRSABits.
func Checkable(pub any) bool {
	k, ok := pub.(*rsa.PublicKey)
	return !ok || k.N.BitLen() <= MaxCheckedRSABits
}

// RSAKeyStatus judges an RSA key by its size: Go refuses to verify with a key
// under 1024 bits (crypto/rsa of Go 1.27, read 2026-11-13), and the
// CA/Browser Forum requires 2048 bits of a public authority (Baseline
// Requirements 6.1.5). Any other key passes this rule.
func RSAKeyStatus(pub any) (status.Status, int) {
	k, ok := pub.(*rsa.PublicKey)
	if !ok {
		return status.Pass, 0
	}
	switch bits := k.N.BitLen(); {
	case bits < 1024:
		return status.Fail, bits
	case bits < 2048:
		return status.Warn, bits
	default:
		return status.Pass, bits
	}
}

// The words the tools end a key_size sentence with, one for each status.
const (
	KeySizeFailWords = "Go refuses to verify with an RSA key under 1024 bits (crypto/rsa)."
	KeySizeWarnWords = "a public authority issues no RSA key under 2048 bits (CA/Browser Forum Baseline " +
		"Requirements 6.1.5)."
	KeySizePassWords = "No RSA key is shorter than 2048 bits." //nolint:gosec // G101: the words for a key size that passes
)

// weakSignatures are the signature algorithms a client should not accept a
// certificate under: MD2 and MD5, which Go's CheckSignature rejects outright,
// and SHA-1, which Go's Verify does not build a chain through and which the
// CA/Browser Forum ended in certificates (Baseline Requirements 7.1.3.2,
// ballot SC097) - crypto/x509 of Go 1.27, read 2026-11-13.
var weakSignatures = map[x509.SignatureAlgorithm]status.Status{
	x509.MD2WithRSA:    status.Fail,
	x509.MD5WithRSA:    status.Fail,
	x509.SHA1WithRSA:   status.Warn,
	x509.DSAWithSHA1:   status.Warn,
	x509.ECDSAWithSHA1: status.Warn,
}

// WeakSignature says how bad a signature algorithm is, when it is one of
// the weak ones.
func WeakSignature(algorithm x509.SignatureAlgorithm) (status.Status, bool) {
	s, weak := weakSignatures[algorithm]
	return s, weak
}

// SignatureAlgorithm names the algorithm a certificate or a request is
// signed with. raw is the whole object - a certificate and a request both end
// in the same AlgorithmIdentifier and signature after what they sign.
//
// AN ALGORITHM GO DOES NOT KNOW IS NAMED BY ITS IDENTIFIER. Go's own name for
// it is "0" (SignatureAlgorithm.String in crypto/x509 of Go 1.27.4), which
// tells a person nothing; the identifier can be looked up.
func SignatureAlgorithm(raw []byte, algorithm x509.SignatureAlgorithm) string {
	if algorithm != x509.UnknownSignatureAlgorithm {
		return algorithm.String()
	}
	var signed struct {
		Content   asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	if _, err := asn1.Unmarshal(raw, &signed); err != nil || len(signed.Algorithm.Algorithm) == 0 {
		return "unknown"
	}
	return signed.Algorithm.Algorithm.String()
}

// keyUsageNames are the bits of RFC 5280 section 4.2.1.3, in its order and by
// its names.
var keyUsageNames = []struct {
	bit  x509.KeyUsage
	name string
}{
	{x509.KeyUsageDigitalSignature, "digitalSignature"},
	{x509.KeyUsageContentCommitment, "contentCommitment"},
	{x509.KeyUsageKeyEncipherment, "keyEncipherment"},
	{x509.KeyUsageDataEncipherment, "dataEncipherment"},
	{x509.KeyUsageKeyAgreement, "keyAgreement"},
	{x509.KeyUsageCertSign, "keyCertSign"},
	{x509.KeyUsageCRLSign, "cRLSign"},
	{x509.KeyUsageEncipherOnly, "encipherOnly"},
	{x509.KeyUsageDecipherOnly, "decipherOnly"},
}

// KeyUsages names the key usage bits set, in the RFC's order.
func KeyUsages(u x509.KeyUsage) []string {
	out := []string{}
	for _, k := range keyUsageNames {
		if u&k.bit != 0 {
			out = append(out, k.name)
		}
	}
	return out
}

// extendedKeyUsages are the purposes the library reads, with their
// identifiers as crypto/x509 of Go 1.27.4 holds them (extKeyUsageOIDs) and the
// names RFC 5280 section 4.2.1.12 gives them. The vendors' purposes have no
// name in an RFC, so they are written as their identifiers.
var extendedKeyUsages = []struct {
	usage x509.ExtKeyUsage
	oid   asn1.ObjectIdentifier
	name  string
}{
	{x509.ExtKeyUsageAny, asn1.ObjectIdentifier{2, 5, 29, 37, 0}, "anyExtendedKeyUsage"},
	{x509.ExtKeyUsageServerAuth, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}, "serverAuth"},
	{x509.ExtKeyUsageClientAuth, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}, "clientAuth"},
	{x509.ExtKeyUsageCodeSigning, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}, "codeSigning"},
	{x509.ExtKeyUsageEmailProtection, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}, "emailProtection"},
	{x509.ExtKeyUsageIPSECEndSystem, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}, "ipsecEndSystem"},
	{x509.ExtKeyUsageIPSECTunnel, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}, "ipsecTunnel"},
	{x509.ExtKeyUsageIPSECUser, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}, "ipsecUser"},
	{x509.ExtKeyUsageTimeStamping, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}, "timeStamping"},
	{x509.ExtKeyUsageOCSPSigning, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}, "OCSPSigning"},
	{x509.ExtKeyUsageMicrosoftServerGatedCrypto, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3},
		"1.3.6.1.4.1.311.10.3.3"},
	{x509.ExtKeyUsageNetscapeServerGatedCrypto, asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1},
		"2.16.840.1.113730.4.1"},
	{x509.ExtKeyUsageMicrosoftCommercialCodeSigning, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 22},
		"1.3.6.1.4.1.311.2.1.22"},
	{x509.ExtKeyUsageMicrosoftKernelCodeSigning, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1},
		"1.3.6.1.4.1.311.61.1.1"},
}

// ExtKeyUsagesOf sorts purposes given by identifier - as a request carries
// them, which the library does not read - into the ones it knows and the rest,
// the two lists a certificate has.
func ExtKeyUsagesOf(oids []asn1.ObjectIdentifier) ([]x509.ExtKeyUsage, []asn1.ObjectIdentifier) {
	var known []x509.ExtKeyUsage
	var unknown []asn1.ObjectIdentifier
	for _, oid := range oids {
		found := false
		for _, e := range extendedKeyUsages {
			if e.oid.Equal(oid) {
				known, found = append(known, e.usage), true
				break
			}
		}
		if !found {
			unknown = append(unknown, oid)
		}
	}
	return known, unknown
}

// ExtendedKeyUsages names the purposes, the known ones first in their order,
// then the others by identifier.
func ExtendedKeyUsages(known []x509.ExtKeyUsage, unknown []asn1.ObjectIdentifier) []string {
	out := []string{}
	for _, u := range known {
		for _, e := range extendedKeyUsages {
			if e.usage == u {
				out = append(out, e.name)
			}
		}
	}
	for _, oid := range unknown {
		out = append(out, oid.String())
	}
	return out
}

// ServesTLS says whether a certificate with these purposes may be a TLS
// server's: it names none, or names serverAuth or any purpose.
func ServesTLS(known []x509.ExtKeyUsage, unknown []asn1.ObjectIdentifier) bool {
	if len(known) == 0 && len(unknown) == 0 {
		return true
	}
	for _, u := range known {
		if u == x509.ExtKeyUsageServerAuth || u == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}
