package cert

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"time"

	"github.com/donislawdev/certdoctor/internal/tool/certfacts"
)

// Certificate is one certificate as Data carries it. The names the report's
// certificates have - subject, issuer, dns_names, not_before, not_after,
// fingerprint_sha256, is_ca - mean the same here; every list is an empty
// array rather than null when the certificate has none of it.
type Certificate struct {
	// Number counts the certificates of the input from 1, read or not.
	Number         int      `json:"number"`
	Subject        string   `json:"subject"`
	Issuer         string   `json:"issuer"`
	SerialNumber   string   `json:"serial_number"`
	NotBefore      string   `json:"not_before"`
	NotAfter       string   `json:"not_after"`
	DNSNames       []string `json:"dns_names"`
	IPAddresses    []string `json:"ip_addresses"`
	EmailAddresses []string `json:"email_addresses"`
	URIs           []string `json:"uris"`
	IsCA           bool     `json:"is_ca"`
	// MaxPathLength is how many authorities may stand below this one, null
	// when it is not an authority or sets no limit.
	MaxPathLength      *int      `json:"max_path_length"`
	SelfSigned         bool      `json:"self_signed"`
	PublicKey          PublicKey `json:"public_key"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	KeyUsage           []string  `json:"key_usage"`
	ExtendedKeyUsage   []string  `json:"extended_key_usage"`
	FingerprintSHA256  string    `json:"fingerprint_sha256"`
	// FingerprintSHA1 is what Windows calls the thumbprint.
	FingerprintSHA1 string `json:"fingerprint_sha1"`
	// SPKISHA256 is the pin of RFC 7469 section 2.4: base64 of the SHA-256
	// of the SubjectPublicKeyInfo.
	SPKISHA256            string   `json:"spki_sha256"`
	SubjectKeyID          *string  `json:"subject_key_id"`
	AuthorityKeyID        *string  `json:"authority_key_id"`
	IssuingCertificateURL []string `json:"issuing_certificate_urls"`
	OCSPServers           []string `json:"ocsp_servers"`
	CRLDistributionPoints []string `json:"crl_distribution_points"`
}

// PublicKey is a certificate's key: its algorithm, and its size or curve
// where the algorithm has one.
type PublicKey struct {
	Algorithm string  `json:"algorithm"`
	Bits      *int    `json:"bits"`
	Curve     *string `json:"curve"`
}

// describe is the Data of one certificate the library read.
func describe(e entry) Certificate {
	c := e.cert
	return Certificate{
		Number:                e.number,
		Subject:               certfacts.Name(c.Subject),
		Issuer:                certfacts.Name(c.Issuer),
		SerialNumber:          serialHex(c),
		NotBefore:             c.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:              c.NotAfter.UTC().Format(time.RFC3339),
		DNSNames:              orEmpty(c.DNSNames),
		IPAddresses:           addresses(c),
		EmailAddresses:        orEmpty(c.EmailAddresses),
		URIs:                  uris(c),
		IsCA:                  c.IsCA,
		MaxPathLength:         pathLength(c),
		SelfSigned:            certfacts.SelfSigned(c),
		PublicKey:             publicKey(c),
		SignatureAlgorithm:    c.SignatureAlgorithm.String(),
		KeyUsage:              keyUsages(c.KeyUsage),
		ExtendedKeyUsage:      extendedKeyUsages(c),
		FingerprintSHA256:     certfacts.FingerprintSHA256(c.Raw),
		FingerprintSHA1:       thumbprint(c),
		SPKISHA256:            spkiPin(c),
		SubjectKeyID:          hexOrNull(c.SubjectKeyId),
		AuthorityKeyID:        hexOrNull(c.AuthorityKeyId),
		IssuingCertificateURL: orEmpty(c.IssuingCertificateURL),
		OCSPServers:           orEmpty(c.OCSPServer),
		CRLDistributionPoints: orEmpty(c.CRLDistributionPoints),
	}
}

// thumbprint is the SHA-1 of the certificate's bytes, which Windows shows as
// its thumbprint (X509Certificate2.Thumbprint is "generated using the SHA1
// algorithm", Microsoft, read 2026-11-13).
func thumbprint(c *x509.Certificate) string {
	sum := sha1.Sum(c.Raw)
	return hex.EncodeToString(sum[:])
}

// spkiPin is the pin of RFC 7469 section 2.4: the SHA-256 of the DER of the
// SubjectPublicKeyInfo, in base64 - what certificate pinning compares.
func spkiPin(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// serialHex is the serial number as the bytes of its magnitude in lower case
// hex - 01eee6..., with the leading zero Windows and OpenSSL show, where a
// number written in base 16 would drop it.
func serialHex(c *x509.Certificate) string {
	if c.SerialNumber.Sign() == 0 {
		return "00"
	}
	return hex.EncodeToString(c.SerialNumber.Bytes())
}

func orEmpty(list []string) []string {
	return append([]string{}, list...)
}

func hexOrNull(b []byte) *string {
	if len(b) == 0 {
		return nil
	}
	s := hex.EncodeToString(b)
	return &s
}

func addresses(c *x509.Certificate) []string {
	out := []string{}
	for _, ip := range c.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

func uris(c *x509.Certificate) []string {
	out := []string{}
	for _, u := range c.URIs {
		out = append(out, u.String())
	}
	return out
}

// pathLength is the limit of RFC 5280 section 4.2.1.9 as the library reads
// it: -1, or 0 without MaxPathLenZero, means none was set.
func pathLength(c *x509.Certificate) *int {
	if !c.IsCA || c.MaxPathLen < 0 || c.MaxPathLen == 0 && !c.MaxPathLenZero {
		return nil
	}
	n := c.MaxPathLen
	return &n
}

// publicKey names a certificate's key. Ed25519 has one size and no curve to
// name; an algorithm the library does not read is "unknown".
func publicKey(c *x509.Certificate) PublicKey {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := k.N.BitLen()
		return PublicKey{Algorithm: "RSA", Bits: &bits}
	case *ecdsa.PublicKey:
		bits, curve := k.Curve.Params().BitSize, k.Curve.Params().Name
		return PublicKey{Algorithm: "ECDSA", Bits: &bits, Curve: &curve}
	}
	if c.PublicKeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
		return PublicKey{Algorithm: "unknown"}
	}
	return PublicKey{Algorithm: c.PublicKeyAlgorithm.String()}
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

func keyUsages(u x509.KeyUsage) []string {
	out := []string{}
	for _, k := range keyUsageNames {
		if u&k.bit != 0 {
			out = append(out, k.name)
		}
	}
	return out
}

// extendedKeyUsageNames are the purposes the library reads, by the names
// RFC 5280 section 4.2.1.12 gives them. The vendors' purposes Go also reads
// have no name in an RFC, so they are written as their identifiers.
var extendedKeyUsageNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                            "anyExtendedKeyUsage",
	x509.ExtKeyUsageServerAuth:                     "serverAuth",
	x509.ExtKeyUsageClientAuth:                     "clientAuth",
	x509.ExtKeyUsageCodeSigning:                    "codeSigning",
	x509.ExtKeyUsageEmailProtection:                "emailProtection",
	x509.ExtKeyUsageIPSECEndSystem:                 "ipsecEndSystem",
	x509.ExtKeyUsageIPSECTunnel:                    "ipsecTunnel",
	x509.ExtKeyUsageIPSECUser:                      "ipsecUser",
	x509.ExtKeyUsageTimeStamping:                   "timeStamping",
	x509.ExtKeyUsageOCSPSigning:                    "OCSPSigning",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "1.3.6.1.4.1.311.10.3.3",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      "2.16.840.1.113730.4.1",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "1.3.6.1.4.1.311.2.1.22",
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "1.3.6.1.4.1.311.61.1.1",
}

func extendedKeyUsages(c *x509.Certificate) []string {
	out := []string{}
	for _, u := range c.ExtKeyUsage {
		if name, ok := extendedKeyUsageNames[u]; ok {
			out = append(out, name)
		}
	}
	for _, oid := range c.UnknownExtKeyUsage {
		out = append(out, oid.String())
	}
	return out
}

// servesTLS says whether a certificate may be a TLS server's by its purposes:
// it names none, or names serverAuth or any purpose.
func servesTLS(c *x509.Certificate) bool {
	if len(c.ExtKeyUsage) == 0 && len(c.UnknownExtKeyUsage) == 0 {
		return true
	}
	for _, u := range c.ExtKeyUsage {
		if u == x509.ExtKeyUsageServerAuth || u == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}
