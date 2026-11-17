package certfacts

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"slices"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/status"
)

// publicKey is the key of a SubjectPublicKeyInfo fixture.
func publicKey(t testing.TB, fixture string) any {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(fixture)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// TestAKeyTooLargeToCheckLeavesTheNameToDecide holds ADR154: a parent whose
// RSA key is over the ceiling is not asked to verify - that would cost
// seconds - and the name decides, as for a signature nothing can check. The
// same parent under a key that is checked, and did not sign, is refused: the
// canary that the ceiling, not the name alone, made the difference.
func TestAKeyTooLargeToCheckLeavesTheNameToDecide(t *testing.T) {
	child, huge, checked := parse(t, fixtureBigChild), parse(t, fixtureBigCA), parse(t, fixtureCheckedCA)
	if Name(huge.Subject) != Name(child.Issuer) || Name(checked.Subject) != Name(child.Issuer) {
		t.Fatal("the fixtures do not carry the child's issuer name, so they prove nothing")
	}
	if !IssuedBy(child, huge) {
		t.Error("a parent with a key over the ceiling and the right name is not the issuer")
	}
	if IssuedBy(child, checked) {
		t.Error("canary: a parent with a key that is checked, and did not sign, is the issuer")
	}
	if SelfSigned(huge) {
		t.Error("a certificate with a key over the ceiling is called self-signed without its signature")
	}
	if Checkable(publicKey(t, spkiRSA16392)) || !Checkable(publicKey(t, spkiRSA16384)) ||
		!Checkable(publicKey(t, spkiP384)) {
		t.Error("the ceiling stands somewhere else")
	}
}

// TestAnRSAKeyIsJudgedByItsSize holds the two lines of RSAKeyStatus.
func TestAnRSAKeyIsJudgedByItsSize(t *testing.T) {
	for _, tc := range []struct {
		fixture string
		bits    int
		want    status.Status
	}{
		{spkiRSA512, 512, status.Fail}, {spkiRSA1023, 1023, status.Fail}, {spkiRSA1024, 1024, status.Warn},
		{spkiRSA2047, 2047, status.Warn}, {spkiRSA2048, 2048, status.Pass},
	} {
		if got, bits := RSAKeyStatus(publicKey(t, tc.fixture)); got != tc.want || bits != tc.bits {
			t.Errorf("%d bits: %s %d, want %s", tc.bits, got, bits, tc.want)
		}
	}
	if got, _ := RSAKeyStatus(publicKey(t, spkiP384)); got != status.Pass {
		t.Errorf("a key that is not RSA: %s", got)
	}
}

// TestAKeyIsNamedOneWay holds the key's description both decoders give.
func TestAKeyIsNamedOneWay(t *testing.T) {
	if _, ok := publicKey(t, spkiP384).(*ecdsa.PublicKey); !ok {
		t.Fatal("the P-384 fixture is not an ECDSA key")
	}
	if _, ok := publicKey(t, spkiRSA2048).(*rsa.PublicKey); !ok {
		t.Fatal("the RSA fixture is not an RSA key")
	}
	for _, tc := range []struct {
		pub       any
		algorithm x509.PublicKeyAlgorithm
		want      string
	}{
		{publicKey(t, spkiRSA2048), x509.RSA, "RSA, 2048 bits"},
		{publicKey(t, spkiP384), x509.ECDSA, "ECDSA, P-384"},
		{nil, x509.Ed25519, "Ed25519"},
		{nil, x509.UnknownPublicKeyAlgorithm, "unknown"},
	} {
		if got := Key(tc.pub, tc.algorithm).Words(); got != tc.want {
			t.Errorf("%v: %q, want %q", tc.algorithm, got, tc.want)
		}
	}
}

// TestAnAlgorithmGoDoesNotKnowIsNamedByItsIdentifier holds that "0" - Go's
// name for it - never reaches a person.
func TestAnAlgorithmGoDoesNotKnowIsNamedByItsIdentifier(t *testing.T) {
	raw, err := asn1.Marshal(struct {
		Content   asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}{asn1.RawValue{FullBytes: []byte{0x05, 0x00}}, pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 101,
		113}}, asn1.BitString{Bytes: []byte{1}, BitLength: 8}})
	if err != nil {
		t.Fatal(err)
	}
	if x509.UnknownSignatureAlgorithm.String() != "0" {
		t.Fatalf("Go now names an unknown algorithm %q - this rule may no longer be needed",
			x509.UnknownSignatureAlgorithm.String())
	}
	for _, tc := range []struct {
		raw       []byte
		algorithm x509.SignatureAlgorithm
		want      string
	}{
		{raw, x509.UnknownSignatureAlgorithm, "1.3.101.113"},
		{[]byte{0x30, 0x00}, x509.UnknownSignatureAlgorithm, "unknown"},
		{raw, x509.ECDSAWithSHA256, "ECDSA-SHA256"},
	} {
		if got := SignatureAlgorithm(tc.raw, tc.algorithm); got != tc.want {
			t.Errorf("%q, want %q", got, tc.want)
		}
	}
	if s, weak := WeakSignature(x509.SHA1WithRSA); !weak || s != status.Warn {
		t.Errorf("SHA-1: %s %v", s, weak)
	}
	if _, weak := WeakSignature(x509.SHA256WithRSA); weak {
		t.Error("SHA-256 is weak")
	}
}

// TestPurposesAreReadByIdentifierAndNamedOneWay holds the purposes of a
// request, read by identifier, against the names a certificate's get.
func TestPurposesAreReadByIdentifierAndNamedOneWay(t *testing.T) {
	serverAuth, clientAuth := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	own := asn1.ObjectIdentifier{1, 2, 3, 4}
	known, unknown := ExtKeyUsagesOf([]asn1.ObjectIdentifier{serverAuth, own})
	if !slices.Equal(known, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) || len(unknown) != 1 || !unknown[0].Equal(own) {
		t.Errorf("sorted into %v and %v", known, unknown)
	}
	if got := ExtendedKeyUsages(known, unknown); !slices.Equal(got, []string{"serverAuth", "1.2.3.4"}) {
		t.Errorf("named %v", got)
	}
	clientOnly, _ := ExtKeyUsagesOf([]asn1.ObjectIdentifier{clientAuth})
	for _, tc := range []struct {
		known   []x509.ExtKeyUsage
		unknown []asn1.ObjectIdentifier
		want    bool
	}{
		{nil, nil, true}, {known, unknown, true}, {clientOnly, nil, false}, {nil, []asn1.ObjectIdentifier{own}, false},
		{[]x509.ExtKeyUsage{x509.ExtKeyUsageAny}, nil, true},
	} {
		if got := ServesTLS(tc.known, tc.unknown); got != tc.want {
			t.Errorf("%v %v: %v", tc.known, tc.unknown, got)
		}
	}
	if got := KeyUsages(x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign); !slices.Equal(got,
		[]string{"digitalSignature", "keyCertSign"}) {
		t.Errorf("key usage %v", got)
	}
	if got := SPKIPin([]byte("abc")); got != "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=" {
		t.Errorf("pin %q", got)
	}
}
