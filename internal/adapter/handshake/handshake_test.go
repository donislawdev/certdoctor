package handshake

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	core "github.com/donislawdev/certdoctor/internal/core/handshake"
)

// minted is one certificate this test made, with everything needed to sign the
// next one under it.
type minted struct {
	der  []byte
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// serial counts up so that no two certificates in one run share one.
var serial int64

// mint makes one certificate, signed by parent or by itself when parent is nil.
//
// THE CHAIN IS BUILT RATHER THAN CHECKED IN, for the same reason the testbed's
// is - ADR5 forbids a private key in this repository, and a chain minted here is
// also the only way to produce the SHAPES this adapter has to survive: a bundle,
// a leaf sent alone, and something that signed itself.
func mint(t testing.TB, commonName string, parent *minted, isCA bool) minted {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	serial++
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"certdoctor test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	if !isCA {
		template.DNSNames = []string{"partner.test"}
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}

	signer, signerKey := template, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("signing %s: %v", commonName, err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("reading back %s: %v", commonName, err)
	}
	return minted{der: der, cert: parsed, key: key}
}

// serve starts a TLS listener on loopback and hands back its address and port.
//
// It answers exactly one connection and then stops, which is all any test here
// needs and means a hung test cannot leave a listener behind.
func serve(t *testing.T, config *tls.Config) (string, int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("NOT CHECKED: this machine would not lend a loopback port (%v), so nothing below was exercised.", err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		server := tls.Server(conn, config)
		// The error is deliberately dropped: several tests here make the
		// handshake fail on purpose, and a server complaining about it would be
		// noise rather than a result.
		_ = server.Handshake()
	}()

	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("reading the listener address back: %v", err)
	}
	number := 0
	if _, err := fmt.Sscanf(port, "%d", &number); err != nil {
		t.Fatalf("reading the port back: %v", err)
	}
	return host, number
}

// bundle is a root, an intermediate under it, and a leaf under that - the shape
// a correctly configured server presents.
func bundle(t testing.TB) (root, intermediate, leaf minted) {
	t.Helper()
	root = mint(t, "certdoctor test root", nil, true)
	intermediate = mint(t, "certdoctor test intermediate", &root, true)
	leaf = mint(t, "partner.test", &intermediate, false)
	return root, intermediate, leaf
}

func serverConfig(leaf, intermediate minted, withIntermediate bool) *tls.Config {
	chain := [][]byte{leaf.der}
	if withIntermediate {
		chain = append(chain, intermediate.der)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: leaf.key}},
	}
}

// TestWhatTheServerPresentedIsReportedExactly is the ordinary path, and it pins
// the fields the rest of L4 grades.
func TestWhatTheServerPresentedIsReportedExactly(t *testing.T) {
	_, intermediate, leaf := bundle(t)
	host, port := serve(t, serverConfig(leaf, intermediate, true))

	shown, err := Shake(func(string) error { return nil })(
		context.Background(), host, port, "partner.test")
	if err != nil {
		t.Fatalf("a working server would not hand shake: %v", err)
	}
	if !shown.Completed {
		t.Fatal("the handshake finished and the record says it did not")
	}
	if len(shown.Chain) != 2 {
		t.Fatalf("the server sent 2 certificates and %d were reported", len(shown.Chain))
	}

	// THE ONE-FUNCTION RULE, CHECKED RATHER THAN COMMENTED. L4 asks whether the
	// leaf's issuer is the subject of something else that arrived, by comparing
	// strings. Two spellings would report this complete chain as broken and send
	// somebody to fix a server that is already correct.
	if shown.Chain[0].Issuer != shown.Chain[1].Subject {
		t.Errorf("the leaf says it was issued by %q and the certificate above it calls itself %q - "+
			"one name spelled two ways makes a complete chain look broken",
			shown.Chain[0].Issuer, shown.Chain[1].Subject)
	}
	if shown.Chain[0].FingerprintSHA256 != fingerprint(leaf.der) {
		t.Error("the leaf's fingerprint is not the digest of the bytes that arrived")
	}
	if shown.Chain[0].SelfSigned || !shown.Chain[1].IsCA {
		t.Errorf("the leaf or the authority was described wrongly: %+v", shown.Chain)
	}

	// Both names come from the standard library, so neither can be empty and
	// neither is ours to keep current.
	if shown.Version == "" || shown.CipherSuiteName == "" || shown.CipherSuite == 0 {
		t.Errorf("what was negotiated was not reported: %q / %q / %d",
			shown.Version, shown.CipherSuiteName, shown.CipherSuite)
	}
}

// TestTheNameWeSendTravelsSeparatelyFromTheAddress is the whole of TLS in one
// assertion, checked where it actually goes on the wire.
//
// The name decides which certificate a virtual host chooses and the address
// decides where the packets go. Sending the address as the name asks for a
// certificate nobody issued - and the failure looks exactly like a misconfigured
// server, which is the wrong answer given confidently.
func TestTheNameWeSendTravelsSeparatelyFromTheAddress(t *testing.T) {
	_, intermediate, leaf := bundle(t)
	base := serverConfig(leaf, intermediate, true)

	seen := make(chan string, 1)
	config := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			seen <- hello.ServerName
			return &base.Certificates[0], nil
		},
	}
	host, port := serve(t, config)

	shown, err := Shake(func(string) error { return nil })(
		context.Background(), host, port, "partner.test")
	if err != nil {
		t.Fatalf("the handshake failed: %v", err)
	}

	select {
	case name := <-seen:
		if name != "partner.test" {
			t.Errorf("the server was asked for %q and we meant partner.test", name)
		}
		if name == host {
			t.Errorf("the address was sent as the name, which asks for a certificate nobody issued")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the server never reported which name was asked for")
	}

	// And the record says which name the chain was chosen for, which is what
	// makes the certificate below it interpretable at all.
	if shown.ServerName != "partner.test" {
		t.Errorf("the record says the name sent was %q", shown.ServerName)
	}
}

// TestAServerThatSendsNoIntermediateStillLeavesItsCertificate is ADR46 measured
// rather than argued - scenario S-5.
//
// With ordinary verification this handshake aborts and NOT ONE certificate
// survives to show. That is the difference between "the handshake failed" and
// "the server presented one certificate and did not send its issuer", and it is
// the whole reason the flag in handshake.go is set.
func TestAServerThatSendsNoIntermediateStillLeavesItsCertificate(t *testing.T) {
	_, intermediate, leaf := bundle(t)
	host, port := serve(t, serverConfig(leaf, intermediate, false))

	shown, err := Shake(func(string) error { return nil })(
		context.Background(), host, port, "partner.test")
	if err != nil {
		t.Fatalf("a server with a broken chain would not hand shake at all: %v", err)
	}
	if len(shown.Chain) != 1 {
		t.Fatalf("the server sent 1 certificate and %d were reported", len(shown.Chain))
	}
	// The evidence somebody came for: the leaf names an issuer that did not
	// arrive, and nothing on this side had to consult a trust store to say so.
	if shown.Chain[0].Issuer == shown.Chain[0].Subject || shown.Chain[0].SelfSigned || shown.Chain[0].IssuerSent {
		t.Errorf("the missing issuer is not visible from what was reported: %+v", shown.Chain[0])
	}
}

// TestTheIssuerOfTheLeafIsFoundByItsKey is B01 from ADR114. Whether the issuer
// arrived used to be one comparison of names, and a certificate carrying the
// issuer's name with somebody else's key passed it.
func TestTheIssuerOfTheLeafIsFoundByItsKey(t *testing.T) {
	root, intermediate, leaf := bundle(t)
	// The same name and a key of its own: an issuer re-issued, sent in the form
	// that did not sign this leaf.
	impostor := mint(t, "certdoctor test intermediate", &root, true)
	if distinguishedName(impostor.cert.Subject) != distinguishedName(leaf.cert.Issuer) {
		t.Fatalf("the fixture failed to reproduce the issuer's name")
	}
	// A leaf claiming MD5 - its signature cannot be checked against any key, so
	// the name decides, as it did before keys were asked.
	unverifiable := *leaf.cert
	unverifiable.SignatureAlgorithm = x509.MD5WithRSA

	cases := []struct {
		name  string
		chain []*x509.Certificate
		want  bool
	}{
		{"the issuer right after the leaf", []*x509.Certificate{leaf.cert, intermediate.cert}, true},
		{"the issuer after another certificate", []*x509.Certificate{leaf.cert, root.cert, intermediate.cert}, true},
		{"the leaf alone", []*x509.Certificate{leaf.cert}, false},
		{"the issuer's name with another key", []*x509.Certificate{leaf.cert, impostor.cert}, false},
		{"another key, then the issuer", []*x509.Certificate{leaf.cert, impostor.cert, intermediate.cert}, true},
		{"a signature nothing can check, under the issuer's name", []*x509.Certificate{&unverifiable, impostor.cert}, true},
		{"a signature nothing can check, under another name", []*x509.Certificate{&unverifiable, root.cert}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := certificates(c.chain)
			if got[0].IssuerSent != c.want {
				t.Errorf("IssuerSent %v, want %v", got[0].IssuerSent, c.want)
			}
			for i, rest := range got[1:] {
				if rest.IssuerSent {
					t.Errorf("certificate %d was asked about its issuer, and only the leaf is", i+1)
				}
			}
		})
	}
}

// TestSelfSignedIsReadFromTheSignatureAndNotFromTheNames covers the trap that
// would call a broken chain complete.
//
// A certificate can name itself as its own issuer without having signed itself.
// Deciding by name equality would mark that self-signed, L4 would call the chain
// complete, and the report would pass a server nothing can build a path to.
func TestSelfSignedIsReadFromTheSignatureAndNotFromTheNames(t *testing.T) {
	root := mint(t, "certdoctor test root", nil, true)
	host, port := serve(t, &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{root.der}, PrivateKey: root.key}},
	})

	shown, err := Shake(func(string) error { return nil })(
		context.Background(), host, port, "partner.test")
	if err != nil {
		t.Fatalf("a self-signed server would not hand shake: %v", err)
	}
	if !shown.Chain[0].SelfSigned {
		t.Error("a certificate that signed itself was not recognised as having done so")
	}

	// The other side of it, and it is the one that matters: a certificate whose
	// names match but whose signature is somebody else's must NOT come back
	// self-signed. Both of these carry the same subject and issuer text.
	impostor := mint(t, "certdoctor test root", &root, true)
	summary := summarise(impostor.cert)
	if summary.Subject != summary.Issuer {
		t.Fatalf("the fixture failed to produce matching names: %q against %q", summary.Subject, summary.Issuer)
	}
	if summary.SelfSigned {
		t.Error("a certificate naming itself as issuer was called self-signed, and it did not sign itself")
	}
}

// TestASelfSignedServerCertificateIsSelfSigned is OBS163, measured 2026-10-19:
// self-signed.badssl.com presents one certificate that issued itself and says
// CA:FALSE, as most self-signed server certificates do. CheckSignatureFrom
// refuses a parent that is not an authority, so the leaf was read as not
// self-signed and L4 reported an issuer the server had "not sent" - an issuer
// that does not exist.
func TestASelfSignedServerCertificateIsSelfSigned(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	serial++
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "*.partner.test", Organization: []string{"certdoctor test"}},
		DNSNames:              []string{"*.partner.test", "partner.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("signing the leaf with its own key: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("reading the leaf back: %v", err)
	}

	summary := summarise(parsed)
	if summary.IsCA {
		t.Fatal("the fixture is an authority, so it proves nothing about a server certificate")
	}
	if !summary.SelfSigned {
		t.Error("a server certificate that signed itself with CA:FALSE was not recognised as self-signed")
	}
}

// TestTheServerAskingUsToAuthenticateIsReported covers one of the commonest
// causes of "works in the browser, fails in the tool" - and one a browser holding
// a certificate never shows the user.
func TestTheServerAskingUsToAuthenticateIsReported(t *testing.T) {
	_, intermediate, leaf := bundle(t)

	asking := serverConfig(leaf, intermediate, true)
	asking.ClientAuth = tls.RequestClientCert
	host, port := serve(t, asking)

	shown, err := Shake(func(string) error { return nil })(
		context.Background(), host, port, "partner.test")
	if err != nil {
		t.Fatalf("the handshake failed: %v", err)
	}
	if !shown.ClientCertificateRequested {
		t.Error("the server asked us to authenticate and the report does not say so")
	}

	// The other side, without which the assertion above is satisfied by a field
	// that is always true.
	quiet, quietPort := serve(t, serverConfig(leaf, intermediate, true))
	shown, err = Shake(func(string) error { return nil })(
		context.Background(), quiet, quietPort, "partner.test")
	if err != nil {
		t.Fatalf("the handshake failed: %v", err)
	}
	if shown.ClientCertificateRequested {
		t.Error("a server that asked for nothing was reported as requesting a client certificate")
	}
}

// TestARefusalByOurOwnRuleNeverReachesTheNetwork is inviolable rule 16 at the
// fourth place in this program that can break it.
func TestARefusalByOurOwnRuleNeverReachesTheNetwork(t *testing.T) {
	asked := []string{}
	refusing := Shake(func(address string) error {
		asked = append(asked, address)
		return errors.New("not in the allowed set")
	})

	if _, err := refusing(context.Background(), "192.0.2.10", 443, "example.com"); !errors.Is(err, core.ErrRefusedByRule) {
		t.Errorf("a refusal by our own rule came back as %v, which reads as a fact about their network", err)
	}
	// The rule is asked about the SAME string the dialler would have used, which
	// is the pairing tcp.Target exists for and the reason this adapter borrows it.
	if len(asked) != 1 || asked[0] != "192.0.2.10:443" {
		t.Errorf("the permission rule was asked about %v, and the dialler would use 192.0.2.10:443", asked)
	}

	// A missing rule refuses everything. A forgotten wire must read as a program
	// that cannot reach anything, never as one with no restrictions.
	if _, err := Shake(nil)(context.Background(), "192.0.2.10", 443, "example.com"); !errors.Is(err, core.ErrRefusedByRule) {
		t.Errorf("a nil rule answered %v, and it has to refuse", err)
	}

	// A name where an address belongs cannot be spelled for the allowed set, so
	// it is refused rather than handed to a dialler that would resolve it - which
	// would be this program answering L1's question a second time, quietly.
	permissive := Shake(func(string) error { return nil })
	if _, err := permissive(context.Background(), "example.com", 443, "example.com"); !errors.Is(err, core.ErrRefusedByRule) {
		t.Errorf("a host name reached the dialler: %v", err)
	}
}

// TestAConnectionThatCannotOpenIsNotDiagnosedTwice covers the sentinel that
// exists so one fault is not counted as two.
func TestAConnectionThatCannotOpenIsNotDiagnosedTwice(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("NOT CHECKED: this machine would not lend a loopback port (%v).", err)
	}
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	number := 0
	if _, err := fmt.Sscanf(port, "%d", &number); err != nil {
		t.Fatalf("reading the port back: %v", err)
	}
	listener.Close()

	_, shakeErr := Shake(func(string) error { return nil })(
		context.Background(), host, number, "partner.test")
	if !errors.Is(shakeErr, core.ErrNotReached) {
		t.Errorf("a port nothing listens on came back as %v, and L3 has already reported why", shakeErr)
	}
}

// TestFailureNamesWhatHappenedRatherThanGuessing covers the mapping BY VALUE.
//
// A default of "timeout" would send a person to look at their firewall for a
// server that answered immediately and refused, so anything nobody wrote a case
// for has to arrive as the weaker claim.
func TestFailureNamesWhatHappenedRatherThanGuessing(t *testing.T) {
	if got := failure(context.DeadlineExceeded); !errors.Is(got, core.ErrTimeout) {
		t.Errorf("a deadline mapped to %v", got)
	}
	if got := failure(context.Canceled); !errors.Is(got, core.ErrTimeout) {
		t.Errorf("a cancelled attempt mapped to %v", got)
	}
	if got := failure(errors.New("something new")); !errors.Is(got, core.ErrRejected) {
		t.Errorf("an unrecognised failure mapped to %v, and it must not claim to be a diagnosis", got)
	}
	if got := failure(&net.DNSError{IsTimeout: true}); !errors.Is(got, core.ErrTimeout) {
		t.Errorf("a timeout reported by the network layer mapped to %v", got)
	}
}

// TestACertificateNobodyCanReadIsRefusedRatherThanSummarised is the entry point
// the fuzz target drives, checked here on the two cases a corpus would take a
// while to reach.
func TestACertificateNobodyCanReadIsRefusedRatherThanSummarised(t *testing.T) {
	for _, bad := range [][]byte{nil, {}, []byte("not a certificate"), {0x30, 0x82, 0xff, 0xff}} {
		if _, err := CertificateFrom(bad); err == nil {
			t.Errorf("%q was summarised as a certificate", bad)
		}
	}

	root := mint(t, "certdoctor test root", nil, true)
	summary, err := CertificateFrom(root.der)
	if err != nil {
		t.Fatalf("a real certificate was refused: %v", err)
	}
	if summary.FingerprintSHA256 != fingerprint(root.der) {
		t.Error("the fingerprint is not the digest of the bytes handed in")
	}
	if !summary.SelfSigned || !summary.IsCA {
		t.Errorf("a self-signed authority was summarised as %+v", summary)
	}
}

// mintSANOnly is the shape RFC 5280 section 4.1.2.6 requires: no subject at all,
// identity in a subjectAltName that crypto/x509 marks critical by itself.
func mintSANOnly(t testing.TB, parent minted, names ...string) minted {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	serial++
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{},
		DNSNames:              names,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent.cert, &key.PublicKey, parent.key)
	if err != nil {
		t.Fatalf("signing a subject-less leaf: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("reading it back: %v", err)
	}
	return minted{der: der, cert: parsed, key: key}
}

// TestACertificateIsReportedByTheNamesItWasIssuedFor is the field this adapter
// used to drop on the floor - ADR47.
//
// RFC 6125 section 6.4.4: a client MUST NOT match on the common name when the
// certificate presents a DNS-ID. So the subject alone described the certificate
// by the half a modern client is forbidden to use, in a product whose whole
// question is why somebody's client will not accept this server.
func TestACertificateIsReportedByTheNamesItWasIssuedFor(t *testing.T) {
	_, intermediate, leaf := bundle(t)
	host, port := serve(t, serverConfig(leaf, intermediate, true))

	shown, err := Shake(func(string) error { return nil })(
		context.Background(), host, port, "partner.test")
	if err != nil {
		t.Fatalf("the handshake failed: %v", err)
	}
	if len(shown.Chain[0].DNSNames) != 1 || shown.Chain[0].DNSNames[0] != "partner.test" {
		t.Errorf("the leaf was issued for %v and the record carries %v",
			leaf.cert.DNSNames, shown.Chain[0].DNSNames)
	}
	// An authority is not issued for a host name, and inventing one from its
	// common name would be this program answering with a value nobody presented.
	if len(shown.Chain[1].DNSNames) != 0 {
		t.Errorf("the authority carries names it never presented: %v", shown.Chain[1].DNSNames)
	}
}

// TestALeafWithNoSubjectIsReportedRatherThanRefused is the whole of ADR47,
// measured end to end.
//
// BEFORE THIS, THE CONTRACT REFUSED THIS CERTIFICATE, the orchestrator dropped
// the finding, and L4 answered "I could not assess this" - about a server that is
// correctly configured. The failure was ours and the report blamed nobody, which
// is the quietest way this product can be wrong.
func TestALeafWithNoSubjectIsReportedRatherThanRefused(t *testing.T) {
	root := mint(t, "certdoctor test root", nil, true)
	leaf := mintSANOnly(t, root, "partner.test", "www.partner.test")

	host, port := serve(t, &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.der, root.der}, PrivateKey: leaf.key}},
	})

	shown, err := Shake(func(string) error { return nil })(
		context.Background(), host, port, "partner.test")
	if err != nil {
		t.Fatalf("a server with a subject-less leaf would not hand shake: %v", err)
	}
	if shown.Chain[0].Subject != "" {
		t.Errorf("the fixture did not produce an empty subject: %q", shown.Chain[0].Subject)
	}
	if len(shown.Chain[0].DNSNames) != 2 {
		t.Fatalf("the only thing identifying this certificate did not survive: %v", shown.Chain[0].DNSNames)
	}
	// The issuer is still there, and that is what keeps the contract's remaining
	// rule meaningful: RFC 5280 forbids an empty one.
	if shown.Chain[0].Issuer == "" {
		t.Error("the issuer went missing, and RFC 5280 section 4.1.2.4 forbids that")
	}
}
