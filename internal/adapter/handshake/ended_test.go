package handshake

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"unicode/utf8"

	core "github.com/donislawdev/certdoctor/internal/core/handshake"
)

// negativeSerial rebuilds a certificate with the serial number -1 and signs it
// again with the issuer's key - the shape of EC-ACC from OBS210, sent by a
// server this time. crypto/x509 refuses to create such a certificate, so its DER
// is rewritten by hand: the same rebuild as negativeSerial in
// internal/adapter/probe/unreadable_test.go and probe S30.
func negativeSerial(t testing.TB, der []byte, issuer *ecdsa.PrivateKey) []byte {
	t.Helper()
	var certificate struct {
		TBS       asn1.RawValue
		Algorithm asn1.RawValue
		Signature asn1.BitString
	}
	if rest, err := asn1.Unmarshal(der, &certificate); err != nil || len(rest) != 0 {
		t.Fatalf("the certificate to rebuild is not one: %v", err)
	}
	var tbs asn1.RawValue
	if _, err := asn1.Unmarshal(certificate.TBS.FullBytes, &tbs); err != nil {
		t.Fatalf("the TBSCertificate will not decode: %v", err)
	}
	var fields []asn1.RawValue
	for rest := tbs.Bytes; len(rest) > 0; {
		var field asn1.RawValue
		next, err := asn1.Unmarshal(rest, &field)
		if err != nil {
			t.Fatalf("a TBSCertificate field will not decode: %v", err)
		}
		fields, rest = append(fields, field), next
	}
	if len(fields) < 2 || fields[1].Tag != asn1.TagInteger {
		t.Fatal("the TBSCertificate holds no serial number where RFC 5280 puts it")
	}
	fields[1] = asn1.RawValue{FullBytes: []byte{asn1.TagInteger, 0x01, 0xff}}
	var body []byte
	for _, field := range fields {
		body = append(body, field.FullBytes...)
	}
	rebuilt, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
	if err != nil {
		t.Fatalf("the TBSCertificate will not encode: %v", err)
	}
	digest := sha256.Sum256(rebuilt)
	signature, err := ecdsa.SignASN1(rand.Reader, issuer, digest[:])
	if err != nil {
		t.Fatalf("no signature: %v", err)
	}
	certificate.TBS = asn1.RawValue{FullBytes: rebuilt}
	certificate.Signature = asn1.BitString{Bytes: signature, BitLength: 8 * len(signature)}
	out, err := asn1.Marshal(certificate)
	if err != nil {
		t.Fatalf("the certificate will not encode: %v", err)
	}
	if _, err := x509.ParseCertificate(out); err == nil {
		t.Fatal("the rebuilt certificate is one Go reads, so nothing below is about a certificate it cannot")
	}
	return out
}

func shakeAny(t *testing.T, chain [][]byte, key *ecdsa.PrivateKey) (core.Presented, error) {
	t.Helper()
	host, port := serve(t, &tls.Config{Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: key}}})
	return Shake(func(string) error { return nil })(context.Background(), host, port, "partner.test")
}

// TestACertificateGoCannotReadIsEndedHereRatherThanBlamedOnTheServer is
// ADR129 at the wire, closing OBS211.
//
// Measured with probe S30 on 2026-11-09: OpenSSL, Python, Node, curl on
// schannel and Java all completed this handshake, with the certificate as the
// leaf and as the intermediate, and this adapter reported the server as the
// one that did not.
func TestACertificateGoCannotReadIsEndedHereRatherThanBlamedOnTheServer(t *testing.T) {
	root, intermediate, leaf := bundle(t)
	for name, chain := range map[string][][]byte{
		"leaf":         {negativeSerial(t, leaf.der, intermediate.key), intermediate.der},
		"intermediate": {leaf.der, negativeSerial(t, intermediate.der, root.key)},
	} {
		_, err := shakeAny(t, chain, leaf.key)
		var ended core.EndedHere
		if !errors.As(err, &ended) {
			t.Errorf("a %s Go cannot read came back as %v, which blames the server for our own library", name, err)
			continue
		}
		if ended.Words == "" {
			t.Errorf("a %s Go cannot read was reported without the library's own words", name)
		}
	}
}

// TestABadSignatureAfterTheChainWasReadIsStillTheServers is the other half:
// the library read the certificates, and the server then signed the handshake
// with a key that is not the leaf's. Every client refuses that, so it stays the
// server's failure - the hook is what tells the two apart.
func TestABadSignatureAfterTheChainWasReadIsStillTheServers(t *testing.T) {
	_, intermediate, leaf := bundle(t)
	stranger := mint(t, "certdoctor test stranger", nil, true)
	_, err := shakeAny(t, [][]byte{leaf.der, intermediate.der}, stranger.key)
	if !errors.Is(err, core.ErrRejected) {
		t.Errorf("a handshake signed with the wrong key came back as %v, and the server is the one at fault", err)
	}
}

// TestTheLibraryEndingTheHandshakeIsToldFromTheServerEndingIt pins the shapes
// endedHere reads, each read in src/crypto/tls of go1.27.3.
func TestTheLibraryEndingTheHandshakeIsToldFromTheServerEndingIt(t *testing.T) {
	for _, theirs := range []error{
		&net.OpError{Op: "remote error", Err: errors.New("handshake failure")},
		io.EOF,
		fmt.Errorf("reading a record: %w", io.ErrUnexpectedEOF),
		tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"},
	} {
		if got := failure(theirs, false); !errors.Is(got, core.ErrRejected) {
			t.Errorf("%#v came from the server or the wire and mapped to %v", theirs, got)
		}
	}

	var ended core.EndedHere
	if got := failure(errors.New("tls: something of the library's own"), false); !errors.As(got, &ended) {
		t.Fatalf("a bare failure before the certificates were read mapped to %v", got)
	}
	if ended.Words != "tls: something of the library's own" {
		t.Errorf("the library's words arrived as %q", ended.Words)
	}
}

// TestTheLibrarysWordsAreBounded: crypto/x509 can quote a field the server
// chose, so a row must not carry all of it.
func TestTheLibrarysWordsAreBounded(t *testing.T) {
	if got := bounded("short"); got != "short" {
		t.Errorf("words under the limit came back as %q", got)
	}
	exact := strings.Repeat("a", wordsLimit)
	if got := bounded(exact); got != exact {
		t.Error("words exactly at the limit were cut")
	}
	// One byte, then two-byte characters: with an even limit the cut falls
	// inside one of them, which is the case the walk back exists for.
	long := "a" + strings.Repeat(string(rune(0x17c)), wordsLimit)
	got := bounded(long)
	if !strings.HasSuffix(got, "...") || len(got) > wordsLimit+len("...") {
		t.Errorf("long words came back %d bytes long, without saying they were cut", len(got))
	}
	if !utf8.ValidString(got) {
		t.Error("the cut split a character in two")
	}

	// And the words reaching the core are the bounded ones.
	var ended core.EndedHere
	if errors.As(failure(errors.New(strings.Repeat("a", 4*wordsLimit)), false), &ended) &&
		len(ended.Words) > wordsLimit+len("...") {
		t.Errorf("the library's words reached the core %d bytes long", len(ended.Words))
	}
}
