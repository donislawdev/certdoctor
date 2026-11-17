//go:build acceptance

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"strings"
	"testing"

	"crypto/x509"

	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// requestWithPassword is a signed request for cli.example.test carrying a
// challenge password - put together by hand, because crypto/x509 does not
// write that attribute (RFC 2985 section 5.4.1).
func requestWithPassword(t *testing.T, password string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	subject, err := asn1.Marshal(pkix.Name{CommonName: "cli.example.test"}.ToRDNSequence())
	if err != nil {
		t.Fatal(err)
	}
	value, err := asn1.Marshal(password)
	if err != nil {
		t.Fatal(err)
	}
	attribute, err := asn1.Marshal(struct {
		ID     asn1.ObjectIdentifier
		Values []asn1.RawValue `asn1:"set"`
	}{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}, []asn1.RawValue{{FullBytes: value}}})
	if err != nil {
		t.Fatal(err)
	}
	tbs, err := asn1.Marshal(struct {
		Version    int
		Subject    asn1.RawValue
		PublicKey  asn1.RawValue
		Attributes []asn1.RawValue `asn1:"tag:0"`
	}{0, asn1.RawValue{FullBytes: subject}, asn1.RawValue{FullBytes: spki}, []asn1.RawValue{{FullBytes: attribute}}})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(tbs)
	signature, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}{asn1.RawValue{FullBytes: tbs}, pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}},
		asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TestTheShippedBinaryDecodesARequestAndKeepsItsSecrets holds ADR154 through
// the process boundary: a request carrying a challenge password, with a
// private key piped beside it - the request is decoded, its signature
// verified, the password said to be there, and neither the password nor a
// line of the key comes out on either stream.
func TestTheShippedBinaryDecodesARequestAndKeepsItsSecrets(t *testing.T) {
	const password = "MARKERPASSWORDMARKER"
	key := "-----BEGIN PRIVATE KEY-----\nMARKERKEYLINEMARKERKEYLINEMARKERKEYA\n-----END PRIVATE KEY-----\n"
	request := requestWithPassword(t, password)
	piped := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: request})) + key
	for _, format := range []string{"--json", ""} {
		args := []string{"tool", "csr"}
		if format != "" {
			args = append(args, format)
		}
		r := startProgram(t, invocation{stdin: piped}, args...)
		if r.code != 0 {
			t.Fatalf("%v: exit %d, stderr %q", args, r.code, r.stderr)
		}
		out := r.stdout + r.stderr
		if strings.Contains(out, password) || strings.Contains(out, "MARKERKEYLINE") {
			t.Fatalf("%v: the password or the key came out:\n%s", args, out)
		}
		if format == "" {
			continue
		}
		doc, err := spec.ReadDocument([]byte(r.stdout))
		if err != nil {
			t.Fatalf("the window could not read what the binary wrote: %v\n%s", err, r.stdout)
		}
		if doc.Tool != "csr" || !strings.Contains(string(doc.Data), `"challenge_password":true`) ||
			!strings.Contains(string(doc.Data), `"signature_valid":true`) {
			t.Errorf("the document does not say what the request is: %s", doc.Data)
		}
	}
}
