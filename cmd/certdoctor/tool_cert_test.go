package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// testCertificate is a self-signed certificate valid around the harness's
// clock, as DER.
func testCertificate(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "cli.example.test"},
		DNSNames:     []string{"cli.example.test"},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TestTheCertificateToolReadsBytesEveryWay holds the shape bytes (ADR146): a
// DER file reaches the tool as it is - it is not text, and the door that
// holds a line to being text lets it through - and PEM arrives piped, in a
// request as text and in a request as base64.
func TestTheCertificateToolReadsBytesEveryWay(t *testing.T) {
	der := testCertificate(t)
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	request := func(input string) *string {
		return ptr(`{"schema_version":"1.0","tool":"cert","inputs":{"certificates":` + input + `}}`)
	}
	quoted, _ := json.Marshal(pemText)
	for _, c := range []struct {
		name string
		run  *harness
		form string
	}{
		{"a DER file", toolRun(nil, nil, map[string]string{"c.cer": string(der)}, "tool", "cert", "--file", "c.cer",
			"--json"), "der"},
		{"PEM piped", toolRun(ptr(pemText), nil, nil, "tool", "cert", "--json"), "pem"},
		{"a request with text", toolRun(request(`{"text":`+string(quoted)+`}`), nil, nil, "tool", "cert", "--request",
			"-", "--json"), "pem"},
		{"a request with bytes", toolRun(request(`{"base64":"`+base64.StdEncoding.EncodeToString(der)+`"}`), nil, nil,
			"tool", "cert", "--request", "-", "--json"), "der"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.run.code != exitcode.OK {
				t.Fatalf("exit %d: %s", c.run.code, c.run.stderr.String())
			}
			doc, err := spec.ReadDocument(c.run.stdout.Bytes())
			if err != nil {
				t.Fatalf("the window could not read what the command line wrote: %v", err)
			}
			var data struct {
				Form         string `json:"form"`
				Certificates []struct {
					Subject string `json:"subject"`
				} `json:"certificates"`
			}
			if err := json.Unmarshal(doc.Data, &data); err != nil || data.Form != c.form ||
				len(data.Certificates) != 1 || data.Certificates[0].Subject != "CN=cli.example.test" {
				t.Errorf("tool %q, data %s (%v)", doc.Tool, doc.Data, err)
			}
		})
	}
}

// TestACertificateIsNotAskedForAtATerminal: a chain has many lines and no
// Enter that ends it, so a terminal with nothing piped is told how to give it
// rather than asked to paste.
func TestACertificateIsNotAskedForAtATerminal(t *testing.T) {
	run := toolRun(nil, ptr("-----BEGIN CERTIFICATE-----\n"), nil, "tool", "cert")
	if run.code != exitcode.Config {
		t.Fatalf("exit %d, want CONFIG", run.code)
	}
	if got := run.stderr.String(); strings.Contains(got, "Paste") ||
		!strings.Contains(got, "Pipe the certificates in or name a file with --file") {
		t.Errorf("stderr %q", got)
	}
	help := toolRun(nil, nil, nil, "tool", "cert", "--help").stdout.String()
	if strings.Contains(help, "paste") || !strings.Contains(help, "certdoctor tool cert --file chain.pem") ||
		!strings.Contains(help, "The certificates are never taken as an argument") {
		t.Errorf("help:\n%s", help)
	}
}
