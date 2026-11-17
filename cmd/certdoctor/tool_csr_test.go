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
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// testRequest is a certificate signing request for cli.example.test, as DER.
func testRequest(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "cli.example.test"}, DNSNames: []string{"cli.example.test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TestTheRequestToolReadsBytesEveryWay holds ADR154 at the command line: a
// DER file, PEM piped, and a request document carrying the input csr as text
// and as base64 all reach the decoder, and the window reads what comes out.
func TestTheRequestToolReadsBytesEveryWay(t *testing.T) {
	der := testRequest(t)
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	request := func(input string) *string {
		return ptr(`{"schema_version":"1.0","tool":"csr","inputs":{"csr":` + input + `}}`)
	}
	quoted, _ := json.Marshal(pemText)
	for _, c := range []struct {
		name string
		run  *harness
		form string
	}{
		{"a DER file", toolRun(nil, nil, map[string]string{"r.csr": string(der)}, "tool", "csr", "--file", "r.csr",
			"--json"), "der"},
		{"PEM piped", toolRun(ptr(pemText), nil, nil, "tool", "csr", "--json"), "pem"},
		{"a request with text", toolRun(request(`{"text":`+string(quoted)+`}`), nil, nil, "tool", "csr", "--request",
			"-", "--json"), "pem"},
		{"a request with bytes", toolRun(request(`{"base64":"`+base64.StdEncoding.EncodeToString(der)+`"}`), nil, nil,
			"tool", "csr", "--request", "-", "--json"), "der"},
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
				Form    string `json:"form"`
				Request struct {
					Subject  string   `json:"subject"`
					DNSNames []string `json:"dns_names"`
				} `json:"request"`
			}
			if err := json.Unmarshal(doc.Data, &data); err != nil || data.Form != c.form || doc.Tool != "csr" ||
				data.Request.Subject != "CN=cli.example.test" || len(data.Request.DNSNames) != 1 {
				t.Errorf("tool %q, data %s (%v)", doc.Tool, doc.Data, err)
			}
		})
	}
}

// TestARequestIsNotAskedForAtATerminalAndACertificateIsSentOn: a request has
// many lines and no Enter that ends it, so a terminal with nothing piped is
// told how to give it; and a certificate given in its place ends with CONFIG
// and the tool that reads it.
func TestARequestIsNotAskedForAtATerminalAndACertificateIsSentOn(t *testing.T) {
	run := toolRun(nil, ptr("-----BEGIN CERTIFICATE REQUEST-----\n"), nil, "tool", "csr")
	if run.code != exitcode.Config || strings.Contains(run.stderr.String(), "Paste") ||
		!strings.Contains(run.stderr.String(), "name a file with --file") {
		t.Errorf("exit %d, stderr %q", run.code, run.stderr.String())
	}
	certificate := toolRun(nil, nil, map[string]string{"c.cer": string(testCertificate(t))}, "tool", "csr", "--file",
		"c.cer")
	if certificate.code != exitcode.Config || !strings.Contains(certificate.stderr.String(), "certdoctor tool cert") {
		t.Errorf("a certificate: exit %d, stderr %q", certificate.code, certificate.stderr.String())
	}
	help := toolRun(nil, nil, nil, "tool", "csr", "--help").stdout.String()
	if !strings.Contains(help, "certdoctor tool csr --file request.csr") {
		t.Errorf("help:\n%s", help)
	}
}
