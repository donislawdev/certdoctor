//go:build acceptance

package main

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/tool/spec"
)

// The tools through the process boundary (ADR141): standard input from a real
// pipe, the code the process really ends with, and the disk watched rather
// than the source read. The tests in tool_test.go run the same paths inside
// the process, where a pipe is a strings.Reader and a code is a return value.

func TestTheShippedBinaryDecodesATokenPipedIn(t *testing.T) {
	r := startProgram(t, invocation{stdin: "Bearer " + testToken + "\r\n"}, "tool", "jwt", "--json")
	if r.code != 0 || r.stderr != "" {
		t.Fatalf("exit %d, stderr %q", r.code, r.stderr)
	}
	doc, err := spec.ReadDocument([]byte(r.stdout))
	if err != nil {
		t.Fatalf("the window could not read what the binary wrote: %v\n%s", err, r.stdout)
	}
	if doc.Tool != "jwt" || len(doc.Notes) != 1 || !strings.Contains(string(doc.Data), "MARKERSUBJECT") {
		t.Errorf("the document is not the token's: %+v", doc)
	}
}

func TestTheShippedBinaryRefusesATokenAsAnArgumentWithoutRepeatingIt(t *testing.T) {
	r := runProgram(t, "tool", "jwt", testToken)
	if r.code != 2 || r.stdout != "" {
		t.Errorf("exit %d and %d bytes on standard output, want 2 and none", r.code, len(r.stdout))
	}
	if strings.Contains(r.stderr, testToken[:20]) || !strings.Contains(r.stderr, "takes no argument") {
		t.Errorf("stderr %q", r.stderr)
	}
}

// TestTheShippedBinaryDecodesACertificateEveryWayItArrives holds ADR146
// through the process boundary: a chain with a private key in it piped in,
// where no line of the key may come out, and a DER file named with --file,
// whose bytes no door may take for text.
func TestTheShippedBinaryDecodesACertificateEveryWayItArrives(t *testing.T) {
	der := testCertificate(t)
	key := "-----BEGIN PRIVATE KEY-----\nMARKERKEYLINEMARKERKEYLINEMARKERKEYA\n-----END PRIVATE KEY-----\n"
	piped := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) + key
	r := startProgram(t, invocation{stdin: piped}, "tool", "cert", "--json")
	if r.code != 0 || r.stderr != "" {
		t.Fatalf("exit %d, stderr %q", r.code, r.stderr)
	}
	doc, err := spec.ReadDocument([]byte(r.stdout))
	if err != nil {
		t.Fatalf("the window could not read what the binary wrote: %v\n%s", err, r.stdout)
	}
	if doc.Tool != "cert" || !strings.Contains(string(doc.Data), "cli.example.test") ||
		strings.Contains(r.stdout, "MARKERKEYLINE") {
		t.Errorf("the document is not the certificate's, or carries the key: %s", r.stdout)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "c.cer"), der, 0o600); err != nil {
		t.Fatal(err)
	}
	r = startProgram(t, invocation{dir: dir}, "tool", "cert", "--file", "c.cer", "--json")
	if r.code != 0 || !strings.Contains(r.stdout, `"form": "der"`) {
		t.Errorf("a DER file: exit %d, stderr %q", r.code, r.stderr)
	}
}

// TestTheShippedBinaryToolWritesNothing holds inviolable rule 14 for the tools:
// decoding a token, refusing one and listing the tools leave the disk as it
// was.
func TestTheShippedBinaryToolWritesNothing(t *testing.T) {
	dir := t.TempDir()
	before := census(t, dir)
	for _, args := range [][]string{{"tool"}, {"tool", "jwt", "--json"}, {"tool", "jwt", "--file", "missing.txt"},
		{"tool", "cert", "--json"}} {
		startProgram(t, invocation{dir: dir, stdin: testToken}, args...)
	}
	if added := appeared(before, census(t, dir)); len(added) != 0 {
		t.Errorf("a tool wrote %v", added)
	}
}
