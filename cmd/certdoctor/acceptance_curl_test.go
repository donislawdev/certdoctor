//go:build acceptance

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestTheShippedBinaryStartsCurlWithoutSSLKeyLogFile is OBS189 asked of the
// program as it ships, decided by the owner 2026-10-20. curl built on OpenSSL
// opens the file SSLKEYLOGFILE names as it starts, so curl --version alone
// creates it - the twin below shows whether this curl does - and no curl this
// program starts may write a file on its behalf, inviolable rule 14. Only the
// running binary can answer this: the probe is handed its runner in main.
//
// Skipped where no curl is on PATH, and where that curl creates no file - a
// Schannel build among them, which is every curl measured on Windows - because
// then the file staying absent would prove nothing.
func TestTheShippedBinaryStartsCurlWithoutSSLKeyLogFile(t *testing.T) {
	curl, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("no curl on PATH, so there is no curl process to keep the variable from")
	}
	keylog := filepath.Join(t.TempDir(), "keylog")
	setting := "SSLKEYLOGFILE=" + keylog

	// THE TWIN: this curl creates the file when it is handed the variable, so
	// the file staying absent below is this program's doing.
	twin := exec.Command(curl, "--version")
	twin.Env = append(minimalEnvironment(), setting)
	if out, err := twin.CombinedOutput(); err != nil {
		t.Fatalf("curl --version failed: %v\n%s", err, out)
	}
	if _, err := os.Stat(keylog); err != nil {
		t.Skip("this curl creates no key log file as it starts, so the file staying absent would prove nothing")
	}
	if err := os.Remove(keylog); err != nil {
		t.Fatalf("the key log file could not be cleared: %v", err)
	}

	r := startProgram(t, invocation{env: []string{setting}}, aLoopbackTarget(t), "--json")
	if _, err := os.Stat(keylog); err == nil {
		t.Fatal("a curl this program started created the key log file")
	}
	if len(trustRowsIn(t, r.stdout, "curl")) == 0 {
		t.Fatalf("no curl row in the report, so curl was never asked and the absent file proves nothing:\n%s", r.stdout)
	}
}
