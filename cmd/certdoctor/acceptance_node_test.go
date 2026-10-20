//go:build acceptance

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestTheShippedBinaryStartsNodeWithoutNodeOptions is ADR111 part 2 asked of
// the program as it ships. A NODE_OPTIONS preloading a module runs that module
// inside every node process started with it - the twin below shows node doing
// exactly that here - so the node this program starts must not get it. Only the
// running binary can answer this: the probe is handed its runner in main, and
// a wrong one there passes every test in the probe's own package.
//
// Skipped where no node is on PATH, because then there is nothing to start.
func TestTheShippedBinaryStartsNodeWithoutNodeOptions(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("no node on PATH, so there is no node process to keep the preload out of")
	}
	dir := t.TempDir()
	marker := filepath.ToSlash(filepath.Join(dir, "preloaded"))
	preload := filepath.ToSlash(filepath.Join(dir, "preload.js"))
	if err := os.WriteFile(preload, []byte("require('fs').writeFileSync("+strconv.Quote(marker)+", 'ran');\n"), 0o600); err != nil {
		t.Fatalf("no preload: %v", err)
	}
	options := "NODE_OPTIONS=--require " + strconv.Quote(preload)

	// THE TWIN: node runs the preload when it is handed the variable, so the
	// marker staying absent below is this program's doing.
	twin := exec.Command(node, "-e", "0")
	twin.Env = append(minimalEnvironment(), options)
	if out, err := twin.CombinedOutput(); err != nil {
		t.Fatalf("node would not run with the preload: %v\n%s", err, out)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("node did not run the preload either, so this test would prove nothing: %v", err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatalf("the marker could not be cleared: %v", err)
	}

	r := startProgram(t, invocation{env: []string{options}}, aLoopbackTarget(t), "--json")
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the preload ran inside the node process this program started")
	}
	if len(trustRowsIn(t, r.stdout, "node")) == 0 {
		t.Fatalf("no node row in the report, so node was never asked and the marker proves nothing:\n%s", r.stdout)
	}
}

// TestTheShippedBinaryStartsNodeWithoutOpenSSLConf is OBS188 asked of the
// program as it ships, decided by the owner 2026-10-20. An OpenSSL configuration
// naming a provider module loads that module into every node started with it.
// The twin below names a module that does not exist, so node stops rather than
// loads it, and a row that does not report that stop shows the node this
// program started never read the file.
//
// Skipped where no node is on PATH, and where that node does not stop for the
// twin, because then a row without the stop would prove nothing.
func TestTheShippedBinaryStartsNodeWithoutOpenSSLConf(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("no node on PATH, so there is no node process to keep the configuration from")
	}
	dir := t.TempDir()
	// OpenSSL reads a backslash in a value as an escape, so the path goes in with
	// forward slashes, which Windows accepts as well.
	module := filepath.ToSlash(filepath.Join(dir, "missing", "provider-module"))
	config := filepath.Join(dir, "openssl.cnf")
	body := "nodejs_conf = nodejs_init\n[nodejs_init]\nproviders = provider_sect\n[provider_sect]\nprobe = probe_sect\n" +
		"[probe_sect]\nmodule = " + module + "\nactivate = 1\n"
	if err := os.WriteFile(config, []byte(body), 0o600); err != nil {
		t.Fatalf("no configuration: %v", err)
	}
	setting := "OPENSSL_CONF=" + config

	// THE TWIN: node reads the file it is handed and stops on the module.
	twin := exec.Command(node, "-e", "0")
	twin.Env = append(minimalEnvironment(), setting)
	if err := twin.Run(); err == nil {
		t.Skip("node started with a configuration naming a missing provider module, so its stop cannot be looked for")
	}

	r := startProgram(t, invocation{env: []string{setting}}, aLoopbackTarget(t), "--json")
	rows := trustRowsIn(t, r.stdout, "node")
	if len(rows) == 0 {
		t.Fatalf("no node row in the report, so node was never asked and nothing is proven:\n%s", r.stdout)
	}
	for _, reason := range rows {
		if strings.HasPrefix(reason, "node exited with") {
			t.Errorf("the node this program started read OPENSSL_CONF: %s", reason)
		}
	}
}

// trustRowsIn is the not_assessed of every trust row of one runtime in a
// report, empty for a row with a verdict.
func trustRowsIn(t *testing.T, stdout, runtime string) []string {
	t.Helper()
	var document struct {
		Layers []struct {
			Findings []struct {
				TrustStore *struct {
					Runtime     string  `json:"runtime"`
					NotAssessed *string `json:"not_assessed"`
				} `json:"trust_store"`
			} `json:"findings"`
		} `json:"layers"`
	}
	if err := json.Unmarshal([]byte(stdout), &document); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	var reasons []string
	for _, layer := range document.Layers {
		for _, finding := range layer.Findings {
			if store := finding.TrustStore; store != nil && store.Runtime == runtime {
				reason := ""
				if store.NotAssessed != nil {
					reason = *store.NotAssessed
				}
				reasons = append(reasons, reason)
			}
		}
	}
	return reasons
}
