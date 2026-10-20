//go:build acceptance

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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
	if !reportsANodeRow(t, r.stdout) {
		t.Fatalf("no node row in the report, so node was never asked and the marker proves nothing:\n%s", r.stdout)
	}
}

// reportsANodeRow says whether the report carries a row of the node probe.
func reportsANodeRow(t *testing.T, stdout string) bool {
	t.Helper()
	var document struct {
		Layers []struct {
			Findings []struct {
				TrustStore *struct {
					Runtime string `json:"runtime"`
				} `json:"trust_store"`
			} `json:"findings"`
		} `json:"layers"`
	}
	if err := json.Unmarshal([]byte(stdout), &document); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	for _, layer := range document.Layers {
		for _, finding := range layer.Findings {
			if finding.TrustStore != nil && finding.TrustStore.Runtime == "node" {
				return true
			}
		}
	}
	return false
}
