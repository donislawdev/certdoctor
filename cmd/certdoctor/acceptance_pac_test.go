//go:build acceptance

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

// aPACServer serves one PAC file over plain HTTP on loopback and returns its
// address.
func aPACServer(t *testing.T, source string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("no loopback port to listen on: %v", err)
	}
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
			_, _ = w.Write([]byte(source))
		}),
		ReadHeaderTimeout: time.Second,
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return fmt.Sprintf("http://%s/proxy.pac", listener.Addr())
}

// TestAPACFileAskingForTenGigabytesLeavesAReport is OBS199 on the program a
// user gets. Until ADR150 this line ended certdoctor with no report at all -
// "fatal error: out of memory", or the process killed by the system - because
// the built-in allocates in native code the sandbox's stopwatch cannot reach.
// Now the file runs in a process of its own: that process ends, the run goes
// on, and the report says what happened to the file.
func TestAPACFileAskingForTenGigabytesLeavesAReport(t *testing.T) {
	script := aPACServer(t, `function FindProxyForURL(url, host) { return "x".repeat(1e10); }`)
	start := time.Now()
	run := runProgram(t, aLoopbackTarget(t), "--pac-url", script, "--json")
	elapsed := time.Since(start)

	var document map[string]any
	if err := json.Unmarshal([]byte(run.stdout), &document); err != nil {
		t.Fatalf("no report came out (code %d, %v): %v\n%s", run.code, elapsed, err, run.stderr)
	}
	if run.code != 4 && run.code != 5 {
		t.Errorf("code %d, want the diagnosis's own 4 or 5", run.code)
	}
	if document["schema_version"] != "2.5" {
		t.Errorf("schema_version %v", document["schema_version"])
	}
	outcomes := pacOutcomes(document)
	if len(outcomes) != 1 || (outcomes[0] != "memory_ceiling" && outcomes[0] != "evaluator_failed") {
		t.Errorf("the PAC row says %v, want memory_ceiling or evaluator_failed", outcomes)
	}
}

// pacOutcomes collects every pac_script.outcome in a report, wherever its
// finding sits.
func pacOutcomes(v any) []string {
	var found []string
	switch v := v.(type) {
	case map[string]any:
		if body, ok := v["pac_script"].(map[string]any); ok {
			if outcome, ok := body["outcome"].(string); ok {
				found = append(found, outcome)
			}
		}
		for _, child := range v {
			found = append(found, pacOutcomes(child)...)
		}
	case []any:
		for _, child := range v {
			found = append(found, pacOutcomes(child)...)
		}
	}
	return found
}
