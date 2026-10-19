package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// TestTheReportSaysItDoesNotLookInsideContainers is inviolable rule 1 after
// ADR108. The container layer stood in every report as UNKNOWN "not
// implemented" and said this on its own; with the layer gone, a report that
// stayed quiet about it would read as a run that looked everywhere.
func TestTheReportSaysItDoesNotLookInsideContainers(t *testing.T) {
	var document struct {
		Notes []struct {
			Kind   string `json:"kind"`
			Field  string `json:"field"`
			Detail string `json:"detail"`
		} `json:"notes"`
	}
	if err := json.Unmarshal(invoke("https://example.com", "--json").stdout.Bytes(), &document); err != nil {
		t.Fatalf("the document does not parse: %v", err)
	}
	found := 0
	for _, note := range document.Notes {
		if note.Kind == string(report.NoteNotImplemented) && note.Field == "layers" &&
			strings.Contains(note.Detail, "inside a container is not built yet") {
			found++
		}
	}
	if found != 1 {
		t.Errorf("%d note(s) say the report does not look inside containers, want exactly 1", found)
	}
	if out := invoke("https://example.com").stdout.String(); !strings.Contains(out, "inside a container is not built yet") {
		t.Error("the terminal report does not carry the note the document carries")
	}
}
