package model

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestTheExampleIsTheReportTheTestsDrawFrom - the report the window carries
// for its catalogue is the example.com report of testdata, byte for byte, and
// it reads as one.
func TestTheExampleIsTheReportTheTestsDrawFrom(t *testing.T) {
	saved, err := os.ReadFile(filepath.Join("testdata", "example-com.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(exampleDocument, saved) {
		t.Error("the window carries another example than testdata/example-com.json")
	}
	r, err := Example()
	if err != nil {
		t.Fatalf("the example the window carries does not read: %v", err)
	}
	if r.Target != "https://example.com" || r.Schema != SchemaVersion || len(r.Layers) == 0 {
		t.Errorf("the example reads as %q, schema %q, %d layers", r.Target, r.Schema, len(r.Layers))
	}
}
