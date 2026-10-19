package render

import (
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/layer"
	"github.com/donislawdev/certdoctor/internal/core/report"
)

// A row that takes another row's answer says WHICH row, on every surface -
// ADR108 part 4, schema 2.1. The member exists so a consumer counting stores
// does not count one store twice, and the populated shape is the one the
// validator would otherwise never compare against anything.
func TestARowTakingAnotherRowsAnswerSaysWhichOnEverySurface(t *testing.T) {
	refused := false
	finding := report.Finding{
		Kind: report.FindingTrustStore,
		Summary: `curl C:\Windows\system32\curl.exe does NOT accept the presented chain - the server's certificate ` +
			"names nowhere to check whether it was revoked, and this runtime refuses what it cannot check",
		Source: report.SourceDetected,
		TrustStore: &report.TrustStore{
			Runtime:              "curl",
			Instance:             `C:\Windows\system32\curl.exe`,
			StoreForm:            report.StoreSystem,
			Backend:              "schannel",
			DefersTo:             &report.StoreRef{Runtime: report.RuntimeSystemStore, Instance: report.InstanceCurrentUser},
			TrustAnchorCount:     91,
			TrustsPresentedChain: &refused,
			TrustFailure:         report.NoRevocationInfo,
			SelectedBy:           []string{"PATH"},
		},
	}
	if broken := finding.Breach(); broken != "" {
		t.Fatalf("the fixture is not a valid finding: %s", broken)
	}

	r := everyStatusReport()
	for i := range r.Layers {
		if r.Layers[i].ID == layer.TrustMatrix {
			r.Layers[i].Findings = []report.Finding{finding, bodyFixtures[report.FindingTrustStore]}
		}
	}

	document, err := Encode(r)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	if err := ValidateDocument(document); err != nil {
		t.Errorf("a document with a deferring row does not match its own schema: %v", err)
	}
	text := string(document)
	for _, want := range []string{
		`"defers_to": {`, `"runtime": "system-store"`, `"instance": "CurrentUser"`,
		`"trust_failure": "no_revocation_info"`,
		// The row that judged its store itself says so with a null, never with a
		// missing key - an absent key says nobody looked.
		`"defers_to": null`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the document does not carry %s", want)
		}
	}

	var page strings.Builder
	if err := (Terminal{}).Render(&page, r); err != nil {
		t.Fatalf("terminal: %v", err)
	}
	if !strings.Contains(page.String(), "names nowhere to check whether it was revoked") {
		t.Errorf("the terminal does not carry the row's own sentence:\n%s", page.String())
	}
}
