package run

import (
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/redact"
	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/status"
	"github.com/donislawdev/certdoctor/internal/core/trust"
)

// THE HALF THAT MUST BE MASKED AND THE HALF THAT MUST NOT ARE BOTH CHECKED. A
// rule enforced in one direction only can be satisfied by a function that masks
// everything, which would strip the evidence the matrix exists to carry.
func TestMaskingTakesThePathAndLeavesTheEvidence(t *testing.T) {
	// The name is registered as sensitive so this test proves the FIELD travels
	// through masking - what redaction knows about is a separate question, and
	// OBS70 records that the account name is not supplied to it yet.
	redaction := redact.New(redact.Everything, redact.Host("jdoe"))
	trusts := true
	store := report.TrustStore{
		Runtime:              "curl",
		Instance:             `C:\Users\jdoe\tools\curl.exe`,
		Variant:              "",
		Architecture:         "x64",
		StorePath:            `C:\Users\jdoe\certs\bundle.crt`,
		StoreForm:            report.StoreFile,
		Backend:              "openssl",
		TrustAnchorCount:     150,
		TrustsPresentedChain: &trusts,
		SelectedBy:           []string{"PATH"},
	}
	finding := report.Finding{
		Kind:       report.FindingTrustStore,
		Summary:    "curl trusts the presented chain",
		Source:     report.SourceDetected,
		TrustStore: &store,
	}

	Options{Redaction: redaction}.maskFinding(&finding)
	body := finding.TrustStore

	if strings.Contains(body.StorePath, "jdoe") {
		t.Errorf("the account name survived in the store path: %q", body.StorePath)
	}
	// For curl the thing telling two instances apart IS the path to the binary,
	// which is the easy one to miss.
	if strings.Contains(body.Instance, "jdoe") {
		t.Errorf("the account name survived in the instance: %q", body.Instance)
	}
	if body.TrustAnchorCount != 150 {
		t.Errorf("the anchor count was altered to %d - it names nobody and is evidence", body.TrustAnchorCount)
	}
	if body.Backend != "openssl" || body.Architecture != "x64" || body.Runtime != "curl" {
		t.Errorf("a field from a closed list was masked: %+v", *body)
	}
	if len(body.SelectedBy) != 1 || body.SelectedBy[0] != "PATH" {
		t.Errorf("the names of the deciding variables were masked: %v", body.SelectedBy)
	}
	// The body is REPLACED rather than written through, so the evidence a layer
	// handed over is not rewritten underneath it.
	if store.StorePath == body.StorePath {
		t.Error("masking wrote through the pointer into the layer's own evidence")
	}
}

// A store that could not be read explains itself in English, and the most useful
// such sentence names the file it failed on - which is where a path leaks.
func TestTheReasonAStoreCouldNotBeReadIsMaskedToo(t *testing.T) {
	// The name is registered as sensitive so this test proves the FIELD travels
	// through masking - what redaction knows about is a separate question, and
	// OBS70 records that the account name is not supplied to it yet.
	redaction := redact.New(redact.Everything, redact.Host("jdoe"))
	store := report.TrustStore{
		Runtime:     "git",
		Instance:    "/opt/git",
		StoreForm:   report.StoreSystem,
		NotAssessed: `the bundle at C:\Users\jdoe\certs\bundle.crt could not be read`,
		SelectedBy:  []string{},
	}
	finding := report.Finding{
		Kind:       report.FindingTrustStore,
		Summary:    "git could not be assessed",
		Source:     report.SourceDetected,
		TrustStore: &store,
	}

	Options{Redaction: redaction}.maskFinding(&finding)
	if strings.Contains(finding.TrustStore.NotAssessed, "jdoe") {
		t.Errorf("the account name survived in the reason: %q", finding.TrustStore.NotAssessed)
	}
}

// The boundary carries four fields across unchanged - it grades nothing and
// masks nothing, which is what keeps ADR7 and ADR18 true at this seam.
func TestTheTrustBoundaryCarriesTheAnswerUnchanged(t *testing.T) {
	findings := []report.Finding{{Kind: report.FindingTrustStore, Summary: "one"}}
	answer := answerFromTrust(trust.Result{
		Status:   status.Warn,
		Reason:   status.ReasonAccessDenied,
		Detail:   "one store could not be read",
		Findings: findings,
	})

	if answer.Status != status.Warn || answer.Reason != status.ReasonAccessDenied {
		t.Errorf("got %s / %s, want WARN / access_denied", answer.Status, answer.Reason)
	}
	if answer.Detail != "one store could not be read" {
		t.Errorf("detail %q", answer.Detail)
	}
	if len(answer.Findings) != 1 {
		t.Errorf("%d findings crossed, want 1", len(answer.Findings))
	}
}

// TestMaskingTakesThePathOutOfTheCommandToo is the one field where leaving a
// path behind would be worst.
//
// THE COMMAND IS THE LINE MOST LIKELY TO BE PASTED INTO A TICKET, so a store
// path masked in one field and left whole in the command would mean the
// directory travels anyway - in the half somebody copies. The two also have to
// come out as ONE pseudonym: two names for one directory would say there are two
// stores, which is the exact failure pseudonyms exist to prevent.
func TestMaskingTakesThePathOutOfTheCommandToo(t *testing.T) {
	redaction := redact.New(redact.Everything, redact.Host("jdoe"))
	no := false
	store := report.TrustStore{
		Runtime:              "curl",
		Instance:             `C:\Users\jdoe\tools\curl.exe`,
		StorePath:            `C:\Users\jdoe\certs\bundle.crt`,
		StoreForm:            report.StoreFile,
		Backend:              "openssl",
		TrustAnchorCount:     150,
		TrustsPresentedChain: &no,
		TrustFailure:         report.UnknownAuthority,
		SelectedBy:           []string{"PATH"},
		Fix: &report.Fix{
			Command:      `cat <certificate.pem> >> "C:\Users\jdoe\certs\bundle.crt"`,
			Placeholders: []string{"<certificate.pem>"},
		},
	}
	original := *store.Fix
	finding := report.Finding{
		Kind:       report.FindingTrustStore,
		Summary:    "curl does NOT trust the presented chain",
		Source:     report.SourceDetected,
		TrustStore: &store,
	}

	Options{Redaction: redaction}.maskFinding(&finding)
	masked := finding.TrustStore

	if strings.Contains(masked.Fix.Command, "jdoe") {
		t.Errorf("the account name survived in the command somebody pastes: %q", masked.Fix.Command)
	}
	if !strings.Contains(masked.Fix.Command, masked.StorePath) {
		t.Errorf("the store path and the same path inside the command came out as two different names: %q is not in %q",
			masked.StorePath, masked.Fix.Command)
	}
	// The closed-list half, checked in the other direction as everywhere else.
	if masked.TrustFailure != report.UnknownAuthority {
		t.Errorf("a word from a closed list was masked: %q", masked.TrustFailure)
	}
	if len(masked.Fix.Placeholders) != 1 || masked.Fix.Placeholders[0] != "<certificate.pem>" {
		t.Errorf("a placeholder was masked, and it names nobody: %v", masked.Fix.Placeholders)
	}
	// MASKING MUST NOT REACH BACK THROUGH THE POINTER. The finding is copied and
	// the Fix behind it is not, so an edit in place would rewrite the row the
	// core still holds - and the masked and unmasked reports would be one object.
	if store.Fix != nil && original.Command != `cat <certificate.pem> >> "C:\Users\jdoe\certs\bundle.crt"` {
		t.Error("masking edited the fix in place instead of copying it")
	}
}

// A row with nothing to fix must survive masking rather than panicking on a nil,
// and that is the common case: every green row in the matrix.
func TestMaskingARowWithNoCommandIsFine(t *testing.T) {
	redaction := redact.New(redact.Everything, redact.Host("jdoe"))
	trusts := true
	finding := report.Finding{
		Kind:    report.FindingTrustStore,
		Summary: "curl trusts the presented chain",
		Source:  report.SourceDetected,
		TrustStore: &report.TrustStore{
			Runtime: "curl", Instance: "/usr/bin/curl",
			StorePath: "/etc/ssl/certs/ca-certificates.crt", StoreForm: report.StoreFile,
			TrustAnchorCount: 150, TrustsPresentedChain: &trusts, SelectedBy: []string{},
		},
	}
	Options{Redaction: redaction}.maskFinding(&finding)
	if finding.TrustStore.Fix != nil {
		t.Error("masking invented a command")
	}
}
