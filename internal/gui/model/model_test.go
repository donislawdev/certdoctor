package model

import (
	"os"
	"path/filepath"
	"testing"
)

// The three reports in testdata were written by certdoctor 0.1.0 with --json
// on 2026-11-03, against example.com and two hosts of badssl.com, and kept
// with the parts that named the machine they ran on replaced: the account in
// profile paths and the address of the local resolver.

// TestTheWindowReadsTheReportsItIsDrawnFrom reads each of them and checks the
// facts the screens are built from.
func TestTheWindowReadsTheReportsItIsDrawnFrom(t *testing.T) {
	for _, c := range []struct {
		file, target   string
		layerStatus    []Status
		yes, no, fixes int
	}{
		{"example-com.json", "https://example.com", []Status{Pass, Pass, Unknown, Pass, Pass, Fail}, 11, 5, 3},
		{"untrusted-root.json", "https://untrusted-root.badssl.com", []Status{Pass, Pass, Unknown, Pass, Pass, Fail}, 0, 16, 13},
		{"wrong-host.json", "https://wrong.host.badssl.com", []Status{Pass, Pass, Unknown, Pass, Fail, Pass}, 16, 0, 0},
	} {
		r := read(t, c.file)
		if r.Target != c.target || r.Version != "0.1.0" || r.OS != "windows" {
			t.Errorf("%s: target %q, version %q, system %q", c.file, r.Target, r.Version, r.OS)
		}
		if r.Verdict.Status != Fail || r.Verdict.ExitCode != 4 || r.Verdict.Sentence == "" {
			t.Errorf("%s: verdict %+v", c.file, r.Verdict)
		}
		if len(r.Layers) != len(c.layerStatus) {
			t.Fatalf("%s: %d layers, want %d", c.file, len(r.Layers), len(c.layerStatus))
		}
		for i, want := range c.layerStatus {
			if l := r.Layers[i]; l.Status != want || l.Name == "" || l.Detail == "" {
				t.Errorf("%s: layer %s is %s with name %q, want %s", c.file, l.ID, l.Status, l.Name, want)
			}
		}
		if got := r.Layers[2].Reason; got != "undetermined" {
			t.Errorf("%s: L2 gives the reason %q", c.file, got)
		}
		yes, no, fixes := 0, 0, 0
		for _, s := range r.Layers[5].Stores {
			switch s.Trust {
			case TrustYes:
				yes++
			case TrustNo:
				no++
			}
			if s.Command != "" {
				fixes++
			}
		}
		if yes != c.yes || no != c.no || fixes != c.fixes {
			t.Errorf("%s: %d stores trust, %d do not, %d carry a command - want %d, %d, %d", c.file, yes, no, fixes, c.yes, c.no, c.fixes)
		}
		// A finding that carries a trust store is a row of the matrix and not
		// also a finding, so the one finding of L5 left is the one that names
		// who signed the certificate.
		if n := len(r.Layers[5].Findings); n != 1 {
			t.Errorf("%s: L5 keeps %d findings besides its stores, want 1", c.file, n)
		}
	}
}

// TestAStoreKeepsAllThreeAnswers holds the answer of a store to three states:
// a store that was not assessed is not a store that said no.
func TestAStoreKeepsAllThreeAnswers(t *testing.T) {
	r, err := Decode([]byte(`{"layers":[{"id":"L5","findings":[
		{"kind":"trust_store","trust_store":{"runtime":"a","trusts_presented_chain":true}},
		{"kind":"trust_store","trust_store":{"runtime":"b","trusts_presented_chain":false}},
		{"kind":"trust_store","trust_store":{"runtime":"c","trusts_presented_chain":null}}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	stores := r.Layers[0].Stores
	if len(stores) != 3 || stores[0].Trust != TrustYes || stores[1].Trust != TrustNo || stores[2].Trust != TrustNotAssessed {
		t.Fatalf("read %+v", stores)
	}
}

// TestAFixCarriesWhatTheCommandNeeds reads every part of a command the matrix
// shows beside it.
func TestAFixCarriesWhatTheCommandNeeds(t *testing.T) {
	r, err := Decode([]byte(`{"layers":[{"id":"L5","reason":null,"findings":[
		{"kind":"trust_store","trust_store":{"runtime":"java","instance":"x","trust_anchor_count":7,
		"selected_by":["JAVA_HOME"],"fix":{"command":"keytool","requires_elevation":true,
		"elevation":"administrator","caveat":"in cmd.exe"}}}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	s := r.Layers[0].Stores[0]
	if s.Command != "keytool" || !s.NeedsAdmin || s.Elevation != "administrator" || s.Caveat != "in cmd.exe" ||
		s.Anchors != 7 || len(s.ChosenBy) != 1 || r.Layers[0].Reason != "" {
		t.Fatalf("read %+v", s)
	}
}

// TestADocumentThatIsNotJSONIsRefused is the one judgement this reader makes.
func TestADocumentThatIsNotJSONIsRefused(t *testing.T) {
	for _, b := range []string{"", "certdoctor: not a URL", `{"layers":`} {
		if _, err := Decode([]byte(b)); err == nil {
			t.Errorf("%q was read as a report", b)
		}
	}
}

// TestTheStatusesAreTheReportsOwn - the four values are the vocabulary's, not
// a copy of it.
func TestTheStatusesAreTheReportsOwn(t *testing.T) {
	for _, s := range []Status{Pass, Warn, Fail, Unknown} {
		if !s.Valid() {
			t.Errorf("%q is not a status of the report", s)
		}
	}
}

func read(t *testing.T, name string) Report {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	r, err := Decode(b)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return r
}
