package trust

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

func yes(v bool) *bool { return &v }

// A store that could not be read counts NO anchors - the contract refuses a row
// that counts what nothing could have counted, and this fixture obeys it rather
// than working around it.
func aStore(runtime, instance string, trusts *bool, why string) report.TrustStore {
	anchors := 150
	if trusts == nil {
		anchors = 0
	}
	return report.TrustStore{
		Runtime:              runtime,
		Instance:             instance,
		StorePath:            `C:\bundle.crt`,
		StoreForm:            report.StoreFile,
		TrustAnchorCount:     anchors,
		TrustsPresentedChain: trusts,
		NotAssessed:          why,
		SelectedBy:           []string{},
	}
}

func chain() [][]byte { return [][]byte{{0x30, 0x01}} }

// probesOf builds an Input whose only probe is for the one declared descriptor.
func probesOf(p Probe) Input {
	return Input{PresentedChain: chain, Probes: map[string]Probe{descriptors[0].ID: p}}
}

func TestAMissingPortIsOurDefectAndSaysSo(t *testing.T) {
	cases := []struct {
		name string
		in   Input
		says string
	}{
		{"no chain port", Input{Probes: map[string]Probe{"git": nil}}, noChain},
		{"no probes", Input{PresentedChain: chain}, noProbes},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Ask(context.Background(), c.in)
			if got.Status != status.Unknown {
				t.Errorf("a missing port graded %s, and our own omission is never a fact about a machine", got.Status)
			}
			if got.Detail != c.says {
				t.Errorf("detail %q, want %q", got.Detail, c.says)
			}
			if got.Findings != nil {
				t.Error("a layer that could not look reported a list of findings")
			}
		})
	}
}

// An empty chain means L4 established nothing. That is not a store failing, and
// reporting it as one would accuse every runtime on the machine.
func TestNoPresentedChainIsNothingToJudge(t *testing.T) {
	got := Ask(context.Background(), Input{
		PresentedChain: func() [][]byte { return nil },
		Probes:         map[string]Probe{"git": nil},
	})
	if got.Status != status.Unknown || got.Reason != status.ReasonNothingToCheck {
		t.Errorf("got %s / %s, want UNKNOWN / nothing_to_check", got.Status, got.Reason)
	}
	if !strings.Contains(got.Detail, "nothing for any store") {
		t.Errorf("detail does not say why: %q", got.Detail)
	}
}

// A runtime that is not installed sits OUTSIDE the matrix - docs/20 rule 1.
// Zero instances is a legitimate answer and never a failure.
func TestAProbeFindingNothingIsNotAFailure(t *testing.T) {
	got := Ask(context.Background(), probesOf(func(context.Context, [][]byte) ([]report.TrustStore, error) {
		return nil, nil
	}))
	if got.Status != status.Unknown || got.Reason != status.ReasonNothingToCheck {
		t.Errorf("got %s / %s, want UNKNOWN / nothing_to_check", got.Status, got.Reason)
	}
	if got.Detail != noneHere {
		t.Errorf("detail %q, want %q", got.Detail, noneHere)
	}
}

func TestOneProbeFailingDoesNotSinkTheLayer(t *testing.T) {
	got := Ask(context.Background(), probesOf(func(context.Context, [][]byte) ([]report.TrustStore, error) {
		return nil, errors.New("the config could not be read")
	}))
	if got.Status != status.Unknown {
		t.Errorf("got %s, want UNKNOWN - being unable to ask is not a verdict", got.Status)
	}
	if len(got.Findings) != 1 {
		t.Fatalf("a probe that failed produced %d rows, and silence about it is forbidden", len(got.Findings))
	}
	body := got.Findings[0].TrustStore
	if body.TrustsPresentedChain != nil {
		t.Error("a probe that could not run still produced a verdict")
	}
	if !strings.Contains(body.NotAssessed, "could not read") && !strings.Contains(body.NotAssessed, "could not run") {
		t.Errorf("the row does not say why: %q", body.NotAssessed)
	}
	if body.SelectedBy == nil {
		t.Error("the row carries a nil selection list, which reads as a statement about us")
	}
	if breach := got.Findings[0].Breach(); breach != "" {
		t.Errorf("the layer produced a finding its own contract refuses: %s", breach)
	}
}

func TestTheVerdictCountsStoresRatherThanRuntimes(t *testing.T) {
	cases := []struct {
		name   string
		stores []report.TrustStore
		want   status.Status
		says   string
	}{
		{
			name:   "every store trusts it",
			stores: []report.TrustStore{aStore("git", "a", yes(true), ""), aStore("git", "b", yes(true), "")},
			want:   status.Pass,
			says:   "all 2 store(s)",
		},
		{
			// THE CASE THE WHOLE MATRIX EXISTS FOR: one instance trusts it and
			// another does not, on one machine.
			name:   "one of two does not",
			stores: []report.TrustStore{aStore("git", "a", yes(true), ""), aStore("git", "b", yes(false), "")},
			want:   status.Fail,
			says:   "1 of 2 store(s) do not trust",
		},
		{
			name:   "some trust it and one could not be read",
			stores: []report.TrustStore{aStore("git", "a", yes(true), ""), aStore("git", "b", nil, "no permission")},
			want:   status.Warn,
			says:   "could not be assessed",
		},
		{
			// Inviolable rule 15: unreadable is never FAIL.
			name:   "none could be read",
			stores: []report.TrustStore{aStore("git", "a", nil, "no permission")},
			want:   status.Unknown,
			says:   "none of the 1 store(s)",
		},
		{
			// D10: both numbers travel when both exist.
			name:   "distrust and unknown together",
			stores: []report.TrustStore{aStore("git", "a", yes(false), ""), aStore("git", "b", nil, "no permission")},
			want:   status.Fail,
			says:   "and 1 could not be assessed",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stores := c.stores
			got := Ask(context.Background(), probesOf(func(context.Context, [][]byte) ([]report.TrustStore, error) {
				return stores, nil
			}))
			if got.Status != c.want {
				t.Errorf("graded %s, want %s - detail was %q", got.Status, c.want, got.Detail)
			}
			if !strings.Contains(got.Detail, c.says) {
				t.Errorf("detail %q does not mention %q", got.Detail, c.says)
			}
			if len(got.Findings) != len(c.stores) {
				t.Errorf("%d stores went in and %d rows came out", len(c.stores), len(got.Findings))
			}
			for _, f := range got.Findings {
				if breach := f.Breach(); breach != "" {
					t.Errorf("the layer produced a finding its own contract refuses: %s", breach)
				}
			}
		})
	}
}

// The summary is what a surface prints without knowing the kind, so all three
// states have to read as sentences rather than as a struct dump.
func TestTheSummarySaysWhichOfTheThreeStatesThisIs(t *testing.T) {
	cases := []struct {
		store report.TrustStore
		says  string
	}{
		{aStore("git", "a", yes(true), ""), "trusts the presented chain"},
		{aStore("git", "a", yes(false), ""), "does NOT trust"},
		{aStore("git", "a", nil, "no permission"), "could not be assessed"},
	}
	for _, c := range cases {
		got := summaryOf(c.store)
		if !strings.Contains(got, c.says) {
			t.Errorf("summary %q does not contain %q", got, c.says)
		}
	}
}
