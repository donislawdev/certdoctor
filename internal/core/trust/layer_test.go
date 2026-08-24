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
	store := report.TrustStore{
		Runtime:              runtime,
		Instance:             instance,
		StorePath:            `C:\bundle.crt`,
		StoreForm:            report.StoreFile,
		TrustAnchorCount:     anchors,
		TrustsPresentedChain: trusts,
		NotAssessed:          why,
		SelectedBy:           []string{},
	}
	// A refusal has to say which way, and the fixture obeys the contract rather
	// than working around it - the same call the anchor count above got.
	if trusts != nil && !*trusts {
		store.TrustFailure = report.UnknownAuthority
	}
	return store
}

func chain() [][]byte { return [][]byte{{0x30, 0x01}} }

func whole() bool { return true }

// aLeaf is what L4 renders for the certificate the chain starts with. The issuer
// and the fingerprint are the two fields the signing authority row is built out
// of, and the contract refuses a row missing either.
func aLeaf() *report.Certificate {
	return &report.Certificate{
		Subject:           "CN=partner.test",
		Issuer:            "CN=an authority",
		FingerprintSHA256: "aa:bb:cc",
		DNSNames:          []string{"partner.test"},
	}
}

func leaf() *report.Certificate { return aLeaf() }

// aMachine is the little a remediation needs to know, with a home directory the
// bundle above is NOT inside - so a command comes out needing elevation, which
// is the ordinary case for a shared store.
func aMachine() Machine { return Machine{OS: "windows", Home: `C:\Users\jdoe`} }

// probesOf builds an Input whose only probe is for the one declared descriptor.
func probesOf(p Probe) Input {
	in := full()
	in.Probes = map[string]Probe{descriptors[0].ID: p}
	return in
}

// full is an Input with every port wired, so a test that removes ONE of them is
// testing that one rather than whichever happens to be checked first.
func full() Input {
	return Input{
		PresentedChain: chain,
		ChainComplete:  whole,
		PresentedLeaf:  leaf,
		Machine:        aMachine(),
		Probes:         map[string]Probe{"git": nil},
	}
}

func TestAMissingPortIsOurDefectAndSaysSo(t *testing.T) {
	cases := []struct {
		name   string
		remove func(*Input)
		says   string
	}{
		{"no chain port", func(in *Input) { in.PresentedChain = nil }, noChain},
		{"no completeness port", func(in *Input) { in.ChainComplete = nil }, noWhole},
		{"no leaf port", func(in *Input) { in.PresentedLeaf = nil }, noLeaf},
		{"no platform", func(in *Input) { in.Machine.OS = "" }, noOS},
		{"no probes", func(in *Input) { in.Probes = nil }, noProbes},
	}
	// THE POSITIVE TWIN, AND IT IS HERE BECAUSE OF OBS56. Every case below asserts
	// that a missing port is refused, and a breach check that refused every input
	// would satisfy all of them. This asserts the complete Input is ACCEPTED, so
	// the day one of these ports stops being optional-to-omit rather than
	// required, something goes red.
	t.Run("every port wired", func(t *testing.T) {
		if broken := full().breach(); broken != "" {
			t.Errorf("an input with every port wired was refused: %q", broken)
		}
	})

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := full()
			c.remove(&in)
			got := Ask(context.Background(), in)
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
	in := full()
	in.PresentedChain = func() [][]byte { return nil }
	got := Ask(context.Background(), in)
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
			// COUNTED BY KIND RATHER THAN BY LENGTH, because this layer now
			// emits one row that is not a store: the signing authority summary.
			// Counting the slice would make this assertion quietly become "one
			// store more than there are", which is an assertion about nothing.
			rows := 0
			for _, f := range got.Findings {
				if f.Kind == report.FindingTrustStore {
					rows++
				}
			}
			if rows != len(c.stores) {
				t.Errorf("%d stores went in and %d rows came out", len(c.stores), rows)
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

// TestTheMatrixIsSummarisedByOneRowSayingWhoSigned is the seam between the walk
// and the one place allowed to judge what the walk found.
//
// IT ASSERTS THE POSITION AS WELL AS THE PRESENCE. The summary is what makes the
// rows underneath it mean anything - who signed this, and how much of this
// machine has heard of them - so a reader meets it first or meets nine rows with
// nothing to hang them on.
func TestTheMatrixIsSummarisedByOneRowSayingWhoSigned(t *testing.T) {
	no, yesTrusts := false, true
	stores := []report.TrustStore{
		aStore("git", "/usr/bin/git", &yesTrusts, ""),
		aStore("curl", "/usr/bin/curl", &no, ""),
	}
	// Two rows over one path would be one opinion, so the fixture gives them
	// different files - which is what two runtimes with their own bundles are.
	stores[1].StorePath = `C:\other.crt`

	got := Ask(context.Background(), probesOf(func(context.Context, [][]byte) ([]report.TrustStore, error) {
		return stores, nil
	}))

	if len(got.Findings) == 0 {
		t.Fatal("no findings at all")
	}
	first := got.Findings[0]
	if first.Kind != report.FindingSigningAuthority {
		t.Fatalf("the first row is %q, and the summary of the matrix has to come before the matrix", first.Kind)
	}
	if first.SigningAuthority.HeldBy != report.HeldBySomeStores {
		t.Errorf("one store holds the signer and one does not, and the row says %q", first.SigningAuthority.HeldBy)
	}
	summaries := 0
	for _, finding := range got.Findings {
		if finding.Kind == report.FindingSigningAuthority {
			summaries++
		}
	}
	if summaries != 1 {
		t.Errorf("%d summary rows, and the question is about the machine so there is one", summaries)
	}
}

// TestTheCommandArrivesAfterTheWholeMatrixHasBeenWalked is ADR55 through the
// layer rather than through the generator, because the fact it needs - whether
// ANY store closed this chain - is not known until the last probe has answered.
//
// THE ORDER IS THE TEST. The refusing store is asked FIRST, so a layer attaching
// commands as it walks cannot know yet that the store after it will close the
// chain - and would answer "no command" for the row that has one.
func TestTheCommandArrivesAfterTheWholeMatrixHasBeenWalked(t *testing.T) {
	no, yesTrusts := false, true
	refused := aStore("curl", "/usr/bin/curl", &no, "")
	closed := aStore("git", "/usr/bin/git", &yesTrusts, "")
	closed.StorePath = `C:\other.crt`

	in := probesOf(func(context.Context, [][]byte) ([]report.TrustStore, error) {
		return []report.TrustStore{refused, closed}, nil
	})
	// The server did NOT send the issuer of its leaf, which is the state the
	// first arm of the gate refuses on its own.
	in.ChainComplete = func() bool { return false }

	got := Ask(context.Background(), in)
	var command *report.Fix
	for _, finding := range got.Findings {
		if finding.Kind == report.FindingTrustStore && finding.TrustStore.Runtime == "curl" {
			command = finding.TrustStore.Fix
		}
	}
	if command == nil {
		t.Error("no command for a store that refused a chain another store on this machine closed - " +
			"the measured middlebox case, where adding the certificate IS the repair")
	}

	// THE POSITIVE TWIN IS THE NEGATIVE ONE HERE: with nothing closing the
	// chain, the same incomplete chain must still produce no command at all.
	in = probesOf(func(context.Context, [][]byte) ([]report.TrustStore, error) {
		return []report.TrustStore{refused}, nil
	})
	in.ChainComplete = func() bool { return false }
	for _, finding := range Ask(context.Background(), in).Findings {
		if finding.Kind == report.FindingTrustStore && finding.TrustStore.Fix != nil {
			t.Errorf("a command was offered where nothing on this machine closed the chain: %q",
				finding.TrustStore.Fix.Command)
		}
	}
}
