package report

import (
	"strings"
	"testing"
)

// The prohibitions of the trust store body, one case each.
//
// THE ONE THIS FILE EXISTS FOR IS THE THIRD STATE. "This store does not trust
// the chain" and "this store could not be read" send a person to two different
// places - the first to their administrator, the second to a file permission -
// and a body that lets them collapse into one boolean would make L5 lie in the
// most expensive direction available to it. Both halves are checked, because a
// rule enforced in one direction can be satisfied by a function that refuses
// everything.

func trusts(v bool) *bool { return &v }

// aReadableStore is the shape measured on the owner's machine 2026-08-18 - one
// of the six Java stores, with the path read off the machine rather than
// templated.
func aReadableStore() TrustStore {
	return TrustStore{
		Runtime:              "java",
		Instance:             "jdk-25",
		Variant:              "jdk",
		Architecture:         "x64",
		StorePath:            `C:\Program Files\OpenJDK\jdk-25\lib\security\cacerts`,
		StoreForm:            StoreFile,
		TrustAnchorCount:     158,
		TrustsPresentedChain: trusts(true),
		SelectedBy:           []string{"JAVA_HOME"},
	}
}

func TestAWellFormedTrustStoreIsAccepted(t *testing.T) {
	store := aReadableStore()
	if got := store.breach(); got != "" {
		t.Errorf("a well formed store was refused: %q", got)
	}
}

// A store nothing selects is ORDINARY, not broken. Five of the six Java stores
// measured on this machine are in exactly this position, and refusing them
// would drop most of the matrix.
func TestAStoreSelectedByNothingIsAccepted(t *testing.T) {
	store := aReadableStore()
	store.SelectedBy = []string{}
	if got := store.breach(); got != "" {
		t.Errorf("a store nothing selects was refused: %q", got)
	}
}

// The system store has no path to hand out, and that is the whole reason
// StoreForm exists rather than being inferred from an empty path.
func TestTheSystemStoreNeedsNoPath(t *testing.T) {
	store := aReadableStore()
	store.StoreForm = StoreSystem
	store.StorePath = ""
	if got := store.breach(); got != "" {
		t.Errorf("the system store was refused for having no path: %q", got)
	}
}

// A runtime without variants leaves the field empty, and curl is one.
func TestARuntimeWithNoVariantIsAccepted(t *testing.T) {
	store := aReadableStore()
	store.Runtime = "curl"
	store.Instance = `C:\Windows\system32\curl.exe`
	store.Variant = ""
	store.Backend = "schannel"
	store.StoreForm = StoreSystem
	store.StorePath = ""
	if got := store.breach(); got != "" {
		t.Errorf("a runtime with no variant was refused: %q", got)
	}
}

// A store that could not be read carries a reason and NO verdict. This is the
// UNKNOWN of docs/20 - failing to open a keystore with the default password is
// never a fact about trust.
func TestAnUnreadableStoreCarriesAReasonAndNoVerdict(t *testing.T) {
	store := aReadableStore()
	store.TrustsPresentedChain = nil
	store.NotAssessed = "the keystore did not open with the default password"
	store.TrustAnchorCount = 0
	if got := store.breach(); got != "" {
		t.Errorf("an honestly unassessed store was refused: %q", got)
	}
}

// A store that does NOT trust the chain is a verdict, not a failure, and it is
// the answer the whole matrix exists to produce.
func TestDistrustIsAVerdictAndNotAFailure(t *testing.T) {
	store := aReadableStore()
	store.TrustsPresentedChain = trusts(false)
	if got := store.breach(); got != "" {
		t.Errorf("a store that distrusts the chain was refused: %q", got)
	}
}

func TestTheTrustStoreRefusesWhatItMustRefuse(t *testing.T) {
	cases := []struct {
		name  string
		spoil func(*TrustStore)
		says  string
	}{
		{
			name:  "no runtime",
			spoil: func(s *TrustStore) { s.Runtime = "" },
			says:  "runtime",
		},
		{
			name:  "no instance",
			spoil: func(s *TrustStore) { s.Instance = "" },
			says:  "instance",
		},
		{
			name:  "a store form outside the registry",
			spoil: func(s *TrustStore) { s.StoreForm = StoreForm("registry") },
			says:  "outside the registry",
		},
		{
			name:  "a file store with no path",
			spoil: func(s *TrustStore) { s.StorePath = "" },
			says:  "path",
		},
		{
			name:  "a negative anchor count",
			spoil: func(s *TrustStore) { s.TrustAnchorCount = -1 },
			says:  "not a count",
		},
		{
			// nil is a statement about US - that nobody looked - wearing the
			// clothes of a statement about the machine.
			name:  "a nil selection list",
			spoil: func(s *TrustStore) { s.SelectedBy = nil },
			says:  "empty one is the answer",
		},
		{
			name: "no verdict and no reason",
			spoil: func(s *TrustStore) {
				s.TrustsPresentedChain = nil
				s.NotAssessed = ""
			},
			says: "silence about a failure is forbidden",
		},
		{
			name:  "a verdict and a reason at once",
			spoil: func(s *TrustStore) { s.NotAssessed = "the keystore did not open" },
			says:  "also says why it could not",
		},
		{
			name: "anchors counted in a store that was never read",
			spoil: func(s *TrustStore) {
				s.TrustsPresentedChain = nil
				s.NotAssessed = "the keystore did not open"
			},
			says: "still counts anchors",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store := aReadableStore()
			c.spoil(&store)
			got := store.breach()
			if got == "" {
				t.Fatalf("%s was accepted", c.name)
			}
			if !strings.Contains(got, c.says) {
				t.Errorf("the refusal does not name what it defends: %q, wanted it to mention %q", got, c.says)
			}
		})
	}
}

// The registry of store forms, checked the same way every other closed list in
// this package is: a value outside it is a defect in our translation, not news.
func TestEveryStoreFormHasAMeaning(t *testing.T) {
	for _, form := range []StoreForm{StoreFile, StoreSystem} {
		if !form.Valid() {
			t.Errorf("%q is declared and not in the registry", form)
		}
		if form.Meaning() == "" {
			t.Errorf("%q is in the registry with no meaning", form)
		}
		if form.String() != string(form) {
			t.Errorf("%q does not print as itself", form)
		}
	}
	if StoreForm("keychain").Valid() {
		t.Error("an undeclared store form was accepted")
	}
}

// The envelope has to route a trust store finding to the body that checks it.
// Without this the body above could be perfect and never consulted.
func TestAFindingRoutesToTheTrustStoreBody(t *testing.T) {
	store := aReadableStore()
	store.Runtime = ""

	f := Finding{
		Kind:       FindingTrustStore,
		Summary:    "one store",
		Source:     SourceDetected,
		TrustStore: &store,
	}
	got := f.Breach()
	if got == "" {
		t.Fatal("a finding carrying a broken trust store was accepted")
	}
	if !strings.Contains(got, "runtime") {
		t.Errorf("the finding did not report the body's own complaint: %q", got)
	}
}
