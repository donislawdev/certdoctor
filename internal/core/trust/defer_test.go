package trust

import (
	"context"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// The rows below are the shapes ADR108 part 4 settles, measured on the owner's
// machine with probe S25 on 2026-10-20: curl on Schannel judges by this
// account's Root store, and refuses a leaf that names no revocation address
// whatever that store says.

// platformRow is the system-store row for one Windows store.
func platformRow(instance string, trusts *bool) report.TrustStore {
	store := report.TrustStore{
		Runtime:              report.RuntimeSystemStore,
		Instance:             instance,
		StoreForm:            report.StoreSystem,
		TrustsPresentedChain: trusts,
		SelectedBy:           []string{},
	}
	switch {
	case trusts == nil:
		store.NotAssessed = "Windows could not build a chain for it"
	case *trusts:
		store.TrustAnchorCount = 91
	default:
		store.TrustAnchorCount = 91
		store.TrustFailure = report.UnknownAuthority
	}
	return store
}

// waitingCurl is curl on Schannel as its probe writes it: no verdict of its own,
// and the store it judges by named.
func waitingCurl() report.TrustStore {
	return report.TrustStore{
		Runtime:     "curl",
		Instance:    `C:\Windows\system32\curl.exe`,
		StoreForm:   report.StoreSystem,
		Backend:     "schannel",
		DefersTo:    &report.StoreRef{Runtime: report.RuntimeSystemStore, Instance: report.InstanceCurrentUser},
		NotAssessed: "this build uses schannel, which judges by system-store CurrentUser",
		SelectedBy:  []string{"PATH"},
	}
}

// refusingCurl is the same curl over a leaf that names no revocation address.
func refusingCurl() report.TrustStore {
	store := waitingCurl()
	store.NotAssessed = ""
	store.TrustsPresentedChain = yes(false)
	store.TrustFailure = report.NoRevocationInfo
	return store
}

// settledOne settles one curl row against whatever platform rows are given, and
// checks the result against the contract - a settled row the contract refuses
// would never reach a report.
func settledOne(t *testing.T, curl report.TrustStore, leafSignedItself bool, platform ...report.TrustStore) row {
	t.Helper()
	rows := []row{}
	for _, p := range platform {
		rows = append(rows, row{store: p})
	}
	rows = append(rows, row{store: curl})
	got := settleDeferred(rows, leafSignedItself)[len(rows)-1]
	if broken := got.finding().Breach(); broken != "" {
		t.Fatalf("the settled row breaks the contract: %s", broken)
	}
	return got
}

func TestADeferringRowTakesTheAnswerOfTheStoreItJudgesBy(t *testing.T) {
	cases := []struct {
		name     string
		platform []report.TrustStore
		trusts   *bool
		failure  report.TrustFailure
		anchors  int
		says     string
	}{
		{
			name:     "the store trusts the chain",
			platform: []report.TrustStore{platformRow(report.InstanceCurrentUser, yes(true))},
			trusts:   yes(true), anchors: 91,
			says: "trusts the presented chain (91 anchors) - it judges by system-store CurrentUser, and Schannel also checks revocation",
		},
		{
			name:     "the store refuses the chain",
			platform: []report.TrustStore{platformRow(report.InstanceCurrentUser, yes(false))},
			trusts:   yes(false), failure: report.UnknownAuthority, anchors: 91,
			says: "does NOT trust the presented chain (91 anchors) - it judges by system-store CurrentUser, which refuses it",
		},
		{
			name:     "the store could not be assessed",
			platform: []report.TrustStore{platformRow(report.InstanceCurrentUser, nil)},
			says:     "it judges by system-store CurrentUser, which could not be assessed",
		},
		{
			// The OTHER Windows store answering is no answer from this one - the
			// two engines are the two rows ADR103 keeps apart.
			name:     "only the machine's store answered",
			platform: []report.TrustStore{platformRow(report.InstanceLocalMachine, yes(true))},
			says:     "it judges by system-store CurrentUser, and this run has no answer from that store",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := settledOne(t, waitingCurl(), false, c.platform...)
			store := got.store
			switch {
			case c.trusts == nil && store.TrustsPresentedChain != nil:
				t.Fatalf("the row gave a verdict where the store gave none: %v", *store.TrustsPresentedChain)
			case c.trusts != nil && (store.TrustsPresentedChain == nil || *store.TrustsPresentedChain != *c.trusts):
				t.Fatalf("the row did not take the store's answer: %v", store.TrustsPresentedChain)
			}
			if store.TrustFailure != c.failure {
				t.Errorf("the row refuses %q, the store %q", store.TrustFailure, c.failure)
			}
			if store.TrustAnchorCount != c.anchors {
				t.Errorf("the row counts %d anchors, wanted %d", store.TrustAnchorCount, c.anchors)
			}
			if words := got.finding().Summary + store.NotAssessed; !strings.Contains(words, c.says) {
				t.Errorf("the row says %q, wanted it to say %q", words, c.says)
			}
			if store.DefersTo == nil {
				t.Error("the row stopped saying which store it judges by")
			}
		})
	}
}

// A REFUSAL OF ITS OWN IS CERTAIN, measured: the leaf names nowhere to check, so
// curl refuses it whether the store trusts the chain, cannot be asked, or is not
// in this run at all. Only a refusing store goes first.
func TestARefusalOfItsOwnSurvivesEverythingButARefusingStore(t *testing.T) {
	cases := []struct {
		name     string
		platform []report.TrustStore
		failure  report.TrustFailure
		anchors  int
		says     string
	}{
		{
			name:     "the store trusts the chain",
			platform: []report.TrustStore{platformRow(report.InstanceCurrentUser, yes(true))},
			failure:  report.NoRevocationInfo, anchors: 91,
			says: "does NOT accept the presented chain - the server's certificate names nowhere to check whether it was revoked",
		},
		{
			name:     "the store could not be assessed",
			platform: []report.TrustStore{platformRow(report.InstanceCurrentUser, nil)},
			failure:  report.NoRevocationInfo,
			says:     "curl connects with --ssl-revoke-best-effort",
		},
		{
			name:    "the store is not in this run",
			failure: report.NoRevocationInfo,
			says:    "curl connects with --ssl-revoke-best-effort",
		},
		{
			name:     "the store refuses the chain",
			platform: []report.TrustStore{platformRow(report.InstanceCurrentUser, yes(false))},
			failure:  report.UnknownAuthority, anchors: 91,
			says: "which refuses it",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := settledOne(t, refusingCurl(), false, c.platform...)
			store := got.store
			if store.TrustsPresentedChain == nil || *store.TrustsPresentedChain {
				t.Fatalf("a certain refusal turned into %v", store.TrustsPresentedChain)
			}
			if store.TrustFailure != c.failure {
				t.Errorf("the row refuses %q, wanted %q", store.TrustFailure, c.failure)
			}
			if store.TrustAnchorCount != c.anchors {
				t.Errorf("the row counts %d anchors, wanted %d", store.TrustAnchorCount, c.anchors)
			}
			if !strings.Contains(got.finding().Summary, c.says) {
				t.Errorf("the row says %q, wanted it to say %q", got.finding().Summary, c.says)
			}
		})
	}
}

// The anchor is never asked whether it was revoked - S25, a root naming no list
// let every chain under it through. A leaf that signed itself IS the anchor.
func TestALeafThatSignedItselfIsNotRefusedForWantOfARevocationAddress(t *testing.T) {
	got := settledOne(t, refusingCurl(), true, platformRow(report.InstanceCurrentUser, yes(true)))
	if got.store.TrustsPresentedChain == nil || !*got.store.TrustsPresentedChain {
		t.Fatalf("a self-signed leaf the store trusts was refused: %+v", got.store)
	}
	if got.store.TrustFailure != "" {
		t.Errorf("an accepted chain still names a refusal: %q", got.store.TrustFailure)
	}
	// And the exception is about revocation alone: a store that refuses the
	// self-signed leaf is still a refusal.
	refused := settledOne(t, refusingCurl(), true, platformRow(report.InstanceCurrentUser, yes(false)))
	if refused.store.TrustsPresentedChain == nil || *refused.store.TrustsPresentedChain {
		t.Errorf("a self-signed leaf the store refuses was accepted: %+v", refused.store)
	}
}

// AFTER THE WALK, NOT DURING IT: a row that met the store it defers to only
// later in the list still gets that store's answer.
func TestTheAnswerDoesNotDependOnWhichRowWasAskedFirst(t *testing.T) {
	rows := []row{{store: waitingCurl()}, {store: platformRow(report.InstanceCurrentUser, yes(true))}}
	got := settleDeferred(rows, false)[0]
	if got.store.TrustsPresentedChain == nil || !*got.store.TrustsPresentedChain {
		t.Errorf("a row listed before its store was left without the store's answer: %+v", got.store)
	}
	if rows[0].store.TrustsPresentedChain != nil {
		t.Error("settling wrote into the rows it was handed rather than into its own copy")
	}
}

// A runtime this program has no sentence for gets the plain one, which claims
// nothing about what it checks beyond the store.
func TestOnlyCurlOnSchannelIsSaidToCheckRevocationOnline(t *testing.T) {
	other := waitingCurl()
	other.Backend = "secure-transport"
	got := settledOne(t, other, false, platformRow(report.InstanceCurrentUser, yes(true)))
	if strings.Contains(got.finding().Summary, "revocation") {
		t.Errorf("a runtime nothing was measured about is said to check revocation: %q", got.finding().Summary)
	}
}

// THROUGH THE LAYER, on the shape the owner's machine produces: two platform rows
// and two curl binaries on Schannel. Before ADR108 part 4 this was a WARN on
// every ordinary run, for two rows that could not be assessed.
func TestCurlOnSchannelNoLongerTurnsAnOrdinaryWindowsRunIntoAWarning(t *testing.T) {
	secondCurl := waitingCurl()
	secondCurl.Instance = `C:\Program Files\Git\mingw64\bin\curl.exe`
	in := full()
	in.Probes = map[string]Probe{
		report.RuntimeSystemStore: func(context.Context, [][]byte) ([]report.TrustStore, error) {
			return []report.TrustStore{
				platformRow(report.InstanceCurrentUser, yes(true)),
				platformRow(report.InstanceLocalMachine, yes(true)),
			}, nil
		},
		"curl": func(context.Context, [][]byte) ([]report.TrustStore, error) {
			return []report.TrustStore{waitingCurl(), secondCurl}, nil
		},
	}
	got := Ask(context.Background(), in)
	if got.Status != status.Pass {
		t.Fatalf("an ordinary Windows run graded %s: %s", got.Status, got.Detail)
	}
	for _, f := range got.Findings {
		if f.Kind != report.FindingSigningAuthority {
			continue
		}
		// TWO STORES, NOT FOUR: the curl rows are this account's store again.
		if held := f.SigningAuthority.TrustingStores; len(held) != 2 {
			t.Errorf("the signer is said to be held by %v, and curl judges by a store already counted", held)
		}
	}
}

// L4's word on the leaf reaches the settling through the layer, rather than
// only through the function the test above calls directly.
func TestTheLayerHandsOnWhetherTheLeafSignedItself(t *testing.T) {
	in := full()
	in.PresentedLeaf = func() *report.Certificate {
		self := aLeaf()
		self.Issuer = self.Subject
		self.SelfSigned = true
		return self
	}
	in.Probes = map[string]Probe{
		report.RuntimeSystemStore: func(context.Context, [][]byte) ([]report.TrustStore, error) {
			return []report.TrustStore{platformRow(report.InstanceCurrentUser, yes(true))}, nil
		},
		"curl": func(context.Context, [][]byte) ([]report.TrustStore, error) {
			return []report.TrustStore{refusingCurl()}, nil
		},
	}
	if got := Ask(context.Background(), in); got.Status != status.Pass {
		t.Errorf("a self-signed leaf this account trusts failed the layer: %s %s", got.Status, got.Detail)
	}
}

// A deferring row is named as the store it judges by, so the store is spelled
// one way in the signer line whichever of its rows came first.
func TestADeferringRowIsNamedAsTheStoreItJudgesBy(t *testing.T) {
	curl := waitingCurl()
	curl.NotAssessed = ""
	curl.TrustsPresentedChain = yes(true)
	curl.TrustAnchorCount = 91
	trusting, _ := sides([]report.TrustStore{curl, platformRow(report.InstanceCurrentUser, yes(true))})
	if len(trusting) != 1 || trusting[0] != "system-store CurrentUser" {
		t.Errorf("the store is listed as %v, want it once as system-store CurrentUser", trusting)
	}
}

// ON LINUX THE PLATFORM STORE IS A FILE AND IS COUNTED BY ITS PATH - ADR110 -
// so a row deferring to it is counted under that path too, whichever row the
// walk meets first. Measured with the binary on 2026-10-20: counted under the
// pointer, the one store was listed twice.
func TestARowDeferringToAPlatformFileIsCountedUnderThatFile(t *testing.T) {
	platform := platformRow("debian", yes(false))
	platform.StoreForm, platform.StorePath = report.StoreFile, "/etc/ssl/certs/ca-certificates.crt"
	deferring := func(runtime, instance string) report.TrustStore {
		return report.TrustStore{Runtime: runtime, Instance: instance, StoreForm: report.StoreSystem,
			DefersTo:             &report.StoreRef{Runtime: report.RuntimeSystemStore, Instance: "debian"},
			TrustsPresentedChain: yes(false), TrustFailure: report.UnknownAuthority, TrustAnchorCount: 91,
			SelectedBy: []string{"PATH"}}
	}
	_, refusing := sides([]report.TrustStore{deferring("git", "/usr/bin/git"), platform, deferring("curl", "/usr/bin/curl")})
	if len(refusing) != 1 || refusing[0] != "system-store debian" {
		t.Errorf("the store is listed as %v, want it once as system-store debian", refusing)
	}

	// A row naming that file itself is the same store as well - the rule the
	// platform store's own row relied on from ADR104.
	named := report.TrustStore{Runtime: "curl", Instance: "/opt/curl/bin/curl", StoreForm: report.StoreFile,
		StorePath: platform.StorePath, TrustsPresentedChain: yes(false), TrustFailure: report.UnknownAuthority}
	_, refusing = sides([]report.TrustStore{named, deferring("git", "/usr/bin/git"), platform})
	if len(refusing) != 1 {
		t.Errorf("one file read by three rows is listed as %v", refusing)
	}

	// A pointer at a store this run has no row for is counted under the
	// pointer, so two rows pointing there are still one store.
	_, refusing = sides([]report.TrustStore{deferring("git", "/usr/bin/git"), deferring("curl", "/usr/bin/curl")})
	if len(refusing) != 1 {
		t.Errorf("two rows pointing at one missing store are listed as %v", refusing)
	}
}

// And the measured failure, through the layer: the store trusts the chain, the
// leaf names nowhere to check, and the layer fails on curl alone without the
// signer line counting curl as a store that lacks the signer.
func TestALeafWithoutARevocationAddressFailsTheLayerOnCurlAlone(t *testing.T) {
	in := full()
	in.Probes = map[string]Probe{
		report.RuntimeSystemStore: func(context.Context, [][]byte) ([]report.TrustStore, error) {
			return []report.TrustStore{platformRow(report.InstanceCurrentUser, yes(true))}, nil
		},
		"curl": func(context.Context, [][]byte) ([]report.TrustStore, error) {
			return []report.TrustStore{refusingCurl()}, nil
		},
	}
	got := Ask(context.Background(), in)
	if got.Status != status.Fail {
		t.Fatalf("a refusal curl is certain of graded %s: %s", got.Status, got.Detail)
	}
	for _, f := range got.Findings {
		if f.Kind == report.FindingSigningAuthority && len(f.SigningAuthority.RefusingStores) != 0 {
			t.Errorf("curl's refusal was counted as a store lacking the signer: %v", f.SigningAuthority.RefusingStores)
		}
	}
}
