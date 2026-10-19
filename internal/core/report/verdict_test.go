package report

import (
	"fmt"
	"strings"
	"testing"

	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	"github.com/donislawdev/certdoctor/internal/core/layer"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// TestTheVerdictNamesBothFailuresAndLayersItCouldNotAssess covers the sentence
// that used to tell half the truth.
//
// A run with failures AND layers it could not look at reported only the
// failures. Every word of it was true and the omission was the expensive part:
// a reader fixes the two named layers, comes back, and finds three more that
// were never assessed at all. The exit code says DIAGNOSIS either way, so
// nothing else in the report carries this.
func TestTheVerdictNamesBothFailuresAndLayersItCouldNotAssess(t *testing.T) {
	results := []LayerResult{
		{ID: layer.Context, Status: status.Fail, Reason: status.ReasonUnparseable, Detail: "x"},
		{ID: layer.Resolution, Status: status.Fail, Reason: status.ReasonUnparseable, Detail: "x"},
		{ID: layer.Proxy, Status: status.Unknown, Reason: status.ReasonTimeout, Detail: "x"},
		{ID: layer.TCP, Status: status.Unknown, Reason: status.ReasonTimeout, Detail: "x"},
		{ID: layer.TLS, Status: status.Unknown, Reason: status.ReasonTimeout, Detail: "x"},
		{ID: layer.TrustMatrix, Status: status.Pass},
		{ID: layer.Containers, Status: status.Pass},
		{ID: layer.Report, Status: status.Pass},
	}

	got := Assess(results).Sentence
	for _, want := range []string{"Failures in 2 of 8", "3 of 8 diagnostic layers could not be assessed"} {
		if !strings.Contains(got, want) {
			t.Errorf("the verdict leaves out %q: %q", want, got)
		}
	}
}

// storeTrusting and storeRefusing build the two kinds of trust-matrix row the verdict reads.
func storeTrusting(runtime string) Finding {
	yes := true
	return Finding{Kind: FindingTrustStore, TrustStore: &TrustStore{Runtime: runtime, TrustsPresentedChain: &yes}}
}

func storeRefusing(runtime string, why TrustFailure) Finding {
	no := false
	return Finding{Kind: FindingTrustStore, TrustStore: &TrustStore{Runtime: runtime, TrustsPresentedChain: &no, TrustFailure: why}}
}

// storeUndetermined is a row that could not judge the chain, carrying the
// summary the trust layer writes for one.
func storeUndetermined(runtime, instance, why string) Finding {
	return Finding{Kind: FindingTrustStore, Summary: runtime + " " + instance + " could not be assessed: " + why,
		TrustStore: &TrustStore{Runtime: runtime, Instance: instance, NotAssessed: why}}
}

// summarised gives a row the one line a surface prints for it.
func summarised(f Finding, summary string) Finding {
	f.Summary = summary
	return f
}

func signer(summary string, held AnchorHolding) Finding {
	return Finding{Kind: FindingSigningAuthority, Summary: summary, SigningAuthority: &SigningAuthority{Issuer: "x", HeldBy: held}}
}

// inspected is a signer whose name matched the list of inspection products.
func inspected(summary string, held AnchorHolding) Finding {
	f := signer(summary, held)
	f.SigningAuthority.Inspection = &Inspection{Product: "mitmproxy", MatchedAttribute: "CN"}
	return f
}

// row is a layer result with the detail its layer would have written.
func row(id layer.ID, s status.Status, detail string, findings ...Finding) LayerResult {
	r := LayerResult{ID: id, Status: s, Detail: detail, Findings: findings}
	if s == status.Unknown {
		r.Reason = status.ReasonNothingToCheck
	}
	return r
}

const (
	l4Incomplete    = "the server presented 1 certificate(s) and did not send the issuer of the first one, so nothing can build a path to a root - this is a fact about the server rather than about this machine"
	l5TwoRefuse     = "2 of 3 store(s) do not trust the presented chain"
	middlebox       = "mitmproxy signed this certificate and is an authority local to this machine - 1 store(s) here hold it and 1 do not - and that issuer names mitmproxy, a TLS inspection product, so this connection is being intercepted and re-signed between here and the server"
	nobodyHolds     = "certdoctor testbed intermediate signed this certificate, and no store on this machine holds an anchor for it"
	unheldMiddlebox = "mitmproxy signed this certificate, and no store on this machine holds an anchor for it - and that issuer names mitmproxy, a TLS inspection product, so this connection is being intercepted and re-signed between here and the server"
	wantsCreds      = "the proxy this URL goes through demands credentials before it will pass a request, and this run offered none - so whether this URL can be reached through it was not established"
	noBundle        = "there is no CA bundle at any of the places Go and the common distributions keep one, so this platform has no store to judge the chain with - on Debian and Ubuntu the ca-certificates package is what installs it"
	notFetched      = "the issuer this chain needs is on this machine's copy of Microsoft's root program list and is not installed yet - Windows fetches such a root when it first needs one and this program does not, so whether this store would trust the chain is undetermined"
	onSchannel      = "this build uses schannel, which reads the platform store rather than a file - the system-store probe answers for it"
)

// TestTheVerdictNamesTheCauseInTheDecisiveLayersWords is the product's promise
// after the arithmetic: the top line says WHAT is wrong, in the words of the
// layer that established it, and keeps the counts behind it.
//
// The cases are the bench scenarios of docs/21 written as rows. The two that
// matter most are the pair measured on 2026-08-19: a middlebox and a server
// that forgot its intermediate fail L4 identically, and only the trust matrix
// tells them apart - so the middlebox verdict must come from L5 even though L4
// is the earlier red row, and the forgetful server's verdict must blame the
// server even though every trust row under it is red.
func TestTheVerdictNamesTheCauseInTheDecisiveLayersWords(t *testing.T) {
	for _, c := range causeScenarios {
		t.Run(c.name, func(t *testing.T) {
			if got := Assess(c.rows).Sentence; got != c.want {
				t.Errorf("\n got %q\nwant %q", got, c.want)
			}
		})
	}
}

func pass(id layer.ID) LayerResult                { return row(id, status.Pass, "") }
func skipped(id layer.ID, why string) LayerResult { return row(id, status.Unknown, why) }

// unbuilt is the pair of layers this build does not implement, present in every
// real report and so in every scenario here.
var unbuilt = []LayerResult{skipped(layer.Containers, "not implemented"), skipped(layer.Report, "not implemented")}

// causeScenarios are the bench scenarios of docs/21 written as rows, with the
// sentence each must produce at the top of the report.
var causeScenarios = []struct {
	name string
	rows []LayerResult
	want string
}{
	{
		name: "S-4 or a name that does not resolve: L1 is the cause of everything under it",
		rows: append([]LayerResult{pass(layer.Context),
			row(layer.Resolution, status.Fail, "neither view found an address for this name, and at least one of them said so"),
			skipped(layer.Proxy, "x"), skipped(layer.TCP, "nothing to connect to"), skipped(layer.TLS, "x"), skipped(layer.TrustMatrix, "x")}, unbuilt...),
		want: "Neither view found an address for this name, and at least one of them said so. 6 of 8 diagnostic layers could not be assessed.",
	},
	{
		name: "no address accepts a connection: L3 is the cause and L4/L5 are consequences",
		rows: append([]LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy),
			row(layer.TCP, status.Fail, "none of the 2 address(es) this name resolved to accepted a connection"),
			skipped(layer.TLS, "x"), skipped(layer.TrustMatrix, "x")}, unbuilt...),
		want: "None of the 2 address(es) this name resolved to accepted a connection. 4 of 8 diagnostic layers could not be assessed.",
	},
	{
		name: "S-5 the server forgot its intermediate: every trust row is red and the server is still to blame",
		rows: append([]LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP),
			row(layer.TLS, status.Fail, l4Incomplete),
			row(layer.TrustMatrix, status.Fail, l5TwoRefuse, signer(nobodyHolds, HeldByNoStores),
				storeRefusing("curl", UnknownAuthority), storeRefusing("git", UnknownAuthority))}, unbuilt...),
		want: "The server presented 1 certificate(s) and did not send the issuer of the first one, so nothing can build a path to a root - this is a fact about the server rather than about this machine. Failures in 2 of 8 diagnostic layers. 2 of 8 diagnostic layers could not be assessed.",
	},
	{
		name: "S-1 a middlebox: L4 fails exactly as in S-5, and the local authority in L5 outranks it",
		rows: append([]LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP),
			row(layer.TLS, status.Fail, l4Incomplete),
			row(layer.TrustMatrix, status.Fail, "1 of 2 store(s) do not trust the presented chain", inspected(middlebox, HeldBySomeStores),
				storeTrusting("curl"), storeRefusing("git", UnknownAuthority))}, unbuilt...),
		want: middlebox + ". Without it: git. Failures in 2 of 8 diagnostic layers. 2 of 8 diagnostic layers could not be assessed.",
	},
	{
		name: "a middlebox nobody here trusts: L4 fails, no store holds the signer, and the named product still leads - measured on the bench 2026-09-22",
		rows: append([]LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP),
			row(layer.TLS, status.Fail, l4Incomplete),
			row(layer.TrustMatrix, status.Fail, l5TwoRefuse, inspected(unheldMiddlebox, HeldByNoStores),
				storeRefusing("curl", UnknownAuthority), storeRefusing("git", UnknownAuthority))}, unbuilt...),
		want: unheldMiddlebox + ". Failures in 2 of 8 diagnostic layers. 2 of 8 diagnostic layers could not be assessed.",
	},
	{
		name: "S-3 and S-6 an honest server under a company authority: which runtimes lack the anchor, with counts where a runtime has several stores",
		rows: append([]LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP), pass(layer.TLS),
			row(layer.TrustMatrix, status.Fail, "4 of 6 store(s) do not trust the presented chain",
				signer("Example Corp Root CA signed this certificate and is an authority local to this machine - 2 store(s) here hold it and 4 do not", HeldBySomeStores),
				storeTrusting("curl"), storeRefusing("git", UnknownAuthority), storeTrusting("java"), storeRefusing("java", UnknownAuthority), storeRefusing("java", UnknownAuthority), storeRefusing("java", UnknownAuthority))}, unbuilt...),
		want: "Example Corp Root CA signed this certificate and is an authority local to this machine - 2 store(s) here hold it and 4 do not. Without it: git, java (3 of 4). 2 of 8 diagnostic layers could not be assessed.",
	},
	{
		name: "a private root nobody here holds, chain complete: the signer is named and no runtime is listed",
		rows: append([]LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP), pass(layer.TLS),
			row(layer.TrustMatrix, status.Fail, l5TwoRefuse, signer(nobodyHolds, HeldByNoStores),
				storeRefusing("curl", UnknownAuthority), storeRefusing("git", UnknownAuthority))}, unbuilt...),
		want: nobodyHolds + ". 2 of 8 diagnostic layers could not be assessed.",
	},
	{
		name: "stores hold the anchor and still refuse, all for the same reason: the layer's count and that reason",
		rows: append([]LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP), pass(layer.TLS),
			row(layer.TrustMatrix, status.Fail, l5TwoRefuse, storeRefusing("curl", Expired), storeRefusing("git", Expired), storeTrusting("java"))}, unbuilt...),
		want: "2 of 3 store(s) do not trust the presented chain - a certificate in the path is past its validity. 2 of 8 diagnostic layers could not be assessed.",
	},
	{
		name: "stores refuse for different reasons: the layer's count and nothing invented",
		rows: append([]LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP), pass(layer.TLS),
			row(layer.TrustMatrix, status.Fail, l5TwoRefuse, storeRefusing("curl", Expired), storeRefusing("git", NotYetValid), storeTrusting("java"))}, unbuilt...),
		want: "2 of 3 store(s) do not trust the presented chain. 2 of 8 diagnostic layers could not be assessed.",
	},
	{
		name: "nothing failed but the proxy wants credentials: a passing run says so out loud",
		rows: append([]LayerResult{pass(layer.Context), pass(layer.Resolution),
			{ID: layer.Proxy, Status: status.Unknown, Reason: status.ReasonCredentialsRequired, Detail: wantsCreds},
			pass(layer.TCP), pass(layer.TLS), pass(layer.TrustMatrix)}, unbuilt...),
		want: "Everything assessed passed, but " + wantsCreds + ". 3 of 8 diagnostic layers could not be assessed.",
	},
	{
		name: "nothing failed, one warning, two layers unbuilt: the warning is no longer dropped from the top line",
		rows: append([]LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP), pass(layer.TLS),
			row(layer.TrustMatrix, status.Warn, "9 of 11 store(s) trust the presented chain, and 2 could not be assessed")}, unbuilt...),
		want: "Everything assessed passed. Warnings in 1 of 8 diagnostic layers. 2 of 8 diagnostic layers could not be assessed.",
	},
	{
		name: "OBS159 nothing failed and the platform has no store at all, measured in ubuntu:24.04: the top line says what the row says",
		rows: append([]LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP), pass(layer.TLS),
			row(layer.TrustMatrix, status.Unknown, "none of the 1 store(s) found could be assessed",
				storeUndetermined(RuntimeSystemStore, "ubuntu", noBundle))}, unbuilt...),
		want: "Everything assessed passed, but system-store ubuntu could not be assessed: " + noBundle + ". 3 of 8 diagnostic layers could not be assessed.",
	},
	{
		name: "other stores trust and one of the platform's two Windows stores is undetermined: that row is named and the warning still counted",
		rows: append([]LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP), pass(layer.TLS),
			row(layer.TrustMatrix, status.Warn, "2 of 3 store(s) trust the presented chain, and 1 could not be assessed",
				storeTrusting("git"), storeTrusting(RuntimeSystemStore), storeUndetermined(RuntimeSystemStore, "LocalMachine", notFetched))}, unbuilt...),
		want: "Everything assessed passed, but system-store LocalMachine could not be assessed: " + notFetched + ". Warnings in 1 of 8 diagnostic layers. 2 of 8 diagnostic layers could not be assessed.",
	},
	{
		name: "curl on schannel could not be assessed and the platform's row judged the chain, measured on Windows 2026-10-19: the tail counts it and nothing more is said",
		rows: append([]LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP), pass(layer.TLS),
			row(layer.TrustMatrix, status.Warn, "2 of 3 store(s) trust the presented chain, and 1 could not be assessed",
				summarised(storeTrusting(RuntimeSystemStore), "system-store CurrentUser trusts the presented chain (60 anchors)"),
				storeUndetermined("curl", "curl.exe", onSchannel), storeTrusting("git"))}, unbuilt...),
		want: "Everything assessed passed. Warnings in 1 of 8 diagnostic layers. 2 of 8 diagnostic layers could not be assessed.",
	},
	{
		name: "an undetermined platform row with no summary names nothing, so nothing is invented and the function stays total",
		rows: append([]LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP), pass(layer.TLS),
			row(layer.TrustMatrix, status.Unknown, "none of the 1 store(s) found could be assessed",
				summarised(storeUndetermined(RuntimeSystemStore, "ubuntu", noBundle), ""))}, unbuilt...),
		want: "Everything assessed passed. 3 of 8 diagnostic layers could not be assessed.",
	},
	{
		name: "the proxy wants credentials AND the platform has no store: one but, and the proxy's comes first in layer order",
		rows: append([]LayerResult{pass(layer.Context), pass(layer.Resolution),
			{ID: layer.Proxy, Status: status.Unknown, Reason: status.ReasonCredentialsRequired, Detail: wantsCreds},
			pass(layer.TCP), pass(layer.TLS),
			row(layer.TrustMatrix, status.Unknown, "none of the 1 store(s) found could be assessed",
				storeUndetermined(RuntimeSystemStore, "ubuntu", noBundle))}, unbuilt...),
		want: "Everything assessed passed, but " + wantsCreds + ". 4 of 8 diagnostic layers could not be assessed.",
	},
	{
		name: "S-5 with the platform's row undetermined: a failure outranks it and the server is still to blame",
		rows: append([]LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP),
			row(layer.TLS, status.Fail, l4Incomplete),
			row(layer.TrustMatrix, status.Fail, l5TwoRefuse, signer(nobodyHolds, HeldByNoStores),
				storeRefusing("curl", UnknownAuthority), storeRefusing("git", UnknownAuthority),
				storeUndetermined(RuntimeSystemStore, "ubuntu", noBundle))}, unbuilt...),
		want: "The server presented 1 certificate(s) and did not send the issuer of the first one, so nothing can build a path to a root - this is a fact about the server rather than about this machine. Failures in 2 of 8 diagnostic layers. 2 of 8 diagnostic layers could not be assessed.",
	},
	{
		name: "a failing row with no detail names nothing, so the count stands in and the function stays total",
		rows: append([]LayerResult{pass(layer.Context), row(layer.Resolution, status.Fail, ""), pass(layer.Proxy), pass(layer.TCP), pass(layer.TLS), pass(layer.TrustMatrix)}, unbuilt...),
		want: "Failures in 1 of 8 diagnostic layers. 2 of 8 diagnostic layers could not be assessed.",
	},
}

// TestTheDecisiveLayerIsFoundByIdentityNotByPosition: the validator hands the
// fold whatever order the report holds, so the answer must not depend on it.
func TestTheDecisiveLayerIsFoundByIdentityNotByPosition(t *testing.T) {
	rows := []LayerResult{
		row(layer.TrustMatrix, status.Fail, l5TwoRefuse, signer(nobodyHolds, HeldByNoStores), storeRefusing("git", UnknownAuthority)),
		row(layer.TLS, status.Fail, l4Incomplete),
		row(layer.TCP, status.Pass, ""),
		row(layer.Resolution, status.Fail, "neither view found an address for this name"),
	}
	want := Assess(rows).Sentence
	if !strings.HasPrefix(want, "Neither view found an address") {
		t.Fatalf("the earliest dependency is not the cause: %q", want)
	}
	reversed := []LayerResult{rows[3], rows[2], rows[1], rows[0]}
	if got := Assess(reversed).Sentence; got != want {
		t.Errorf("order changed the verdict:\n %q\n %q", want, got)
	}
}

// TestACauseNeverLosesTheCountsBehindIt walks every combination of statuses
// over rows that carry a detail, and checks that naming a cause dropped none of
// the three numbers the arithmetic sentence used to carry.
func TestACauseNeverLosesTheCountsBehindIt(t *testing.T) {
	everyCombinationUpTo(t, 3, func(statuses []status.Status) {
		rows := resultsFor(statuses)
		for i := range rows {
			rows[i].Detail = fmt.Sprintf("detail of %s", rows[i].ID)
			if rows[i].Status == status.Unknown {
				rows[i].Reason = status.ReasonTimeout
			}
		}
		sentence := Assess(rows).Sentence
		total := len(statuses)
		failures, warnings, unknowns := countOf(statuses, status.Fail), countOf(statuses, status.Warn), countOf(statuses, status.Unknown)
		if total == 0 || unknowns == total {
			return
		}
		checks := map[string]bool{}
		if failures > 0 {
			decisive := ""
			for _, id := range []layer.ID{layer.Resolution, layer.TCP, layer.TLS, layer.TrustMatrix, layer.Context, layer.Proxy, layer.Containers, layer.Report} {
				if r, ok := failing(rows, id); ok {
					decisive = r.Detail
					break
				}
			}
			checks["Detail of "+strings.TrimPrefix(decisive, "detail of ")] = true
		}
		if failures > 1 {
			checks[fmt.Sprintf("Failures in %d of %d", failures, total)] = true
		}
		if warnings > 0 {
			checks[fmt.Sprintf("Warnings in %d of %d", warnings, total)] = true
		}
		if unknowns > 0 {
			checks[fmt.Sprintf("%d of %d diagnostic layers could not be assessed", unknowns, total)] = true
		}
		for want := range checks {
			if !strings.Contains(sentence, want) {
				t.Errorf("layers %v produced %q, which leaves out %q", statuses, sentence, want)
			}
		}
		if !strings.HasSuffix(sentence, ".") || strings.Contains(sentence, "..") {
			t.Errorf("layers %v produced %q, which is not punctuated as sentences", statuses, sentence)
		}
	})
}

// TestANameKeepsItsOwnCasingAtTheTop: the sentence over a local authority
// starts with the issuer's name as the certificate spells it, and a detail that
// starts with a digit is left alone too.
func TestANameKeepsItsOwnCasingAtTheTop(t *testing.T) {
	if got, _ := sentence("2 of 3 store(s) do not trust the presented chain"); got != "2 of 3 store(s) do not trust the presented chain." {
		t.Errorf("a leading digit was touched: %q", got)
	}
	if got, _ := sentence("neither view found"); got != "Neither view found." {
		t.Errorf("a leading lower-case letter was not raised: %q", got)
	}
	// The signer's own casing at the top is pinned by the S-1 case above, which
	// starts with "mitmproxy" - the authority sentence is quoted, never raised.
	if got, _ := sentence("it ended already."); got != "It ended already." {
		t.Errorf("a detail that already ends as a sentence got a second full stop: %q", got)
	}
}

// vocabulary is every status a layer can report. The tests below walk every
// combination of it rather than a handful of examples, because the fold is a
// total function and an example test only ever proves the example.
var vocabulary = []status.Status{status.Pass, status.Warn, status.Unknown, status.Fail}

// everyCombinationUpTo calls check once for each ordered combination of
// statuses of length zero through maxLayers. Four statuses over three layers is
// eighty-five cases, which is cheap and complete.
func everyCombinationUpTo(t *testing.T, maxLayers int, check func(statuses []status.Status)) {
	t.Helper()
	for n := 0; n <= maxLayers; n++ {
		total := 1
		for i := 0; i < n; i++ {
			total *= len(vocabulary)
		}
		for c := 0; c < total; c++ {
			combination := make([]status.Status, n)
			remainder := c
			for i := 0; i < n; i++ {
				combination[i] = vocabulary[remainder%len(vocabulary)]
				remainder /= len(vocabulary)
			}
			check(combination)
		}
	}
}

// resultsFor turns a combination of statuses into layer rows.
func resultsFor(statuses []status.Status) []LayerResult {
	results := make([]LayerResult, 0, len(statuses))
	for i, s := range statuses {
		results = append(results, LayerResult{ID: layer.All[i], Status: s})
	}
	return results
}

func contains(statuses []status.Status, want status.Status) bool {
	for _, s := range statuses {
		if s == want {
			return true
		}
	}
	return false
}

// TestVerdictStatusIsTheWorstOfTheLayers is the product's main promise, checked
// over every combination rather than over chosen examples.
//
// The expected value is written out here in full rather than computed with the
// helper the implementation uses. A test that folds the statuses the same way
// the code does would agree with the code even when both are wrong.
func TestVerdictStatusIsTheWorstOfTheLayers(t *testing.T) {
	severityOrder := []status.Status{status.Fail, status.Warn, status.Unknown, status.Pass}

	everyCombinationUpTo(t, 3, func(statuses []status.Status) {
		want := status.Unknown
		if len(statuses) > 0 {
			for _, candidate := range severityOrder {
				if contains(statuses, candidate) {
					want = candidate
					break
				}
			}
		}
		if got := Assess(resultsFor(statuses)).Status; got != want {
			t.Errorf("layers %v folded to %s, want %s", statuses, got, want)
		}
	})
}

// TestExitCodeFollowsTheFrozenRule restates the mapping deliberately. It is the
// bridge between the status vocabulary and the exit code table, and both of
// those are public contracts.
func TestExitCodeFollowsTheFrozenRule(t *testing.T) {
	everyCombinationUpTo(t, 3, func(statuses []status.Status) {
		want := exitcode.OK
		switch {
		case contains(statuses, status.Fail):
			want = exitcode.Diagnosis
		case len(statuses) == 0 || contains(statuses, status.Unknown):
			want = exitcode.Inconclusive
		}
		got := Assess(resultsFor(statuses)).ExitCode
		if got != want {
			t.Errorf("layers %v ended with %s (%d), want %s (%d)",
				statuses, got.Name(), got.Int(), want.Name(), want.Int())
		}
		if !got.Valid() {
			t.Errorf("layers %v produced exit code %d, which is not in the frozen table", statuses, got.Int())
		}
	})
}

// TestNoFailureIsEverReportedAsSuccess is the same promise from the direction
// that costs the most when it breaks. A verdict reading as success over a
// failing row looks like a working machine and the reader stops there.
func TestNoFailureIsEverReportedAsSuccess(t *testing.T) {
	everyCombinationUpTo(t, 3, func(statuses []status.Status) {
		if !contains(statuses, status.Fail) && !contains(statuses, status.Unknown) && len(statuses) > 0 {
			return
		}
		verdict := Assess(resultsFor(statuses))
		if verdict.ExitCode == exitcode.OK {
			t.Errorf("layers %v ended with success", statuses)
		}
		if verdict.Sentence == everythingPassed {
			t.Errorf("layers %v produced the complete-success sentence", statuses)
		}
	})
}

// TestAWarningDoesNotRedenTheExitCode pins the decision that a warning alone
// keeps the code at success. Without it every machine behind a corporate proxy
// would fail a build whose connection works perfectly, and the tool would be
// switched off within a week.
func TestAWarningDoesNotRedenTheExitCode(t *testing.T) {
	everyCombinationUpTo(t, 3, func(statuses []status.Status) {
		if len(statuses) == 0 || contains(statuses, status.Fail) || contains(statuses, status.Unknown) {
			return
		}
		if got := Assess(resultsFor(statuses)).ExitCode; got != exitcode.OK {
			t.Errorf("layers %v are at worst a warning and ended with %s", statuses, got.Name())
		}
	})
}

// TestVerdictOfAnEmptyReportIsNeverSuccess covers the degenerate input that the
// fold would otherwise get wrong for a defensible reason: folding an empty set
// of statuses answers "success", which is right when combining a subset into a
// whole and wrong when the whole is empty.
func TestVerdictOfAnEmptyReportIsNeverSuccess(t *testing.T) {
	for _, results := range [][]LayerResult{nil, {}} {
		verdict := Assess(results)
		if verdict.Status != status.Unknown {
			t.Errorf("a report with no layers folded to %s", verdict.Status)
		}
		if verdict.ExitCode != exitcode.Inconclusive {
			t.Errorf("a report with no layers ended with %s", verdict.ExitCode.Name())
		}
		if verdict.Sentence != nothingAssessed {
			t.Errorf("a report with no layers said %q", verdict.Sentence)
		}
	}
}

// TestTheAllUnknownRunGetsTheSettledSentence pins the sentence this whole slice
// exists to produce, and pins that it is used only when it is true.
func TestTheAllUnknownRunGetsTheSettledSentence(t *testing.T) {
	all := make([]status.Status, len(layer.All))
	for i := range all {
		all[i] = status.Unknown
	}
	if got := Assess(resultsFor(all)).Sentence; got != "Nothing could be assessed yet." {
		t.Errorf("a run where nothing was assessed said %q", got)
	}

	mixed := append([]status.Status{status.Pass}, all[1:]...)
	if got := Assess(resultsFor(mixed)).Sentence; got == nothingAssessed {
		t.Errorf("a run where one layer did produce an answer still said %q", got)
	}
}

// TestEverySentenceSaysSomethingAndItsCountsAgree keeps the provisional
// counting sentences honest. A sentence quoting the wrong number is worse than
// no sentence at all, because the reader checks the number against the rows and
// then trusts whichever one they read first.
func TestEverySentenceSaysSomethingAndItsCountsAgree(t *testing.T) {
	everyCombinationUpTo(t, 3, func(statuses []status.Status) {
		sentence := Assess(resultsFor(statuses)).Sentence
		if sentence == "" {
			t.Fatalf("layers %v produced no sentence", statuses)
		}
		if !strings.HasSuffix(sentence, ".") {
			t.Errorf("layers %v produced %q, which does not end as a sentence", statuses, sentence)
		}

		failures := countOf(statuses, status.Fail)
		if failures == 0 {
			return
		}
		want := fmt.Sprintf("%d of %d", failures, len(statuses))
		if !strings.Contains(sentence, want) {
			t.Errorf("layers %v produced %q, which does not read %q", statuses, sentence, want)
		}
	})
}

func countOf(statuses []status.Status, want status.Status) int {
	n := 0
	for _, s := range statuses {
		if s == want {
			n++
		}
	}
	return n
}
