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
	}

	got := Assess(results).Sentence
	for _, want := range []string{"Failures in 2 of 6", "3 of 6 diagnostic layers could not be assessed"} {
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

// unheld is the signer of nobodyHolds: refused by the two stores that sentence
// counts, listed the way the trust layer lists them - one name per file.
func unheld() Finding {
	f := signer(nobodyHolds, HeldByNoStores)
	f.SigningAuthority.RefusingStores = []string{"curl", "git"}
	return f
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

// handshakeRow is the L4 row carrying the chain, saying whether the issuer of
// its leaf arrived.
func handshakeRow(complete bool) Finding {
	return Finding{Kind: FindingTLSHandshake, TLSHandshake: &TLSHandshake{Completed: true, ChainComplete: complete, Chain: []Certificate{{}}}}
}

// withheld is L4 over a leaf whose issuer did not arrive - a warning since
// ADR114, with the row that says so.
func withheld() LayerResult {
	return row(layer.TLS, status.Warn, l4Incomplete, handshakeRow(false))
}

const (
	l4Incomplete    = "the server presented 1 certificate(s) and did not send the issuer of the first one, so only a client that already holds it can build a path"
	serverWithheld  = "The server presented 1 certificate(s) and did not send the issuer of the first one, so only a client that already holds it can build a path, and none of the 2 store(s) assessed here built one - this is a fact about the server rather than about this machine"
	l5TwoRefuse     = "2 of 3 store(s) do not trust the presented chain"
	middlebox       = "mitmproxy signed this certificate, and 1 store(s) assessed here hold an anchor for it and 1 do not - and that issuer names mitmproxy, a TLS inspection product, so this connection is being intercepted and re-signed between here and the server"
	nobodyHolds     = "certdoctor testbed intermediate signed this certificate, and none of the 2 store(s) assessed here holds an anchor for it"
	unheldMiddlebox = "mitmproxy signed this certificate, and none of the 2 store(s) assessed here holds an anchor for it - and that issuer names mitmproxy, a TLS inspection product, so this connection is being intercepted and re-signed between here and the server"
	companySigner   = "Example Corp Root CA signed this certificate, and 1 store(s) assessed here hold an anchor for it and 1 do not"
	l4OtherName     = "the server presented a certificate for other.example.com, and that does not cover registry.example.com - clients refuse that whatever they trust, so this is a fact about the server or about the name used to reach it"
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
// that forgot its intermediate look identical to L4 - a warning since ADR114 -
// and only the trust matrix tells them apart. So the middlebox verdict comes
// from L5, and the forgetful server's verdict must blame the server even though
// every trust row under it is red.
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

// causeScenarios are the bench scenarios of docs/21 written as rows, with the
// sentence each must produce at the top of the report.
var causeScenarios = []struct {
	name string
	rows []LayerResult
	want string
}{
	{
		name: "S-4 or a name that does not resolve: L1 is the cause of everything under it",
		rows: []LayerResult{pass(layer.Context),
			row(layer.Resolution, status.Fail, "neither view found an address for this name, and at least one of them said so"),
			skipped(layer.Proxy, "x"), skipped(layer.TCP, "nothing to connect to"), skipped(layer.TLS, "x"), skipped(layer.TrustMatrix, "x")},
		want: "Neither view found an address for this name, and at least one of them said so. 4 of 6 diagnostic layers could not be assessed.",
	},
	{
		name: "no address accepts a connection: L3 is the cause and L4/L5 are consequences",
		rows: []LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy),
			row(layer.TCP, status.Fail, "none of the 2 address(es) this name resolved to accepted a connection"),
			skipped(layer.TLS, "x"), skipped(layer.TrustMatrix, "x")},
		want: "None of the 2 address(es) this name resolved to accepted a connection. 2 of 6 diagnostic layers could not be assessed.",
	},
	{
		name: "the direct route fails and a proxy applies: the measurement stays the cause and says which route it was - ADR114",
		rows: []LayerResult{pass(layer.Context), pass(layer.Resolution),
			row(layer.Proxy, status.Pass, "", Finding{Kind: FindingProxyChallenge, Summary: "asked"}),
			row(layer.TCP, status.Fail, "none of the 2 address(es) this name resolved to accepted a connection"),
			skipped(layer.TLS, "x"), skipped(layer.TrustMatrix, "x")},
		want: "None of the 2 address(es) this name resolved to accepted a connection, but that was measured on the " +
			"direct route, and a proxy applies to this URL - a program set to use it goes through the proxy instead. " +
			"2 of 6 diagnostic layers could not be assessed.",
	},
	{
		name: "a name only the proxy resolves: L1 is the cause and says it looked directly",
		rows: []LayerResult{pass(layer.Context),
			row(layer.Resolution, status.Fail, "neither view found an address for this name"),
			row(layer.Proxy, status.Pass, "", Finding{Kind: FindingProxyChallenge, Summary: "asked"}),
			skipped(layer.TCP, "x"), skipped(layer.TLS, "x"), skipped(layer.TrustMatrix, "x")},
		want: "Neither view found an address for this name, but that was measured on the direct route, and a proxy " +
			"applies to this URL - a program set to use it goes through the proxy instead. " +
			"3 of 6 diagnostic layers could not be assessed.",
	},
	{
		name: "S-5 through a proxy: the server is still to blame, on the route that was measured",
		rows: []LayerResult{pass(layer.Context), pass(layer.Resolution),
			row(layer.Proxy, status.Pass, "", Finding{Kind: FindingProxyChallenge, Summary: "asked"}), pass(layer.TCP),
			withheld(),
			row(layer.TrustMatrix, status.Fail, l5TwoRefuse, unheld(),
				storeRefusing("curl", UnknownAuthority), storeRefusing("git", UnknownAuthority))},
		want: serverWithheld + ", but that was measured on the direct route, and a proxy applies to this URL - a " +
			"program set to use it goes through the proxy instead. Warnings in 1 of 6 diagnostic layers.",
	},
	{
		name: "a proxy layer with rows of another kind names no proxy that applies",
		rows: []LayerResult{pass(layer.Context),
			row(layer.Resolution, status.Fail, "neither view found an address for this name"),
			row(layer.Proxy, status.Pass, "", Finding{Kind: FindingProxyStack, Summary: "no proxy named"}),
			skipped(layer.TCP, "x"), skipped(layer.TLS, "x"), skipped(layer.TrustMatrix, "x")},
		want: "Neither view found an address for this name. 3 of 6 diagnostic layers could not be assessed.",
	},
	{
		name: "S-5 the server forgot its intermediate: every trust row is red and the server is still to blame",
		rows: []LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP),
			withheld(),
			row(layer.TrustMatrix, status.Fail, l5TwoRefuse, unheld(),
				storeRefusing("curl", UnknownAuthority), storeRefusing("git", UnknownAuthority))},
		want: serverWithheld + ". Warnings in 1 of 6 diagnostic layers.",
	},
	{
		name: "B01 a leaf signed straight by a root every store here holds: a warning about the bytes and nothing failing - ADR114",
		rows: []LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP),
			withheld(),
			row(layer.TrustMatrix, status.Pass, "2 of 2 store(s) trust the presented chain", storeTrusting("curl"), storeTrusting("git"))},
		want: "Everything assessed passed. Warnings in 1 of 6 diagnostic layers.",
	},
	{
		name: "a chain without its issuer that one store here completed: the server is not blamed, and the refusing stores are the story",
		rows: []LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP),
			withheld(),
			row(layer.TrustMatrix, status.Fail, l5TwoRefuse, storeRefusing("curl", Expired), storeRefusing("git", Expired), storeTrusting("java"))},
		want: "2 of 3 store(s) do not trust the presented chain - a certificate in the path is past its validity. Warnings in 1 of 6 diagnostic layers.",
	},
	{
		name: "a chain without its issuer that one store refused on its dates: that store built a path first, so the server is not blamed - ADR114",
		rows: []LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP),
			withheld(),
			row(layer.TrustMatrix, status.Fail, l5TwoRefuse, unheld(),
				storeRefusing("curl", UnknownAuthority), storeRefusing("git", UnknownAuthority), storeRefusing("java", Expired))},
		want: nobodyHolds + ". Warnings in 1 of 6 diagnostic layers.",
	},
	{
		name: "a chain without its issuer, no_stores on the signer's row and a row that trusts it - two rows over one file judged differently: that row built a path, so the server is not blamed",
		rows: []LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP),
			withheld(),
			row(layer.TrustMatrix, status.Fail, "2 of 3 store(s) do not trust the presented chain", unheld(),
				storeRefusing("curl", UnknownAuthority), storeRefusing("git", UnknownAuthority), storeTrusting("python"))},
		want: nobodyHolds + ". Warnings in 1 of 6 diagnostic layers.",
	},
	{
		name: "S-5 with two rows over one file: the server sentence counts the stores the signer's row counts, decided by the owner 2026-10-27",
		rows: []LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP),
			withheld(),
			row(layer.TrustMatrix, status.Fail, "3 of 3 store(s) do not trust the presented chain", unheld(),
				storeRefusing("curl", UnknownAuthority), storeRefusing("git", UnknownAuthority), storeRefusing("git", UnknownAuthority))},
		want: serverWithheld + ". Warnings in 1 of 6 diagnostic layers.",
	},
	{
		name: "a whole chain warned about for its name and refused by every store: no issuer is said to be missing",
		rows: []LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP),
			row(layer.TLS, status.Warn, "the certificate names legacy.example.com only in its common name", handshakeRow(true)),
			row(layer.TrustMatrix, status.Fail, l5TwoRefuse, unheld(),
				storeRefusing("curl", UnknownAuthority), storeRefusing("git", UnknownAuthority))},
		want: nobodyHolds + ". Warnings in 1 of 6 diagnostic layers.",
	},
	{
		name: "a failing matrix with no store assessed: nothing was built and nothing was tried, so the server is not blamed",
		rows: []LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP),
			withheld(),
			row(layer.TrustMatrix, status.Fail, l5TwoRefuse, storeUndetermined("curl", "curl.exe", onSchannel))},
		want: "2 of 3 store(s) do not trust the presented chain. Warnings in 1 of 6 diagnostic layers.",
	},
	{
		name: "the row carrying the chain is not the first: an address that never completed says nothing about an issuer",
		rows: []LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP),
			row(layer.TLS, status.Warn, "the certificate names legacy.example.com only in its common name",
				Finding{Kind: FindingTLSHandshake, TLSHandshake: &TLSHandshake{NotCompleted: "the server did not complete a TLS handshake"}},
				handshakeRow(true)),
			row(layer.TrustMatrix, status.Fail, l5TwoRefuse, unheld(),
				storeRefusing("curl", UnknownAuthority), storeRefusing("git", UnknownAuthority))},
		want: nobodyHolds + ". Warnings in 1 of 6 diagnostic layers.",
	},
	{
		name: "an L4 warning with no row carrying a chain: nothing is said about an issuer",
		rows: []LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP),
			row(layer.TLS, status.Warn, l4Incomplete),
			row(layer.TrustMatrix, status.Fail, l5TwoRefuse, unheld(),
				storeRefusing("curl", UnknownAuthority), storeRefusing("git", UnknownAuthority))},
		want: nobodyHolds + ". Warnings in 1 of 6 diagnostic layers.",
	},
	{
		name: "a leaf for another name: L4 fails, and its sentence is the cause",
		rows: []LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP),
			row(layer.TLS, status.Fail, "the certificate does not cover wrong.host.example", handshakeRow(true)),
			row(layer.TrustMatrix, status.Pass, "2 of 2 store(s) trust the presented chain", storeTrusting("curl"), storeTrusting("git"))},
		want: "The certificate does not cover wrong.host.example.",
	},
	{
		name: "a leaf for another name on the direct route while a proxy applies: L4 is the cause and says which route it measured - ADR114",
		rows: []LayerResult{pass(layer.Context), pass(layer.Resolution),
			row(layer.Proxy, status.Pass, "", Finding{Kind: FindingProxyChallenge, Summary: "asked"}), pass(layer.TCP),
			row(layer.TLS, status.Fail, l4OtherName, handshakeRow(true)), pass(layer.TrustMatrix)},
		want: "The server presented a certificate for other.example.com, and that does not cover registry.example.com - clients refuse that whatever they trust, so this is a fact about the server or about the name used to reach it, but that was measured on the direct route, and a proxy applies to this URL - a program set to use it goes through the proxy instead.",
	},
	{
		name: "a chain without its issuer and an L4 row with no sentence: nothing is quoted that was not written",
		rows: []LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP),
			row(layer.TLS, status.Warn, "", handshakeRow(false)),
			row(layer.TrustMatrix, status.Fail, l5TwoRefuse, unheld(),
				storeRefusing("curl", UnknownAuthority), storeRefusing("git", UnknownAuthority))},
		want: nobodyHolds + ". Warnings in 1 of 6 diagnostic layers.",
	},
	{
		name: "S-1 a middlebox: L4 warns exactly as in S-5, and the local authority in L5 is the cause",
		rows: []LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP),
			withheld(),
			row(layer.TrustMatrix, status.Fail, "1 of 2 store(s) do not trust the presented chain", inspected(middlebox, HeldBySomeStores),
				storeTrusting("curl"), storeRefusing("git", UnknownAuthority))},
		want: middlebox + ". Without it: git. Warnings in 1 of 6 diagnostic layers.",
	},
	{
		name: "a middlebox nobody here trusts: L4 warns, no store holds the signer, and the named product still leads - measured on the bench 2026-09-22",
		rows: []LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP),
			withheld(),
			row(layer.TrustMatrix, status.Fail, l5TwoRefuse, inspected(unheldMiddlebox, HeldByNoStores),
				storeRefusing("curl", UnknownAuthority), storeRefusing("git", UnknownAuthority))},
		want: unheldMiddlebox + ". Warnings in 1 of 6 diagnostic layers.",
	},
	{
		name: "S-3 and S-6 an honest server under a company authority: which runtimes lack the anchor, with counts where a runtime has several stores",
		rows: []LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP), pass(layer.TLS),
			row(layer.TrustMatrix, status.Fail, "4 of 6 store(s) do not trust the presented chain",
				signer("Example Corp Root CA signed this certificate, and 2 store(s) assessed here hold an anchor for it and 4 do not", HeldBySomeStores),
				storeTrusting("curl"), storeRefusing("git", UnknownAuthority), storeTrusting("java"), storeRefusing("java", UnknownAuthority), storeRefusing("java", UnknownAuthority), storeRefusing("java", UnknownAuthority))},
		want: "Example Corp Root CA signed this certificate, and 2 store(s) assessed here hold an anchor for it and 4 do not. Without it: git, java (3 of 4).",
	},
	{
		name: "B04 a leaf for another name under an authority some stores hold: L4 is the cause, because importing the authority fixes no name - ADR114",
		rows: []LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP),
			row(layer.TLS, status.Fail, l4OtherName, handshakeRow(true)),
			row(layer.TrustMatrix, status.Fail, "1 of 2 store(s) do not trust the presented chain", signer(companySigner, HeldBySomeStores),
				storeTrusting("curl"), storeRefusing("git", UnknownAuthority))},
		want: "The server presented a certificate for other.example.com, and that does not cover registry.example.com - clients refuse that whatever they trust, so this is a fact about the server or about the name used to reach it. Failures in 2 of 6 diagnostic layers.",
	},
	{
		name: "B04 a leaf for another name from a named inspection product: the product leads, because the leaf came from it and not from the server - ADR114",
		rows: []LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP),
			row(layer.TLS, status.Fail, l4OtherName, handshakeRow(true)),
			row(layer.TrustMatrix, status.Fail, "1 of 2 store(s) do not trust the presented chain", inspected(middlebox, HeldBySomeStores),
				storeTrusting("curl"), storeRefusing("git", UnknownAuthority))},
		want: middlebox + ". Without it: git. Failures in 2 of 6 diagnostic layers.",
	},
	{
		name: "B04 an authority some stores hold, with a leaf that covers the name: the split is still the cause - ADR114",
		rows: []LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP), pass(layer.TLS),
			row(layer.TrustMatrix, status.Fail, "1 of 2 store(s) do not trust the presented chain", signer(companySigner, HeldBySomeStores),
				storeTrusting("curl"), storeRefusing("git", UnknownAuthority))},
		want: companySigner + ". Without it: git.",
	},
	{
		name: "a private root nobody here holds, chain complete: the signer is named and no runtime is listed",
		rows: []LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP), pass(layer.TLS),
			row(layer.TrustMatrix, status.Fail, l5TwoRefuse, unheld(),
				storeRefusing("curl", UnknownAuthority), storeRefusing("git", UnknownAuthority))},
		want: nobodyHolds + ".",
	},
	{
		name: "stores hold the anchor and still refuse, all for the same reason: the layer's count and that reason",
		rows: []LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP), pass(layer.TLS),
			row(layer.TrustMatrix, status.Fail, l5TwoRefuse, storeRefusing("curl", Expired), storeRefusing("git", Expired), storeTrusting("java"))},
		want: "2 of 3 store(s) do not trust the presented chain - a certificate in the path is past its validity.",
	},
	{
		name: "stores refuse for different reasons: the layer's count and nothing invented",
		rows: []LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP), pass(layer.TLS),
			row(layer.TrustMatrix, status.Fail, l5TwoRefuse, storeRefusing("curl", Expired), storeRefusing("git", NotYetValid), storeTrusting("java"))},
		want: "2 of 3 store(s) do not trust the presented chain.",
	},
	{
		name: "nothing failed but the proxy wants credentials: a passing run says so out loud",
		rows: []LayerResult{pass(layer.Context), pass(layer.Resolution),
			{ID: layer.Proxy, Status: status.Unknown, Reason: status.ReasonCredentialsRequired, Detail: wantsCreds},
			pass(layer.TCP), pass(layer.TLS), pass(layer.TrustMatrix)},
		want: "Everything assessed passed, but " + wantsCreds + ". 1 of 6 diagnostic layers could not be assessed.",
	},
	{
		name: "nothing failed, one warning: the warning is no longer dropped from the top line",
		rows: []LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP), pass(layer.TLS),
			row(layer.TrustMatrix, status.Warn, "9 of 11 store(s) trust the presented chain, and 2 could not be assessed")},
		want: "Everything assessed passed. Warnings in 1 of 6 diagnostic layers.",
	},
	{
		name: "OBS159 nothing failed and the platform has no store at all, measured in ubuntu:24.04: the top line says what the row says",
		rows: []LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP), pass(layer.TLS),
			row(layer.TrustMatrix, status.Unknown, "none of the 1 store(s) found could be assessed",
				storeUndetermined(RuntimeSystemStore, "ubuntu", noBundle))},
		want: "Everything assessed passed, but system-store ubuntu could not be assessed: " + noBundle + ". 1 of 6 diagnostic layers could not be assessed.",
	},
	{
		name: "other stores trust and one of the platform's two Windows stores is undetermined: that row is named and the warning still counted",
		rows: []LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP), pass(layer.TLS),
			row(layer.TrustMatrix, status.Warn, "2 of 3 store(s) trust the presented chain, and 1 could not be assessed",
				storeTrusting("git"), storeTrusting(RuntimeSystemStore), storeUndetermined(RuntimeSystemStore, "LocalMachine", notFetched))},
		want: "Everything assessed passed, but system-store LocalMachine could not be assessed: " + notFetched + ". Warnings in 1 of 6 diagnostic layers.",
	},
	{
		name: "curl on schannel could not be assessed and the platform's row judged the chain, measured on Windows 2026-10-19: the tail counts it and nothing more is said",
		rows: []LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP), pass(layer.TLS),
			row(layer.TrustMatrix, status.Warn, "2 of 3 store(s) trust the presented chain, and 1 could not be assessed",
				summarised(storeTrusting(RuntimeSystemStore), "system-store CurrentUser trusts the presented chain (60 anchors)"),
				storeUndetermined("curl", "curl.exe", onSchannel), storeTrusting("git"))},
		want: "Everything assessed passed. Warnings in 1 of 6 diagnostic layers.",
	},
	{
		name: "an undetermined platform row with no summary names nothing, so nothing is invented and the function stays total",
		rows: []LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP), pass(layer.TLS),
			row(layer.TrustMatrix, status.Unknown, "none of the 1 store(s) found could be assessed",
				summarised(storeUndetermined(RuntimeSystemStore, "ubuntu", noBundle), ""))},
		want: "Everything assessed passed. 1 of 6 diagnostic layers could not be assessed.",
	},
	{
		name: "the proxy wants credentials AND the platform has no store: one but, and the proxy's comes first in layer order",
		rows: []LayerResult{pass(layer.Context), pass(layer.Resolution),
			{ID: layer.Proxy, Status: status.Unknown, Reason: status.ReasonCredentialsRequired, Detail: wantsCreds},
			pass(layer.TCP), pass(layer.TLS),
			row(layer.TrustMatrix, status.Unknown, "none of the 1 store(s) found could be assessed",
				storeUndetermined(RuntimeSystemStore, "ubuntu", noBundle))},
		want: "Everything assessed passed, but " + wantsCreds + ". 2 of 6 diagnostic layers could not be assessed.",
	},
	{
		name: "S-5 with the platform's row undetermined: a failure outranks it, the server is still to blame, and only the assessed stores are counted",
		rows: []LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP),
			withheld(),
			row(layer.TrustMatrix, status.Fail, l5TwoRefuse, unheld(),
				storeRefusing("curl", UnknownAuthority), storeRefusing("git", UnknownAuthority),
				storeUndetermined(RuntimeSystemStore, "ubuntu", noBundle))},
		want: serverWithheld + ". Warnings in 1 of 6 diagnostic layers.",
	},
	{
		name: "a failing row with no detail names nothing, so the count stands in and the function stays total",
		rows: []LayerResult{pass(layer.Context), row(layer.Resolution, status.Fail, ""), pass(layer.Proxy), pass(layer.TCP), pass(layer.TLS), pass(layer.TrustMatrix)},
		want: "Failures in 1 of 6 diagnostic layers.",
	},
	{
		name: "a failing trust matrix with no detail and no signer: the count stands in rather than a lone full stop",
		rows: []LayerResult{pass(layer.Context), pass(layer.Resolution), pass(layer.Proxy), pass(layer.TCP), pass(layer.TLS),
			row(layer.TrustMatrix, status.Fail, "", storeRefusing("curl", Expired))},
		want: "Failures in 1 of 6 diagnostic layers.",
	},
}

// TestTheDecisiveLayerIsFoundByIdentityNotByPosition: the validator hands the
// fold whatever order the report holds, so the answer must not depend on it.
func TestTheDecisiveLayerIsFoundByIdentityNotByPosition(t *testing.T) {
	rows := []LayerResult{
		row(layer.TrustMatrix, status.Fail, l5TwoRefuse, unheld(), storeRefusing("git", UnknownAuthority)),
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
			for _, id := range []layer.ID{layer.Resolution, layer.TCP, layer.TLS, layer.TrustMatrix, layer.Context, layer.Proxy} {
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
