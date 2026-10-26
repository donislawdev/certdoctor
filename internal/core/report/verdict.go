package report

import (
	"fmt"
	"strings"

	"github.com/donislawdev/certdoctor/internal/core/exitcode"
	"github.com/donislawdev/certdoctor/internal/core/layer"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// Verdict is the one sentence at the top of the report, the status behind it
// and the code the process ends with.
//
// The exit code is carried here as well as being handed to the operating system
// on purpose. A report saved to a file keeps information the process exit status
// cannot, and a reader comparing two saved reports should not have to remember
// what each run returned.
type Verdict struct {
	Status   status.Status
	Sentence string
	ExitCode exitcode.Code
}

// nothingAssessed is the verdict of a run that could not assess a single layer.
//
// It is settled product text, as is everythingPassed below. The sentences in
// between were arithmetic for the first seven weeks of this program - "Failures
// in 2 of 8 diagnostic layers" - and stayed so on purpose, because a count can
// be proven and a cause cannot until the layers that establish one exist. They
// exist now, and the verdict names the cause the decisive layer established,
// in that layer's own words, with the counts kept behind it so that nothing
// the arithmetic used to say is lost. See causeOf for what "decisive" means.
const nothingAssessed = "Nothing could be assessed yet."

// everythingPassed is the other settled one, because it is the only sentence
// that must never appear over a report containing a failure.
const everythingPassed = "Everything that mattered was assessed and passed."

// everythingAssessedPassed opens every sentence over rows with no failure in
// them. "Assessed" is the load-bearing word: it is true of a run that could
// look at three layers and found all three fine, and it says nothing about the
// five it could not look at, which the tail behind it then counts.
const everythingAssessedPassed = "Everything assessed passed"

// Assess folds the layer results into the verdict.
//
// This function is the product's main promise written down: the sentence at the
// top has to agree with the rows underneath it. A verdict reading "all fine"
// above four failures is the worst mistake this tool can make, because it looks
// like success and the reader stops there.
//
// It is pure and total over any slice of results, and it is recomputed by the
// report validator and compared against what the report carries - so every
// word of the sentence has to come from the rows, never from anything a layer
// knew and did not write down. It is also called AFTER masking, so the words
// it takes from the rows are the words the report is allowed to show.
func Assess(results []LayerResult) Verdict {
	counts := map[status.Status]int{}
	for _, r := range results {
		counts[r.Status]++
	}
	return Verdict{
		Status:   worstOf(results),
		Sentence: sentenceFor(results, counts),
		ExitCode: codeFor(counts, len(results)),
	}
}

// worstOf returns the most severe status among the results.
//
// The empty case is not a formality. status.Worst answers "success" for an empty
// set, which is right for folding a subset into a whole and wrong here: a run
// that produced no rows at all assessed nothing, and reporting that as success
// is exactly the failure this file exists to prevent.
func worstOf(results []LayerResult) status.Status {
	if len(results) == 0 {
		return status.Unknown
	}
	all := make([]status.Status, 0, len(results))
	for _, r := range results {
		s := r.Status
		if !s.Valid() {
			// A STATUS OUTSIDE THE VOCABULARY IS FOLDED AS UNKNOWN INSTEAD OF
			// ENDING THE RUN, AND THE PANIC IT REPLACES WAS IN THE ONE PLACE THAT
			// MUST NOT HAVE ONE. Severity panics on a value outside the four,
			// deliberately - it can only mean a caller invented one - and that
			// promise is untouched here. But Validate calls Assess, and Validate
			// exists to collect EVERY violation in a report it did not build:
			// validateLayerResult records the bad status and carries on, and this
			// fold then ended the process before the rest of the list could be
			// reported. The last line of defence must not be the thing that
			// destroys the evidence, and the bad status is already recorded by
			// the time this runs.
			s = status.Unknown
		}
		all = append(all, s)
	}
	return status.Worst(all...)
}

// codeFor maps the fold onto the frozen exit code table.
//
// A warning on its own keeps the code at success, deliberately: otherwise every
// machine behind a corporate proxy would redden a build whose connection works,
// and the tool would be switched off within a week. The machine-readable report
// carries the warnings for a pipeline that wants to decide differently.
func codeFor(counts map[status.Status]int, total int) exitcode.Code {
	switch {
	case counts[status.Fail] > 0:
		return exitcode.Diagnosis
	case total == 0 || counts[status.Unknown] > 0:
		return exitcode.Inconclusive
	default:
		return exitcode.OK
	}
}

// sentenceFor picks the verdict sentence.
//
// Five shapes, in this order:
//
//   - nothing assessed: the settled sentence, because "nothing could be
//     assessed" reads better than "6 of 6 could not be assessed" and says the
//     same thing. A run where only some came back unknown must not use it,
//     because then it would be false.
//   - a failure: the cause the decisive layer established, followed by the
//     tail. When no row can name a cause - which the validator rejects, since
//     every non-passing row must carry a detail - the count of failures stands
//     in, so the function stays total.
//   - no failure, but the proxy this URL goes through wants credentials: said
//     out loud, because this program connects directly and a runtime that
//     goes through the proxy does not.
//   - no failure, but the platform's own store could not judge the chain: said
//     out loud too, because every program without a store of its own judges
//     by that one. See platformStoreUndetermined.
//   - no failure: the settled success sentence when there is nothing else to
//     say, otherwise "everything assessed passed" and the tail.
//
// THE TAIL IS THE BAN ON SILENCE, KEPT FROM THE ARITHMETIC VERSION. A run with
// a named cause AND layers it could not look at used to be the shape that hid
// the second half: a reader fixes what the sentence names, comes back, and
// finds three more layers that were never assessed. The verdict is the line
// people act on, so the counts of further failures, of warnings and of layers
// not assessed stay on it, after the cause.
func sentenceFor(results []LayerResult, counts map[status.Status]int) string {
	total := len(results)
	unknown := counts[status.Unknown]
	switch {
	case total == 0 || unknown == total:
		return nothingAssessed
	case counts[status.Fail] > 0:
		cause, named := causeOf(results)
		if !named {
			cause = fmt.Sprintf("Failures in %d of %d diagnostic layers.", counts[status.Fail], total)
		}
		return cause + tail(counts, total, named)
	}
	if demand, ok := credentialsDemand(results); ok {
		return everythingAssessedPassed + ", but " + demand + tail(counts, total, false)
	}
	if why, ok := platformStoreUndetermined(results); ok {
		return everythingAssessedPassed + ", but " + why + tail(counts, total, false)
	}
	if unknown == 0 && counts[status.Warn] == 0 {
		return everythingPassed
	}
	return everythingAssessedPassed + "." + tail(counts, total, false)
}

// tail is what follows the cause: the counts the sentence used to consist of.
//
// The failure count is stated only when a cause was named and more than one
// layer failed, because then the sentence names one and the rows hold another
// - and when no cause was named, the count IS the sentence, already printed.
func tail(counts map[status.Status]int, total int, causeNamed bool) string {
	var b strings.Builder
	if causeNamed && counts[status.Fail] > 1 {
		fmt.Fprintf(&b, " Failures in %d of %d diagnostic layers.", counts[status.Fail], total)
	}
	if counts[status.Warn] > 0 {
		fmt.Fprintf(&b, " Warnings in %d of %d diagnostic layers.", counts[status.Warn], total)
	}
	if counts[status.Unknown] > 0 {
		fmt.Fprintf(&b, " %d of %d diagnostic layers could not be assessed.", counts[status.Unknown], total)
	}
	return b.String()
}

// causeOf names the cause of a failing run, in the words of the layer that
// established it.
//
// THE DECISIVE LAYER IS NOT THE FIRST RED ROW. The layers depend on each other
// downwards - no address means nothing to connect to, no connection means
// nothing to hand shake with - so a failure in name resolution or in reaching
// the address is the cause of everything under it and goes first. Below that
// the order is deliberately NOT the layer order, and the reason was measured on
// the bench on 2026-08-19: a middlebox re-signing traffic presents a chain
// without its issuer, exactly as a server that forgot its intermediate does, so
// on structure alone L4 fails identically for both. What separates them is L5:
// the middlebox's signer is an authority THIS MACHINE holds in some stores and
// not in others, while nobody holds the forgetful server's missing issuer.
// So a local authority held by some stores is asked before L4, and a chain
// without its issuer that no store here completed is blamed on the server,
// which is scenario S-5 - every row of the trust matrix red, and the right
// answer still "do nothing on this machine". Since ADR114 L4 only warns about
// that chain, so the server is named from the trust rung - issuerWithheld.
//
// Any layer that has no cause of its own here is taken in layer order, in its
// own words, so that a failure a future layer produces is never reported as a
// count alone. L0 does not fail today, and L2 fails since ADR114 when a proxy
// this URL goes through refuses the connection.
func causeOf(results []LayerResult) (string, bool) {
	if r, ok := failing(results, layer.Resolution); ok {
		return directly(results, r.Detail)
	}
	if r, ok := failing(results, layer.TCP); ok {
		return directly(results, r.Detail)
	}
	if r, ok := failing(results, layer.TrustMatrix); ok {
		if authority := localAuthority(r); authority != nil {
			return authorityCause(r, *authority), true
		}
	}
	if r, ok := failing(results, layer.TLS); ok {
		return directly(results, r.Detail)
	}
	if r, ok := failing(results, layer.TrustMatrix); ok {
		if withheld, ok := issuerWithheld(results, r); ok {
			return directly(results, withheld)
		}
		return trustCause(r)
	}
	for _, id := range layer.All {
		if r, ok := failing(results, id); ok {
			return sentence(r.Detail)
		}
	}
	return "", false
}

// directly is the sentence of a layer that measured the direct route, with one
// "but" when a proxy applies to this URL - ADR114 point 2, decided by the owner.
//
// L1, L3 AND L4 GO THE WAY THIS PROGRAM GOES, straight to the target. A name
// only the proxy resolves, or a firewall letting only the proxy out, fails all
// three while a program set to use the proxy gets through - and a top line
// naming the direct route's failure as THE cause sends that reader to fix
// something their program never touches. The measurement stays the cause, and
// stays true; what it does not cover is said beside it. A proxy applies when L2
// put one to the question at all, asked or not - a row per such endpoint.
func directly(results []LayerResult, detail string) (string, bool) {
	if detail == "" {
		return "", false
	}
	for _, r := range results {
		if r.ID != layer.Proxy {
			continue
		}
		for _, f := range r.Findings {
			if f.Kind == FindingProxyChallenge {
				return sentence(detail + ", but that was measured on the direct route, and a proxy applies to this " +
					"URL - a program set to use it goes through the proxy instead")
			}
		}
	}
	return sentence(detail)
}

// issuerWithheld is the verdict over a server that did not send the issuer of
// its leaf when no store on this machine built a path without it - ADR114,
// decided by the owner.
//
// L4 WARNS ABOUT A MISSING ISSUER RATHER THAN FAILING, because the bytes cannot
// tell a missing intermediate from a root the server may leave out, and a
// client holding that root builds a path. What decides is whether any store
// here built one. None did, so the cause is the server, which is scenario S-5:
// every row of the trust matrix red and "do nothing on this machine" still the
// right answer. One that did makes the refusing stores the story, and the rungs
// above and below tell it.
//
// L4'S OWN SENTENCE IS QUOTED, and it is the missing-issuer one by the order
// detailFor keeps in the handshake package: L4 did not fail, or the rung above
// would have spoken, and a layer that did not fail over a chain without its
// issuer reached that sentence before any other. What is added is the count of
// stores, and whose fact it is.
func issuerWithheld(results []LayerResult, trust LayerResult) (string, bool) {
	tls, ok := resultOf(results, layer.TLS)
	if !ok || tls.Detail == "" || !carriesIncompleteChain(tls) {
		return "", false
	}
	assessed := 0
	for _, f := range trust.Findings {
		if f.Kind != FindingTrustStore || f.TrustStore == nil || f.TrustStore.TrustsPresentedChain == nil {
			continue
		}
		if *f.TrustStore.TrustsPresentedChain {
			return "", false
		}
		assessed++
	}
	if assessed == 0 {
		return "", false
	}
	return fmt.Sprintf("%s, and none of the %d store(s) assessed here built one - this is a fact about the server rather than about this machine",
		tls.Detail, assessed), true
}

// carriesIncompleteChain says whether the row carrying the chain says the issuer
// of its leaf did not arrive.
func carriesIncompleteChain(tls LayerResult) bool {
	for _, f := range tls.Findings {
		if f.Kind == FindingTLSHandshake && f.TLSHandshake != nil && len(f.TLSHandshake.Chain) > 0 {
			return !f.TLSHandshake.ChainComplete
		}
	}
	return false
}

// resultOf returns the first result carrying id.
func resultOf(results []LayerResult, id layer.ID) (LayerResult, bool) {
	for _, r := range results {
		if r.ID == id {
			return r, true
		}
	}
	return LayerResult{}, false
}

// failing returns the first result carrying id if that result failed.
func failing(results []LayerResult, id layer.ID) (LayerResult, bool) {
	r, ok := resultOf(results, id)
	return r, ok && r.Status == status.Fail
}

// credentialsDemand returns the proxy layer's own account of a proxy that
// asked for credentials, when that is the layer's reason for not knowing.
func credentialsDemand(results []LayerResult) (string, bool) {
	for _, r := range results {
		if r.ID == layer.Proxy && r.Status == status.Unknown &&
			r.Reason == status.ReasonCredentialsRequired && r.Detail != "" {
			return period(r.Detail), true
		}
	}
	return "", false
}

// platformStoreUndetermined returns the summary of the first row for the
// platform's own store that could not judge the chain - OBS159, settled by
// ADR105 under a decision the owner delegated.
//
// WHY THIS STORE AND NO OTHER. The platform's store is the one every program
// without a store of its own judges by, so "it could not be assessed" is a fact
// about most of what runs on the machine - and on a machine with nothing
// installed it is THE fact. Measured 2026-10-15 in ubuntu:24.04: the row said
// in as many words that there is no CA bundle and which package installs one,
// while the top line read "Everything assessed passed" and a count. A runtime
// that cannot be assessed for reasons of its own stays in the tail, which
// counts it - and measured 2026-10-19 on the author's Windows machine, those
// were the rows that turned an ordinary run into a warning: curl on schannel,
// which hands the question to this very store. Since ADR108 part 4 those rows
// carry this store's answer instead. The platform's own rows were judged on all
// eight sites asked, so this shape does not fire on an ordinary Windows run.
//
// ONE "BUT", AND THE PROXY'S GOES FIRST, in layer order. A run that has both
// keeps the other in its rows and in the count behind the sentence - the top
// line is the one people act on, and two clauses of this length would bury it.
//
// THE SUMMARY IS QUOTED, NOT THE REASON ALONE, because it names the store and
// Windows has two of them. It is the row's own text, masked before this runs.
func platformStoreUndetermined(results []LayerResult) (string, bool) {
	for _, r := range results {
		for _, f := range r.Findings {
			if f.Kind == FindingTrustStore && f.TrustStore != nil && f.TrustStore.Runtime == RuntimeSystemStore &&
				f.TrustStore.TrustsPresentedChain == nil && f.Summary != "" {
				return period(f.Summary), true
			}
		}
	}
	return "", false
}

// localAuthority returns the signing-authority finding of a trust row when it
// outranks a structural failure in the handshake, for the reason written above
// causeOf: the signer is an authority local to this machine - held by some
// stores here and not by others - OR the signer's name is on the list of TLS
// inspection products this program carries, whatever holds it.
//
// THE SECOND HALF WAS ADDED AFTER A MEASUREMENT, NOT BEFORE. On the bench with
// mitmproxy's root deployed nowhere, the signer was held by no store, this
// function said nothing, and the verdict fell through to L4 - "a fact about
// the server rather than about this machine" - over a row that named mitmproxy
// as an inspection product. A named product is the most specific cause this
// program can establish, and inviolable rule 21 lets the word "intercepted"
// stand exactly when there is such a name. So it leads.
func localAuthority(r LayerResult) *Finding {
	for i := range r.Findings {
		f := r.Findings[i]
		if f.Kind != FindingSigningAuthority || f.SigningAuthority == nil || f.Summary == "" {
			continue
		}
		if f.SigningAuthority.HeldBy == HeldBySomeStores || f.SigningAuthority.Inspection != nil {
			return &r.Findings[i]
		}
	}
	return nil
}

// authorityCause is the verdict over a signer this machine holds in some
// stores and not in others - scenario S-1 and its honest twin S-3/S-6.
//
// The finding's summary is the sentence ADR53 settled, and it already carries
// the interception accusation when the issuer's name is on the list this
// program keeps - so it is quoted, not rewritten. What the verdict adds is the
// half the reader acts on: WHICH runtimes are the ones without the anchor.
// Runtimes, not stores, because a store is named by its path and the top line
// is not the place for four of them - the rows underneath carry every path.
func authorityCause(r LayerResult, authority Finding) string {
	if authority.SigningAuthority.HeldBy != HeldBySomeStores {
		// Nobody holds it, or everybody does: the summary says so in as many
		// words, and a list of every runtime would only repeat it.
		return period(authority.Summary)
	}
	refusing := runtimesWithout(r.Findings)
	if len(refusing) == 0 {
		return period(authority.Summary)
	}
	return period(authority.Summary) + " Without it: " + strings.Join(refusing, ", ") + "."
}

// runtimesWithout lists the runtimes whose store refuses the chain for want of
// an anchor, once each, in row order, with "(k of n)" where a runtime has
// several stores and only some of them refuse.
func runtimesWithout(findings []Finding) []string {
	stores := map[string]int{}
	refusing := map[string]int{}
	order := []string{}
	for _, f := range findings {
		if f.Kind != FindingTrustStore || f.TrustStore == nil || f.TrustStore.Runtime == "" {
			continue
		}
		name := f.TrustStore.Runtime
		if _, seen := stores[name]; !seen {
			order = append(order, name)
		}
		stores[name]++
		if f.TrustStore.TrustsPresentedChain != nil && !*f.TrustStore.TrustsPresentedChain &&
			f.TrustStore.TrustFailure == UnknownAuthority {
			refusing[name]++
		}
	}
	out := []string{}
	for _, name := range order {
		k := refusing[name]
		if k == 0 {
			continue
		}
		if n := stores[name]; k < n {
			out = append(out, fmt.Sprintf("%s (%d of %d)", name, k, n))
			continue
		}
		out = append(out, name)
	}
	return out
}

// trustCause is the verdict over a failing trust matrix whose signer is not a
// local authority split across stores.
//
// A signer nobody here holds gets the settled signing-authority sentence, which
// names the signer. Anything else - a chain the stores hold an anchor for and
// still refuse, expired or not yet valid - gets the layer's own count, and the
// one reason the refusing rows agree on when they agree on exactly one.
func trustCause(r LayerResult) (string, bool) {
	for _, f := range r.Findings {
		if f.Kind == FindingSigningAuthority && f.SigningAuthority != nil &&
			f.SigningAuthority.HeldBy == HeldByNoStores && f.Summary != "" {
			return period(f.Summary), true
		}
	}
	cause, named := sentence(r.Detail)
	if !named {
		return "", false
	}
	if why, agreed := sharedFailure(r.Findings); agreed {
		cause = strings.TrimSuffix(cause, ".") + " - " + why + "."
	}
	return cause, true
}

// sharedFailure returns the meaning of the one trust failure every refusing
// store reports, when there is exactly one and it is not the unknown-authority
// case the signing-authority sentence already covers.
func sharedFailure(findings []Finding) (string, bool) {
	var found TrustFailure
	kinds := 0
	for _, f := range findings {
		if f.Kind != FindingTrustStore || f.TrustStore == nil || f.TrustStore.TrustsPresentedChain == nil ||
			*f.TrustStore.TrustsPresentedChain {
			continue
		}
		if f.TrustStore.TrustFailure != found {
			found = f.TrustStore.TrustFailure
			kinds++
		}
	}
	if kinds != 1 || found == UnknownAuthority || !found.Valid() {
		return "", false
	}
	return found.Meaning(), true
}

// sentence turns a row's detail - written to follow the row's label, so it
// starts in lower case and ends without a full stop - into a sentence that can
// stand first on the page. An empty detail names nothing.
func sentence(detail string) (string, bool) {
	if detail == "" {
		return "", false
	}
	return period(capitalised(detail)), true
}

// capitalised upper-cases a leading ASCII lower-case letter and touches nothing
// else. Nothing else, because a detail may begin with a name - an issuer, a
// runtime - and a name's own casing is not this function's to change.
func capitalised(s string) string {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return s
	}
	return string(s[0]-'a'+'A') + s[1:]
}

// period closes s as a sentence unless it already is one.
func period(s string) string {
	if strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}
