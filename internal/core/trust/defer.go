package trust

import (
	"fmt"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// settleDeferred gives every row that defers to another row that row's answer,
// once the whole matrix has been collected - ADR108 part 4.
//
// AFTER THE WALK, NOT DURING IT. The platform's own row is declared first and so
// is asked first today, but an answer that depended on the order of a list would
// turn into "this run has no answer from that store" the day the list was
// reordered, and nothing would go red.
//
// A DEFERRING ROW ARRIVES IN ONE OF TWO SHAPES. Without a verdict it is waiting
// for the store it defers to, and takes that store's answer. With a refusal of
// its own, the runtime refuses whatever the store says - unless the store
// refuses as well, because then adding the anchor is the step that comes first
// and the store's refusal is the one somebody can act on.
//
// leafSignedItself is L4's fact about the leaf, consumed rather than worked out
// again - the adapter that decides it is the only place that rule lives.
func settleDeferred(rows []row, leafSignedItself bool) []row {
	settled := make([]row, len(rows))
	copy(settled, rows)
	for i := range settled {
		if settled[i].store.DefersTo != nil {
			settled[i] = settle(settled[i], targetOf(rows, *settled[i].store.DefersTo), leafSignedItself)
		}
	}
	return settled
}

// targetOf finds the row a deferring row points at. A row that defers is never a
// target itself, so a chain of deferrals cannot form.
func targetOf(rows []row, ref report.StoreRef) *report.TrustStore {
	for i := range rows {
		s := &rows[i].store
		if s.DefersTo == nil && s.Runtime == ref.Runtime && s.Instance == ref.Instance {
			return s
		}
	}
	return nil
}

func settle(r row, target *report.TrustStore, leafSignedItself bool) row {
	store := r.store
	if leafSignedItself {
		store = anchorsAreNotAsked(store)
	}
	name := store.DefersTo.Runtime + " " + store.DefersTo.Instance
	switch {
	case answered(target, false):
		return refusedByTheStore(store, *target, name)
	case answered(&store, false):
		return refusedByTheRuntime(store, target)
	case target == nil:
		return unanswered(store, fmt.Sprintf("it judges by %s, and this run has no answer from that store", name))
	case target.TrustsPresentedChain == nil:
		return unanswered(store, fmt.Sprintf("it judges by %s, which could not be assessed", name))
	}
	return trustedByTheStore(store, *target, name)
}

// answered says whether a row gave the verdict asked about.
func answered(store *report.TrustStore, trusts bool) bool {
	return store != nil && store.TrustsPresentedChain != nil && *store.TrustsPresentedChain == trusts
}

// anchorsAreNotAsked takes back a refusal for want of a revocation address when
// the leaf signed itself.
//
// A LEAF THAT SIGNED ITSELF IS THE ANCHOR, AND AN ANCHOR IS NOT ASKED WHETHER IT
// WAS REVOKED. Measured with probe S25 on 2026-10-20: a root naming no
// revocation list let every chain under it through, on both curl builds. So such
// a leaf takes the store's answer like any other. Taking a self-signed leaf to be
// its own anchor is a JUDGEMENT about a shape S25 did not serve on its own.
func anchorsAreNotAsked(store report.TrustStore) report.TrustStore {
	if answered(&store, false) && store.TrustFailure == report.NoRevocationInfo {
		store.TrustsPresentedChain = nil
		store.TrustFailure = ""
	}
	return store
}

func refusedByTheStore(store, target report.TrustStore, name string) row {
	refused := false
	store.TrustsPresentedChain = &refused
	store.TrustFailure = target.TrustFailure
	store.TrustAnchorCount = target.TrustAnchorCount
	store.NotAssessed = ""
	return row{store: store, summary: fmt.Sprintf(
		"%s %s does NOT trust the presented chain (%d anchors) - it judges by %s, which refuses it",
		store.Runtime, store.Instance, store.TrustAnchorCount, name)}
}

// refusedByTheRuntime keeps a refusal the runtime is certain of whatever the
// store says.
//
// THE STORE'S ANCHOR COUNT TRAVELS ONLY WHEN THE STORE ANSWERED - the contract
// refuses a count nothing could have made.
func refusedByTheRuntime(store report.TrustStore, target *report.TrustStore) row {
	store.TrustAnchorCount = 0
	if target != nil && target.TrustsPresentedChain != nil {
		store.TrustAnchorCount = target.TrustAnchorCount
	}
	summary := fmt.Sprintf("%s %s does NOT accept the presented chain - %s", store.Runtime, store.Instance,
		store.TrustFailure.Meaning())
	if tolerate := tolerationOf(store); tolerate != "" {
		summary += " - " + tolerate
	}
	return row{store: store, summary: summary}
}

func unanswered(store report.TrustStore, why string) row {
	store.TrustsPresentedChain = nil
	store.TrustFailure = ""
	store.TrustAnchorCount = 0
	store.NotAssessed = why
	return row{store: store}
}

func trustedByTheStore(store, target report.TrustStore, name string) row {
	trusted := true
	store.TrustsPresentedChain = &trusted
	store.TrustAnchorCount = target.TrustAnchorCount
	store.NotAssessed = ""
	summary := fmt.Sprintf("%s %s trusts the presented chain (%d anchors) - it judges by %s",
		store.Runtime, store.Instance, store.TrustAnchorCount, name)
	if beyond := beyondTheStore(store); beyond != "" {
		summary += ", and " + beyond
	}
	return row{store: store, summary: summary}
}

// What one runtime does beyond the store it defers to, said where the row is
// written, with the source beside the words - inviolable rule 18. A runtime
// with no entry here gets the plain sentence, which claims nothing about it.
//
// CURL ON SCHANNEL. curl 8.21.0, lib/vtls/schannel.c, read 2026-10-20 at
// https://github.com/curl/curl/blob/curl-8_21_0/lib/vtls/schannel.c - with
// neither --ssl-no-revoke nor --ssl-revoke-best-effort the credential carries
// SCH_CRED_REVOCATION_CHECK_CHAIN, so Schannel checks revocation itself. And
// docs/cmdline-opts/ssl-revoke-best-effort.md of the same tag: the option
// ignores revocation checks that failed because the distribution points were
// missing or offline. Measured beside both with probe S25 on 2026-10-20, both
// curl builds on the owner's machine: a leaf naming no revocation list failed
// with CRYPT_E_NO_REVOCATION_CHECK, connected with --ssl-revoke-best-effort, and
// a leaf naming a list made curl fetch it.
const (
	schannelChecksOnline = "Schannel also checks revocation at the addresses the server's certificate names, " +
		"which this run does not contact"
	schannelTolerates = "curl connects with --ssl-revoke-best-effort, which tolerates a certificate that names " +
		"nowhere to check"
)

// beyondTheStore is what a deferring runtime checks that the store it defers
// to does not, when the store accepted the chain.
func beyondTheStore(store report.TrustStore) string {
	if onSchannel(store) {
		return schannelChecksOnline
	}
	return ""
}

// tolerationOf is how a runtime that refused for want of a revocation address
// can be told to accept the chain anyway.
func tolerationOf(store report.TrustStore) string {
	if onSchannel(store) && store.TrustFailure == report.NoRevocationInfo {
		return schannelTolerates
	}
	return ""
}

func onSchannel(store report.TrustStore) bool {
	return store.Runtime == "curl" && store.Backend == "schannel"
}
