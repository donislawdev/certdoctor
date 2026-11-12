package handshake

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// grade turns what each address presented into rows and one verdict.
//
// THE VERDICT IS STRUCTURAL AND NOTHING HERE CONSULTS A TRUST STORE - ADR46.
// "Did a handshake happen" and "did the server send enough to build a path" are
// both answered from bytes that arrived. "Does this machine trust it" is one
// answer per runtime and belongs to L5; answering it here would quietly claim
// the machine has one trust store, and the whole product exists because it does
// not.
func (in Input) grade(addresses []string, outcomes []outcome) Result {
	findings := make([]report.Finding, 0, len(addresses))

	completed := 0
	// ONE ROW CARRIES THE CHAIN AND THE OTHERS DO NOT - ADR45. Four chains of
	// four certificates is a page nobody reads, and the difference between them
	// is visible from the fingerprint alone.
	//
	// WHICH ROW THAT IS COMES FROM carrierIndex RATHER THAN FROM A SECOND COPY
	// OF THE RULE HERE, AND THE COPY IS WHAT WAS WRONG - 2026-08-26. This asked
	// only whether the handshake completed; the seam to L5 asks that AND whether
	// anything was presented. A handshake that completed without a certificate
	// therefore became the row the report called the carrier, while the chain
	// handed to L5 came from the address after it - the mismatch firstShown's
	// own comment promises cannot happen, and the measured shape of OBS50.
	carrier := carrierIndex(outcomes)
	var firstChain []Certificate
	if carrier >= 0 {
		firstChain = outcomes[carrier].shown.Chain
	}
	// THE WHOLE CHAIN IS COMPARED, NOT THE LEAF ALONE - ADR114, B02, decided by
	// the owner. Two addresses presenting one certificate under two different
	// intermediates are two different answers to a client, and the leaf alone
	// called them the same. others counts the completed addresses whose chain is
	// not the one L5 judges, and travels to L5 so its sentence can say so.
	others := 0

	// THE OUTCOMES NO SERVER CAN BE BLAMED FOR, counted in the same walk as
	// everything else here - ADR58, ADR129 and NotOpened.
	var missed unheard

	// EVERY LEAF IS ASKED ABOUT THE NAME, NOT ONLY THE CARRIER'S - ADR106. Each
	// address presented its own, and one path handing out a certificate for a
	// different name is exactly what a client on that path will refuse.
	names := nameTally{host: in.ServerName}

	for i, o := range outcomes {
		// MatchesFirstAddress KEEPS ITS PUBLISHED MEANING, the same certificate,
		// and the chain is compared beside it: a field consumers already read
		// would otherwise change what it says under the same name.
		matches := (*bool)(nil)
		sameChain := true
		switch {
		case o.err == nil && o.shown.Completed:
			completed++
			names.count(o.shown)
			if i != carrier {
				same := leafOf(o.shown.Chain) == leafOf(firstChain)
				matches = &same
				sameChain = chainsEqual(o.shown.Chain, firstChain)
				if !sameChain {
					others++
				}
			}
		default:
			missed.count(o.err)
		}
		findings = append(findings, in.row(o, i == carrier, matches, sameChain))
	}

	complete := chainComplete(firstChain)
	detail := detailFor(completed, len(addresses), firstChain, complete, others > 0, names)
	// ChainWhole travels on EVERY outcome, including the failing ones, because
	// L5 asks it in order to decide whether a store can be advised at all - and
	// the case it most needs it for is the FAIL below.
	graded := Result{Detail: detail, Findings: findings, ChainWhole: complete, OtherChains: others}
	if completed == 0 && missed.settle(&graded, len(addresses)) {
		return graded
	}

	switch {
	// THREE FAILURES, ONE BRANCH - the sentence above them, from detailFor, is
	// what tells them apart.
	//
	// A HANDSHAKE THAT PRESENTED NO CERTIFICATE leaves every store with nothing
	// to judge - ADR66 made it legal and left it failing.
	//
	// A NAME THE LEAF DOES NOT COVER is a fact about the server or about the
	// name, and never about this machine - ADR106. Every client refuses it
	// whatever its trust store holds, which is why it is asked here and not in
	// L5: there, every store would say it does not trust a chain it trusts
	// perfectly well.
	case completed == 0, len(firstChain) == 0, names.notCovered > 0:
		graded.Status = status.Fail
	// THREE WARNINGS, ONE BRANCH, all decided by the owner.
	//
	// AN ISSUER THE SERVER DID NOT SEND - ADR114. The bytes cannot tell a
	// missing intermediate from a root left out on purpose, and a client that
	// already holds the issuer builds a path, so this layer says what arrived
	// and L5 says who can. When no store here builds one, the verdict still
	// names the server - causeOf in the report package.
	//
	// A NAME ONLY IN THE COMMON NAME - ADR106: a client written to RFC 6125 may
	// still accept it, so whether this works depends on which client is asking.
	//
	// ADDRESSES THAT PRESENTED DIFFERENT CHAINS - ADR114, B02. L5 judges one of
	// them, so a run can pass on the address that happened to come first while
	// a client sent to another refuses. The matrix per chain is for after 0.1.0,
	// because it changes the shape of --json.
	case !complete, names.commonOnly > 0, others > 0:
		graded.Status = status.Warn
	default:
		graded.Status = status.Pass
	}
	return graded
}

// unheard counts, by reason, the addresses that gave this layer no answer it
// can hold against a server: three of the reasons are on our side, and the
// fourth is a handshake the wire never let start.
type unheard struct {
	// skipped and refused NEVER LEFT THIS MACHINE - ADR58: this layer running
	// out of its own budget before an address came up, and our own allowed set
	// refusing the address.
	skipped, refused int
	// ended LEFT THIS MACHINE AND WAS ENDED BY IT - ADR129: our own TLS library
	// stopped the handshake. first is the first such address's account, the one
	// the layer's line quotes.
	ended int
	first EndedHere
	// unopened ACCEPTED L3's CONNECTION AND NOT THIS LAYER'S - NotOpened. No
	// handshake was started with them, so nothing they said can be held against
	// their TLS. firstUnopened is the first such address's account.
	unopened      int
	firstUnopened NotOpened
}

// count records one address that did not complete a handshake.
//
// ErrRejected and ErrTimeout are NOT counted: they are what the server, or the
// network in front of it, answered to a handshake this layer started.
func (u *unheard) count(err error) {
	var ended EndedHere
	var unopened NotOpened
	switch {
	case errors.Is(err, errNotAttempted):
		u.skipped++
	case errors.Is(err, ErrRefusedByRule):
		u.refused++
	case errors.As(err, &ended):
		if u.ended == 0 {
			u.first = ended
		}
		u.ended++
	case errors.As(err, &unopened):
		if u.unopened == 0 {
			u.firstUnopened = unopened
		}
		u.unopened++
	}
}

// settle answers for a layer where no handshake completed, when some address
// gave no answer that can be held against its server, and says whether it did.
func (u unheard) settle(graded *Result, addresses int) bool {
	switch {
	case u.skipped+u.refused > 0:
		// A VERDICT AGAINST THESE SERVERS REQUIRES THAT THIS LAYER FINISHED
		// TRYING - ADR58. Both counts are ours. With nothing completed and some
		// addresses never spoken to, FAIL says every server refused a handshake -
		// about servers nothing said hello to.
		graded.Status = status.Unknown
		graded.Reason = status.ReasonForNothingAttempted(u.skipped)
		graded.Detail = notFinishedDetail(u.skipped, u.refused, addresses)
	case u.ended > 0:
		// THE SAME RULE ONE STEP FURTHER - ADR129. These addresses were spoken
		// to, and it was our own library that stopped: on the bench every other
		// client completed the handshake it ended, so FAIL would blame a server
		// for an answer we could not read.
		graded.Status = status.Unknown
		graded.Reason = status.ReasonUndetermined
		graded.Detail = endedDetail(u.ended, addresses, u.first.Words)
	case u.unopened > 0:
		// NO HANDSHAKE WAS STARTED WITH THESE ADDRESSES - NotOpened. The same
		// argument as ADR58: a verdict against a server's TLS requires that this
		// layer got to ask, and here it did not. The reason is the wire's, which is
		// what transport_error says.
		graded.Status = status.Unknown
		graded.Reason = status.ReasonTransportError
		graded.Detail = unopenedDetail(u.unopened, addresses, u.firstUnopened.Words)
	default:
		return false
	}
	return true
}

// nameTally is what the leaves of every completed address said about the name
// this run asked for.
type nameTally struct {
	host string
	// withLeaf counts the addresses that presented a leaf at all, so a sentence
	// can say "2 of 3" rather than claiming every address did the same.
	withLeaf   int
	notCovered int
	commonOnly int
	// first is the first leaf in address order that did not cover the name,
	// or that covered it only through the common name - the one the sentence
	// quotes. Address order puts the carrier first when it is one of them, so
	// the sentence and the chain on the page describe one certificate.
	first *Certificate
}

// count records one completed address.
func (n *nameTally) count(presented Presented) {
	if len(presented.Chain) == 0 {
		return
	}
	n.withLeaf++
	switch presented.Name {
	case NameNotCovered:
		if n.notCovered == 0 {
			// A NOT-COVERED LEAF TAKES THE SENTENCE FROM A COMMON-NAME ONE: the
			// failure is what the layer reports, so it is what gets quoted.
			n.first = &presented.Chain[0]
		}
		n.notCovered++
	case NameInCommonNameOnly:
		if n.first == nil {
			n.first = &presented.Chain[0]
		}
		n.commonOnly++
	}
}

// coveredOf is the report's answer for one row: nil where nothing was checked,
// and the common-name case reported as not covered, because by the rules in
// force it is not - RFC 9525 section 2.
func coveredOf(match NameMatch) *bool {
	var covered bool
	switch match {
	case NameCovered:
		covered = true
	case NameInCommonNameOnly, NameNotCovered:
		covered = false
	default:
		return nil
	}
	return &covered
}

// namesOn lists what a certificate says it is for, for a sentence: the DNS
// names, then the addresses, at most three of them.
//
// CAPPED, BECAUSE A SHARED CERTIFICATE CARRIES HUNDREDS. The full list of DNS
// names is in the chain on the same page; this sentence is the one the verdict
// quotes, and OBS165 measured what a line of four hundred characters does to a
// terminal.
func namesOn(c Certificate) string {
	all := append(append([]string{}, c.DNSNames...), c.IPAddresses...)
	const shown = 3
	if len(all) <= shown {
		return strings.Join(all, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(all[:shown], ", "), len(all)-shown)
}

// nameDetail is the layer's sentence when a leaf does not cover the name, or
// covers it only through the common name - empty when neither happened.
func nameDetail(n nameTally) string {
	if n.first == nil {
		return ""
	}
	who := "the server"
	affected := n.notCovered
	if affected == 0 {
		affected = n.commonOnly
	}
	if affected < n.withLeaf {
		who = fmt.Sprintf("%d of %d address(es)", affected, n.withLeaf)
	}

	if n.notCovered == 0 {
		return fmt.Sprintf("%s presented a certificate with no subjectAltName, naming %s only in its common name - "+
			"clients following RFC 9525 refuse that and older ones may still accept it, so whether this connection "+
			"works depends on the client", who, n.host)
	}

	const consequence = " - clients refuse that whatever they trust, so this is a fact about the server or about the name used to reach it"
	listed := namesOn(*n.first)
	switch {
	case listed == "":
		return fmt.Sprintf("%s presented a certificate with no host name or address in its subjectAltName, so nothing in it covers %s",
			who, n.host) + consequence
	case len(n.first.DNSNames)+len(n.first.IPAddresses) == 1:
		return fmt.Sprintf("%s presented a certificate for %s, and that does not cover %s", who, listed, n.host) + consequence
	}
	return fmt.Sprintf("%s presented a certificate for %s, and none of those names covers %s", who, listed, n.host) + consequence
}

// nameClause is what one row adds to its own summary when its leaf does not
// fit the name, so that every surface printing summaries shows it - parity
// rule 12 - and not only the --json reader of name_covered.
//
// SILENT WHEN THE NAME IS COVERED, the way a complete chain is: the ordinary
// case needs no sentence, and a clause on every healthy row would bury the one
// that is not.
func nameClause(match NameMatch, host string) string {
	switch match {
	case NameNotCovered:
		return ", and its certificate does not cover " + host
	case NameInCommonNameOnly:
		return ", and its certificate names " + host + " only in its common name"
	}
	return ""
}

// notFinishedDetail says no handshake completed and this layer did not finish
// trying - the same shape, and the same argument, as the sentence the
// connecting layer uses.
func notFinishedDetail(skipped, refused, addresses int) string {
	var why string
	switch {
	case refused == 0:
		why = fmt.Sprintf("%d of %d were never spoken to, because this layer ran out of its own time budget first",
			skipped, addresses)
	case skipped == 0:
		why = fmt.Sprintf("%d of %d were never spoken to, because this run's own rule about where it may connect refused them",
			refused, addresses)
	default:
		why = fmt.Sprintf("%d of %d were never spoken to because this layer ran out of its own time budget, and %d more "+
			"were refused by this run's own rule about where it may connect", skipped, addresses, refused)
	}
	return "no address completed a TLS handshake, and this layer did not finish trying: " + why +
		" - so this is a limit of this run rather than a finding about those servers"
}

// leafOf is the fingerprint that identifies what a server presented, or empty.
func leafOf(chain []Certificate) string {
	if len(chain) == 0 {
		return ""
	}
	return chain[0].FingerprintSHA256
}

// chainsEqual says whether two chains are the same certificates in the same
// order, by fingerprint - ADR114, B02.
//
// THE ORDER IS PART OF THE ANSWER. TLS 1.2 required each certificate to certify
// the one before it, RFC 5246 section 7.4.2, so a client written to it can
// refuse on one address the chain it accepts on another.
func chainsEqual(a, b []Certificate) bool {
	return slices.EqualFunc(a, b, func(x, y Certificate) bool { return x.FingerprintSHA256 == y.FingerprintSHA256 })
}

// row turns one address's answer into one finding.
//
// IT ALWAYS PRODUCES A ROW, including for an address whose handshake never
// happened, because a report with fewer rows reads as a name with fewer
// addresses.
func (in Input) row(o outcome, carriesChain bool, matchesFirst *bool, sameChain bool) report.Finding {
	body := &report.TLSHandshake{
		Address:   o.address,
		Port:      in.Port,
		Completed: o.err == nil && o.shown.Completed,
	}

	if !body.Completed {
		// NOTHING WAS NEGOTIATED, SO NOTHING IS FILLED IN. A version or a cipher
		// beside a handshake that did not happen is a measurement of something
		// that did not occur - the same rule that keeps a duration off a
		// connection which never left this machine.
		body.NotCompleted = reasonFor(o.err)
		return report.Finding{
			Kind:         report.FindingTLSHandshake,
			Summary:      fmt.Sprintf("%s on port %d: %s", o.address, in.Port, body.NotCompleted),
			Source:       report.SourceDetected,
			TLSHandshake: body,
		}
	}

	body.Version = o.shown.Version
	body.CipherSuite = o.shown.CipherSuite
	body.CipherSuiteName = o.shown.CipherSuiteName
	body.ALPN = o.shown.Protocol
	body.ServerName = o.shown.ServerName
	body.ClientCertificateRequested = o.shown.ClientCertificateRequested
	body.LeafFingerprintSHA256 = leafOf(o.shown.Chain)
	// THE COMPARISON EXISTS ONLY WHERE THERE IS SOMETHING TO COMPARE - OBS78. A
	// handshake that completed and presented no certificate is legal, and saying
	// it presented "the same certificate as the first address" would be a
	// measurement of two things neither of which happened.
	if body.LeafFingerprintSHA256 != "" {
		body.MatchesFirstAddress = matchesFirst
		body.NameCovered = coveredOf(o.shown.Name)
	}

	if carriesChain {
		body.ChainComplete = chainComplete(o.shown.Chain)
		body.Chain = certificatesFor(o.shown.Chain)
	}

	return report.Finding{
		Kind:         report.FindingTLSHandshake,
		Summary:      summaryFor(o.address, in.Port, o.shown, carriesChain, matchesFirst, sameChain) + nameClause(o.shown.Name, in.ServerName),
		Source:       report.SourceDetected,
		TLSHandshake: body,
	}
}

// certificatesFor carries the chain across into the report's own type.
func certificatesFor(chain []Certificate) []report.Certificate {
	out := make([]report.Certificate, 0, len(chain))
	for _, c := range chain {
		out = append(out, report.Certificate{
			Subject:           c.Subject,
			Issuer:            c.Issuer,
			NotBefore:         c.NotBefore,
			NotAfter:          c.NotAfter,
			FingerprintSHA256: c.FingerprintSHA256,
			DNSNames:          c.DNSNames,
			IsCA:              c.IsCA,
			SelfSigned:        c.SelfSigned,
		})
	}
	return out
}

// reasonFor is the short English phrase a row shows when no handshake happened.
//
// IT NEVER CLAIMS TO KNOW MORE THAN IT DOES. An unanticipated failure reads as
// "the server did not complete a handshake" rather than as one of the specific
// diagnoses, because each of those sends a person somewhere particular.
func reasonFor(err error) string {
	var ended EndedHere
	var unopened NotOpened
	switch {
	case err == nil:
		return "the handshake did not complete and no reason was given, which is a defect on our side"
	case errors.Is(err, errNotAttempted):
		return "there was no budget left to try this address"
	case errors.Is(err, ErrRefusedByRule):
		return "this address is not in the set of places this run may connect to"
	case errors.As(err, &unopened):
		return "layer L3 connected to this address, and " + unopened.Error()
	case errors.Is(err, ErrTimeout):
		return "nothing answered before the deadline"
	case errors.As(err, &ended):
		return ended.Error() + undecided
	}
	return "the server did not complete a TLS handshake"
}

// undecided is what a handshake this program's own library ended leaves open -
// ADR129. Other clients read certificates by other rules, and on the bench every
// one of them completed the handshake this program's library would not.
const undecided = ", so whether another client would complete it cannot be told here"

// endedDetail is the layer's line when no handshake completed and this
// program's own library ended at least one of them - ADR129.
//
// THE COUNT IS OF THE ADDRESSES OUR LIBRARY ENDED, and the rows beside it say
// what happened on the rest. The words quoted are the first such address's.
func endedDetail(ended, total int, words string) string {
	return fmt.Sprintf("this program's own TLS library ended the handshake with %d of %d address(es) itself (%s)",
		ended, total, words) + undecided
}

// unopenedDetail is the layer's line when no handshake completed and the
// connection made for it did not open on at least one address L3 had reached -
// NotOpened.
//
// IT IS WRITTEN TO STAND AT THE TOP OF THE REPORT, where the verdict quotes it,
// so it names layer L3 rather than "this layer". The advice is the one thing a
// reader can do about a moment on the wire, and the first run that met this
// case got its answer on the second.
func unopenedDetail(unopened, total int, words string) string {
	return fmt.Sprintf("no TLS handshake could start with %d of %d address(es): layer L3 connected to them, "+
		"and the second connection made for the handshake did not open (%s) - so what the server presents "+
		"was not established, and running the diagnosis again may get further", unopened, total, words)
}

// summaryFor is the sentence a surface prints when it has no special handling
// for this kind of finding.
func summaryFor(address string, port int, shown Presented, carriesChain bool, matchesFirst *bool, sameChain bool) string {
	// NOTHING WAS PRESENTED, SO NOTHING IS COMPARED - the same rule the body
	// already obeys through MatchesFirstAddress, arriving here two weeks late.
	//
	// OBS78 stopped this row from CARRYING a comparison and left it SAYING one.
	// With no address presenting a certificate there is no carrier, so every
	// completed row is measured against an empty chain, leafOf(nil) equals
	// leafOf(nil), and the sentence read "presented the same certificate as the
	// first address" - naming a certificate that does not exist and an address
	// that was never chosen. The mirror case is no better: a row holding nothing
	// beside a carrier that holds something read "presented a DIFFERENT
	// certificate", which still claims this address presented one.
	//
	// It goes FIRST, before carriesChain, and that ordering is free rather than
	// load-bearing: carrierIndex will not name a row with an empty chain, so the
	// two conditions cannot both be true. It is written this way so that a later
	// change to carrierIndex cannot produce "presented 0 certificate(s)".
	if len(shown.Chain) == 0 {
		return fmt.Sprintf("%s on port %d completed a handshake and presented no certificate", address, port)
	}
	if carriesChain {
		return fmt.Sprintf("%s on port %d presented %d certificate(s)", address, port, len(shown.Chain))
	}
	if matchesFirst != nil && !*matchesFirst {
		return fmt.Sprintf("%s on port %d presented a DIFFERENT certificate from the first address", address, port)
	}
	if !sameChain {
		// THE CASE THE LEAF ALONE HID - ADR114, B02: one certificate, under
		// intermediates that are not the first address's.
		return fmt.Sprintf("%s on port %d presented the same certificate as the first address, in a DIFFERENT chain", address, port)
	}
	return fmt.Sprintf("%s on port %d presented the same chain as the first address", address, port)
}
