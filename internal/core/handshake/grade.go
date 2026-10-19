package handshake

import (
	"errors"
	"fmt"

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
	disagreed := false

	// THE TWO OUTCOMES THAT NEVER LEFT THIS MACHINE, counted in the same walk as
	// everything else here - ADR58. Both are ours: one is this layer running out
	// of its own budget before an address came up, the other is our own allowed
	// set refusing the address.
	skipped, refused := 0, 0

	for i, o := range outcomes {
		matches := (*bool)(nil)
		switch {
		case o.err == nil && o.shown.Completed:
			completed++
			if i != carrier {
				same := leafOf(o.shown.Chain) == leafOf(firstChain)
				matches = &same
				if !same {
					disagreed = true
				}
			}
		case errors.Is(o.err, errNotAttempted):
			skipped++
		case errors.Is(o.err, ErrRefusedByRule):
			refused++
		}
		findings = append(findings, in.row(o, i == carrier, matches))
	}

	complete := chainComplete(firstChain)
	detail := detailFor(completed, len(addresses), firstChain, complete, disagreed)
	// ChainWhole travels on EVERY outcome, including the failing ones, because
	// L5 asks it in order to decide whether a store can be advised at all - and
	// the case it most needs it for is the FAIL below.
	graded := Result{Detail: detail, Findings: findings, ChainWhole: complete}

	switch {
	case completed == 0 && skipped+refused > 0:
		// A VERDICT AGAINST THESE SERVERS REQUIRES THAT THIS LAYER FINISHED
		// TRYING - ADR58. Both counts are ours: this layer running out of its own
		// budget, and our own allowed set refusing. With nothing completed and
		// some addresses never spoken to, FAIL says every server refused a
		// handshake - about servers nothing said hello to.
		//
		// ErrNotReached is deliberately NOT one of the two counted. L4 is handed
		// only the addresses L3 connected to, so it cannot ordinarily see one -
		// and if it ever does, L3 tried and failed, which is a fact about the
		// network rather than about our budget.
		graded.Status = status.Unknown
		graded.Reason = status.ReasonForNothingAttempted(skipped)
		graded.Detail = notFinishedDetail(skipped, refused, len(addresses))
	case completed == 0:
		graded.Status = status.Fail
	case !complete:
		// A FACT ABOUT THE SERVER, AND THE SENTENCE SAYS SO. Every runtime on this
		// machine will fail against this server and the answer is still "do
		// nothing here" - the one scenario where a verdict computed from the trust
		// matrix would point the reader at exactly the wrong machine.
		graded.Status = status.Fail
	default:
		graded.Status = status.Pass
	}
	return graded
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

// row turns one address's answer into one finding.
//
// IT ALWAYS PRODUCES A ROW, including for an address whose handshake never
// happened, because a report with fewer rows reads as a name with fewer
// addresses.
func (in Input) row(o outcome, carriesChain bool, matchesFirst *bool) report.Finding {
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
	}

	if carriesChain {
		body.ChainComplete = chainComplete(o.shown.Chain)
		body.Chain = certificatesFor(o.shown.Chain)
	}

	return report.Finding{
		Kind:         report.FindingTLSHandshake,
		Summary:      summaryFor(o.address, in.Port, o.shown, carriesChain, matchesFirst),
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
	switch {
	case err == nil:
		return "the handshake did not complete and no reason was given, which is a defect on our side"
	case errors.Is(err, errNotAttempted):
		return "there was no budget left to try this address"
	case errors.Is(err, ErrRefusedByRule):
		return "this address is not in the set of places this run may connect to"
	case errors.Is(err, ErrNotReached):
		return "the connection could not be opened, which layer L3 has already reported"
	case errors.Is(err, ErrTimeout):
		return "nothing answered before the deadline"
	}
	return "the server did not complete a TLS handshake"
}

// summaryFor is the sentence a surface prints when it has no special handling
// for this kind of finding.
func summaryFor(address string, port int, shown Presented, carriesChain bool, matchesFirst *bool) string {
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
	return fmt.Sprintf("%s on port %d presented the same certificate as the first address", address, port)
}
