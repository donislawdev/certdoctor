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
	first := -1
	var firstChain []Certificate
	disagreed := false

	for i, o := range outcomes {
		matches := (*bool)(nil)
		if o.err == nil && o.shown.Completed {
			completed++
			if first < 0 {
				// THE FIRST COMPLETED HANDSHAKE CARRIES THE CHAIN AND THE OTHERS DO
				// NOT - ADR45. Four chains of four certificates is a page nobody
				// reads, and the difference between them is visible from the
				// fingerprint alone.
				first = i
				firstChain = o.shown.Chain
			} else {
				same := leafOf(o.shown.Chain) == leafOf(firstChain)
				matches = &same
				if !same {
					disagreed = true
				}
			}
		}
		findings = append(findings, in.row(o, i == first, matches))
	}

	complete := chainComplete(firstChain)
	detail := detailFor(completed, len(addresses), firstChain, complete, disagreed)
	// ChainWhole travels on EVERY outcome, including the failing ones, because
	// L5 asks it in order to decide whether a store can be advised at all - and
	// the case it most needs it for is the FAIL below.
	graded := Result{Detail: detail, Findings: findings, ChainWhole: complete}

	switch {
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
	body.MatchesFirstAddress = matchesFirst

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
	if carriesChain {
		return fmt.Sprintf("%s on port %d presented %d certificate(s)", address, port, len(shown.Chain))
	}
	if matchesFirst != nil && !*matchesFirst {
		return fmt.Sprintf("%s on port %d presented a DIFFERENT certificate from the first address", address, port)
	}
	return fmt.Sprintf("%s on port %d presented the same certificate as the first address", address, port)
}
