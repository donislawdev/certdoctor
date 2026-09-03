// Package handshake is layer L4: what the server presents when the connection
// is upgraded to TLS.
//
// WHY THE PACKAGE IS NOT CALLED tls. The adapter behind it has to import
// crypto/tls, and a package of our own with the same name would force an alias
// at every such file - the trap docs/18 already recorded for layer.Context
// against context.Context, where the answer was "the layer gets a package named
// after what it does". This one establishes what was presented during the
// handshake, so that is its name.
//
// IT ANSWERS A NARROWER QUESTION THAN IT LOOKS, and the narrowing is the whole
// reason L5 exists separately. This layer says what the server SENT: which
// version and cipher were agreed, whether a client certificate was asked for,
// and which certificates arrived. It does NOT say whether anything on this
// machine trusts them - that is one answer per runtime, not one per connection,
// and a single "trusted" field here would quietly claim there is only one trust
// store on the machine. The entire product exists because there is not.
package handshake

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// Shake completes one TLS handshake against one address and reports what the
// server presented.
//
// IT IS DECLARED HERE RATHER THAN IMPORTED FROM THE ADAPTER, the same reason
// tcp.Connect and resolve.Exchange are: the core may not name a type from
// internal/adapter.
//
// THE PORT TRAVELS BESIDE THE ADDRESS RATHER THAN GLUED TO IT, for the reason
// L3 paid for once: the set of places this run may reach compares STRINGS, so
// the joining happens in one function next to the dialler, and the core never
// holds a second spelling.
//
// SERVER NAME IS SEPARATE FROM ADDRESS AND THAT IS THE POINT OF TLS. The name is
// what goes out in SNI and decides which certificate the server chooses; the
// address is where the packets go. Sending the address as the name would ask a
// virtual host for a certificate nobody issued.
type Shake func(ctx context.Context, address string, port int, serverName string) (Presented, error)

// The failures a caller of Shake has to be able to tell apart.
//
// THEY ARE SENTINELS RATHER THAN TYPES FROM THE ADAPTER, so the decision "which
// word does the report show" is made here, in the core, where it is testable
// without a network.
var (
	// ErrRefusedByRule - the allowed set refused this address, so nothing was
	// sent. A fact about us, never about their network.
	ErrRefusedByRule = errors.New("this address is not in the set of places this run may connect to")
	// ErrNotReached - the connection underneath never opened. L3 has already
	// reported why, and repeating its diagnosis here would count one fault twice.
	ErrNotReached = errors.New("the connection could not be opened")
	// ErrRejected - the connection opened and the server would not complete a
	// handshake on it. A fact about the server, not about its certificates.
	ErrRejected = errors.New("the server did not complete a TLS handshake")
	// ErrTimeout - nothing answered before the deadline.
	ErrTimeout = errors.New("nothing answered before the deadline")
)

// Certificate is one certificate as this program reports it.
//
// IT IS OUR OWN TYPE AND NOT crypto/x509's, deliberately. The core never parses
// a certificate: the adapter turns foreign bytes into these values, which is
// where parsing of somebody else's data belongs (docs/22 row 3). What arrives
// here is already a record with no code attached to it.
type Certificate struct {
	// Subject and Issuer are rendered by ONE function on the adapter side, and
	// that is what makes the completeness check below meaningful. Comparing two
	// distinguished names is only sound when both were spelled the same way -
	// the same reason tcp.Target exists one layer down.
	Subject string
	Issuer  string
	// NotBefore and NotAfter bound validity. They are reported rather than
	// judged against a trust store, which is L5's question.
	NotBefore time.Time
	NotAfter  time.Time
	// FingerprintSHA256 identifies this certificate exactly. It is the evidence
	// inviolable rule 21 requires to travel beside any claim about interception,
	// and it is never masked: it is the answer somebody came here for.
	FingerprintSHA256 string
	// DNSNames is what the certificate says it is FOR - the subjectAltName DNS
	// entries. It is the field a modern client matches on, and RFC 6125 section
	// 6.4.4 forbids matching on the common name when these are present, so a
	// record without them describes the certificate by its deprecated half.
	DNSNames []string
	// IsCA is the basic constraint, reported as presented.
	IsCA bool
	// Raw is this certificate exactly as it arrived, DER encoded.
	//
	// IT DOES NOT REACH THE REPORT AND MUST NOT: report.Certificate is a summary
	// built for people to read, and these bytes exist for L5, which cannot verify
	// a path from a summary. They travel BESIDE the summary rather than as a
	// second list, so the two cannot drift apart - the same reason the leaf
	// fingerprint is not stored twice.
	Raw []byte
	// SelfSigned is set when the certificate issued itself. It is computed on the
	// adapter side from the signature rather than from the names matching,
	// because a certificate can name itself as issuer without having signed it.
	SelfSigned bool
}

// Presented is everything one handshake established.
type Presented struct {
	// Completed says whether a handshake happened at all. Every field below it is
	// meaningless when this is false, and the layer refuses to fill them in - a
	// negotiated version on a handshake that never happened is a measurement of
	// something that did not occur.
	Completed bool
	// Version is the negotiated version as a name. IT IS THE ONE PLACE WHERE A
	// NAME RATHER THAN A NUMBER IS THE IDENTITY, and the reason is that the set is
	// closed and tiny - four standardised values - unlike the cipher registry.
	Version string
	// CipherSuite is the IANA number that came off the wire; CipherSuiteName is
	// the rendering of it. THE NUMBER IS THE FACT - inviolable rule 19 in its
	// clearest case, and a consumer branching on the name is doing what "never
	// parse somebody else's output by message text" forbids.
	//
	// BOTH NAMES ARE RENDERED BY THE STANDARD LIBRARY, IN THE ADAPTER, and never
	// by a table of ours. A hand-kept table would be a claim about somebody else's
	// registry that nothing keeps current - the class inviolable rule 18 is about.
	CipherSuite     uint16
	CipherSuiteName string
	// Protocol is what ALPN agreed, or empty when nothing was agreed.
	Protocol string
	// ServerName is what WE sent in SNI. It is ours, not theirs, and is recorded
	// so a reader can tell which name the certificate was chosen for.
	ServerName string
	// ClientCertificateRequested says the server asked us to authenticate. It is
	// one of the commonest causes of "works in the browser, fails in the tool"
	// and is invisible from a browser that has a certificate installed.
	ClientCertificateRequested bool
	// Chain is what the server sent, leaf first, exactly as presented. NOT what a
	// verifier would build: the gap between the two IS the diagnosis in the
	// commonest real misconfiguration there is.
	Chain []Certificate
}

// Input is everything one walk of L4 was handed.
type Input struct {
	// Addresses is where to connect, asked for AT WALK TIME rather than handed
	// over as a list - the same seam L3 uses, and for the same reason: these do
	// not exist when the entry point assembles everything else.
	Addresses func() []string
	// Port is the port to try, taken from the target URL.
	Port int
	// ServerName is the host from the target URL, sent in SNI.
	ServerName string
	// Shake is how a handshake is completed. A nil one refuses everything: a
	// forgotten port must read as a program that cannot ask.
	Shake Shake
	// Now is the clock, taken as a port so the budget arithmetic is testable
	// without waiting for real time.
	Now func() time.Time
	// PerAddress is the longest one attempt may take, capped by whatever is left
	// of the layer's own deadline - ADR44, decided for L3 and binding here for
	// the same reason.
	PerAddress time.Duration
}

// Result is what this layer establishes.
type Result struct {
	Status   status.Status
	Reason   status.Reason
	Detail   string
	Findings []report.Finding
	// Presented is the chain the report shows, DER encoded, leaf first - the seam
	// L5 reads. It is EMPTY when no handshake completed, and L5 treats that as
	// nothing to judge rather than as a store failing.
	Presented [][]byte
	// ChainWhole says whether the issuer of the leaf actually arrived - the
	// second half of the seam L5 reads, and the half that decides whether a store
	// can be given advice at all.
	//
	// MEASURED ON THE BENCH 2026-08-19, WHICH IS WHY IT TRAVELS. A server that
	// withholds its intermediate turns every trust store on the machine red, and
	// a command offered there sends somebody to edit a store that is perfectly
	// fine. L5 cannot work this out for itself without a second copy of the rule
	// two lines up, so it is handed the answer instead.
	//
	// It is false when nothing completed, which is correct rather than merely
	// convenient: no chain arrived, so no issuer did either.
	ChainWhole bool
	// Leaf is the summary of the certificate the chain starts with, and is nil
	// when no handshake completed - the third half of the seam L5 reads.
	//
	// IT IS THE RENDERED SUMMARY RATHER THAN THE BYTES, and the bytes are right
	// beside it in Presented. Naming who signed a chain needs an issuer and a
	// fingerprint, and both were rendered once already, on the adapter side, for
	// the report. Handing L5 the DER instead would put a second distinguished
	// name renderer in the tree - the measured shape of OBS50, and the exact way
	// a complete chain starts looking broken.
	Leaf *report.Certificate
}

// unlimited is what limitFor answers when nothing caps one attempt at all.
//
// The same collision, the same convention and the same measured reason as in L3:
// zero at the call site means "no time is left", while zero in PerAddress means
// the caller asked for NO LIMIT. OBS62 is what happens when one value carries
// both.
const unlimited time.Duration = -1

// Sentences for the cases where the layer establishes nothing.
const (
	noShake     = "no way to complete a handshake was supplied, so nothing about TLS was established"
	noClock     = "no clock was supplied, so the time each handshake took could not be established"
	noAddresses = "no way to learn the addresses was supplied, so this layer could not know what to connect to"
	// nothingToDo is what this layer says when the layer before it LOOKED and no
	// address accepted a connection.
	//
	// IT USED TO SAY THE NAME HAD RESOLVED TO NO ADDRESS, AND THAT WAS OFTEN
	// UNTRUE. Measured on this binary: a URL with a port outside the legal range
	// had L1 report four addresses, L3 thrown away for breaking its own contract,
	// and this layer announcing that the name resolved to nowhere. The sentence
	// described a layer two floors down, guessed at its result, and guessed wrong.
	nothingToDo = "no address accepted a connection, so there was nothing to hand shake with"
	// nothingEstablished is the other way this layer can be handed nothing, and
	// telling the two apart is ADR20 applied to a seam: an empty list is a
	// measurement, a nil one means the layer before this established nothing at
	// all - it never ran, or its answer was refused by its own contract.
	nothingEstablished = "nothing was established about which addresses accepted a connection, so there was nothing to hand shake with"
)

// Ask completes one handshake per address and reports what each server
// presented.
//
// ONE HANDSHAKE PER ADDRESS, AND THE FULL CHAIN PRINTED ONCE - ADR45. Measured
// on 2026-08-17 across example.com and cloudflare.com: every address of a name
// presented a byte-identical leaf, so agreement is the norm and the report is
// normally one chain plus a line per remaining address. When they disagree, that
// disagreement is the most important thing on the page - it is the only signal
// this program has for a middlebox sitting on one path and not another.
func Ask(ctx context.Context, in Input) Result {
	if broken := in.unusable(); broken != "" {
		return Result{Status: status.Unknown, Reason: status.ReasonProbeError, Detail: broken}
	}
	addresses := in.Addresses()
	if len(addresses) == 0 {
		// NOT A FAILURE OF THIS LAYER. The name resolving nowhere is L1's finding
		// and L3 already declines to repeat it; a third FAIL here would count one
		// fault three times in the verdict.
		detail := nothingToDo
		if addresses == nil {
			detail = nothingEstablished
		}
		return Result{Status: status.Unknown, Reason: status.ReasonNothingToCheck, Detail: detail}
	}

	shown, fell := in.fanOut(ctx, addresses)
	if fell != nil {
		// THE SAME RULE AS L3, AND crypto/tls IS WHY IT IS NEEDED HERE - R-1.
		// This layer hands somebody else's certificate to code this program does
		// not own, on a goroutine the orchestrator's recover cannot see.
		return Result{Status: status.Unknown, Reason: status.ReasonProbeError,
			Detail: "this layer could not finish: " + fell.Error()}
	}
	result := in.grade(addresses, shown)
	result.Presented = presentedOf(shown)
	result.Leaf = presentedLeafOf(shown)
	return result
}

// unusable names the port this layer was not given, or returns empty.
//
// A MISSING PORT IS OUR DEFECT AND SAYS SO. Reporting it as a server that cannot
// hand shake would accuse somebody else of our own omission - inviolable rule 15.
func (in Input) unusable() string {
	switch {
	case in.Shake == nil:
		return noShake
	case in.Now == nil:
		return noClock
	case in.Addresses == nil:
		return noAddresses
	}
	return ""
}

// limitFor is the longest this attempt may take: the per-address cap or what is
// left of the layer's budget, whichever is smaller - ADR44.
//
// THE SAME UNGUARDED CASE AS L3's, AND THE SAME ONE FUNCTION HOLDING IT SHUT.
// With neither a deadline on the context nor a PerAddress this answers
// unlimited, and a server that completes a TCP connection and then never speaks
// keeps the handshake open with nothing able to end it. Nothing in this package
// prevents that: budget() in cmd/certdoctor/flags.go does, by turning
// --timeout 0 into a day rather than into no deadline at all. Named here because
// the invariant lives two layers away and these ports are exported.
func (in Input) limitFor(ctx context.Context) time.Duration {
	deadline, set := ctx.Deadline()
	if !set {
		if in.PerAddress > 0 {
			return in.PerAddress
		}
		return unlimited
	}
	// THE CLOCK IS THE PORT AND NEVER time.Until, so the budget behaves the same
	// under test as in production - the one place a wrong measurement is
	// invisible.
	left := deadline.Sub(in.Now())
	if left <= 0 {
		return 0
	}
	if in.PerAddress > 0 && in.PerAddress < left {
		return in.PerAddress
	}
	return left
}

// attempt makes one handshake and returns what was presented, or why not.
func (in Input) attempt(ctx context.Context, address string) (Presented, error) {
	remaining := in.limitFor(ctx)
	if remaining == 0 {
		// NOT A TIMEOUT. Nothing was sent, so nothing failed to answer.
		return Presented{}, errNotAttempted
	}

	// AN UNLIMITED ATTEMPT GETS NO DEADLINE OF ITS OWN rather than a deadline of
	// zero - the whole of OBS62.
	attemptCtx := ctx
	if remaining > 0 {
		limited, cancel := context.WithTimeout(ctx, remaining)
		defer cancel()
		attemptCtx = limited
	}
	return in.Shake(attemptCtx, address, in.Port, in.ServerName)
}

// errNotAttempted is internal: it never reaches a report, it selects a row.
var errNotAttempted = errors.New("there was no budget left to try this address")

// chainComplete says whether the server sent enough to build a path.
//
// IT IS ANSWERED FROM THE PRESENTED BYTES ALONE AND NEEDS NO TRUST STORE, which
// is exactly why it belongs to L4 while trust belongs to L5 - ADR46. A leaf
// whose issuer is not among the certificates that arrived, and which did not
// sign itself, cannot be chained by anybody who does not already hold the
// missing certificate. That is the commonest real misconfiguration there is, and
// it is invisible from a browser that cached the intermediate elsewhere.
//
// AN EMPTY CHAIN IS NOT COMPLETE, and saying so explicitly matters: the zero
// value of a slice would otherwise sail through a loop that finds no
// counter-example and report a server that sent nothing as correctly configured.
func chainComplete(chain []Certificate) bool {
	if len(chain) == 0 {
		return false
	}
	leaf := chain[0]
	if leaf.SelfSigned {
		// It chains to itself. Whether anybody trusts that is L5's question.
		return true
	}
	for _, candidate := range chain[1:] {
		if candidate.Subject == leaf.Issuer {
			return true
		}
	}
	return false
}

// detailFor is the layer's one line.
func detailFor(completed, total int, chain []Certificate, complete bool, disagreed bool) string {
	switch {
	case completed == 0:
		return fmt.Sprintf("none of the %d address(es) completed a TLS handshake", total)
	case len(chain) == 0:
		// A HANDSHAKE COMPLETED AND NOTHING AUTHENTICATED THE SERVER. It has to
		// come before the branch below, which would otherwise describe a missing
		// issuer "of the first one" when there is no first one - chainComplete is
		// false for an empty chain, so that is exactly where this case landed
		// until 2026-09-04. Same untruth as the row sentence in summaryFor, one
		// level up, and found while fixing that one.
		//
		// THE STATUS IS STILL FAIL and this sentence does not soften it. ADR66
		// settled that such a handshake is LEGAL, which is a different question
		// from whether it answers the one this tool was asked: a server that
		// authenticates itself with nothing leaves every trust store on this
		// machine with nothing to judge.
		return fmt.Sprintf("%d of %d address(es) completed a handshake and presented no certificate, so nothing on this machine has anything to judge - this is a fact about the server rather than about this machine",
			completed, total)
	case !complete:
		return fmt.Sprintf("the server presented %d certificate(s) and did not send the issuer of the first one, so nothing can build a path to a root - this is a fact about the server rather than about this machine",
			len(chain))
	case disagreed:
		return fmt.Sprintf("%d of %d address(es) completed a handshake, and they did not all present the same certificate",
			completed, total)
	}
	return fmt.Sprintf("%d of %d address(es) completed a handshake and presented the same chain of %d certificate(s)",
		completed, total, len(chain))
}

// presentedOf returns the chain the report shows, DER encoded, for L5 to verify.
//
// IT PICKS THE SAME CHAIN THE REPORT DOES - the first address that completed a
// handshake, ADR45 - so what L5 judges and what a reader sees are the same
// certificates. Picking any other would produce a matrix about a chain nobody
// was shown.
// leafOf is the summary of the certificate the reported chain starts with.
//
// IT WALKS THE SAME OUTCOMES IN THE SAME ORDER AS presentedOf, so the leaf named
// here is the leaf of the chain shown there. Two different rules for "which
// address does the report describe" would let the fingerprint of one address
// travel with the chain of another - a mismatch nobody could see and everybody
// would believe.
// IT REUSES certificatesFor RATHER THAN COPYING THE FIELDS, so the leaf L5 is
// handed is summarised by the same rule as the leaf the report prints. A second
// copy of that mapping is the measured shape of OBS50.
func presentedLeafOf(outcomes []outcome) *report.Certificate {
	shown := firstShown(outcomes)
	if shown == nil {
		return nil
	}
	// NO LENGTH CHECK ON THE RESULT, and that is deliberate rather than
	// careless. certificatesFor returns one record per certificate handed to
	// it, and exactly one is handed to it here - so a guard would be a branch
	// nothing can execute, which is the shape the mutation register caught
	// twice in P3a: code that reads as caution and decides nothing.
	summarised := certificatesFor(shown.Chain[:1])
	return &summarised[0]
}

// firstShown is the rule for WHICH ADDRESS THE REPORT DESCRIBES, and it lives
// once because both things crossing the seam to L5 have to agree about it.
//
// A second copy would let the fingerprint of one address travel beside the chain
// of another - a mismatch nobody could see on the page and everybody would
// believe - and it is also the measured shape of OBS50, where a duplicated
// boundary rule disarmed three mutation entries while looking like tidying up.
// THE COMMENT ABOVE WAS TRUE OF THIS FILE AND FALSE OF THE PACKAGE UNTIL
// 2026-08-26. The grader picked the carrier a second time, one condition short
// of this one - it asked only whether the handshake completed - so a completed
// handshake that presented no certificate at all became the row the report
// called the carrier while the chain crossing the seam to L5 came from the next
// address. Exactly the mismatch this comment promises cannot happen, sitting
// forty lines away from it, and the measured shape of OBS50 for the fifth time.
// Both now consume carrierIndex.
func firstShown(outcomes []outcome) *Presented {
	i := carrierIndex(outcomes)
	if i < 0 {
		return nil
	}
	shown := outcomes[i].shown
	return &shown
}

// carrierIndex is the same rule expressed as a POSITION, because the two
// callers ask two halves of one question: the grader needs to know which row
// carries the chain, and this file needs to know what that row carries.
//
// A HANDSHAKE THAT COMPLETED AND PRESENTED NOTHING IS NOT A CARRIER. There is
// no leaf to identify it by, so a report naming it as the row that describes
// this server would print an empty chain beside a fingerprint that is not
// there. Such a row breaks the report contract on its own - it says the
// handshake completed and carries no leaf fingerprint - so this is not the
// place that reports it, only the place that stops it from deciding what
// everybody else sees.
func carrierIndex(outcomes []outcome) int {
	for i, o := range outcomes {
		if o.err != nil || !o.shown.Completed || len(o.shown.Chain) == 0 {
			continue
		}
		return i
	}
	return -1
}

func presentedOf(outcomes []outcome) [][]byte {
	if shown := firstShown(outcomes); shown != nil {
		raw := make([][]byte, 0, len(shown.Chain))
		for _, certificate := range shown.Chain {
			if len(certificate.Raw) > 0 {
				raw = append(raw, certificate.Raw)
			}
		}
		return raw
	}
	return nil
}
