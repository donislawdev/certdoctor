package run

import (
	"context"

	"github.com/donislawdev/certdoctor/internal/core/handshake"
	"github.com/donislawdev/certdoctor/internal/core/layer"
	"github.com/donislawdev/certdoctor/internal/core/machine"
	"github.com/donislawdev/certdoctor/internal/core/proxy"
	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/resolve"
	"github.com/donislawdev/certdoctor/internal/core/status"
	"github.com/donislawdev/certdoctor/internal/core/tcp"
	"github.com/donislawdev/certdoctor/internal/core/trust"
)

// Wire returns the behaviour of all eight layers: the ones that are written
// doing their work, and the rest saying they are not written.
//
// IT IS BUILT ON TOP OF NotImplemented RATHER THAN BESIDE IT. The unwritten
// layers keep answering exactly as before, and a ninth layer added to the
// registry still cannot appear in the report without a row, because the base is
// still built from the registry rather than listed here by hand. What this
// function adds is the short list of layers that have grown code.
//
// The environment is a parameter and not something read here, because nothing
// below the entry point is allowed to reach the operating system. Passing nil is
// legal and is not silently ignored: L0 reports that it could not look, with a
// reason, which is the answer that cannot be mistaken for a clean result.
// Wiring is everything Wire needs, as one value rather than a parameter list
// that grows by one every time a layer is written.
type Wiring struct {
	// Environment is how L0 reads this machine's variables.
	Environment machine.Lookup
	// Resolution is everything L1 was given by the entry point.
	Resolution resolve.Input
	// Proxy is everything L2 was given.
	//
	// IT NEEDS NOTHING FROM THE LAYER ABOVE IT, which is why there is no seam
	// here and why this field is complete when the entry point builds it. What a
	// machine keeps in its proxy settings does not depend on what a name resolved
	// to, so wiring one to the other would weld two layers together for no
	// answer.
	Proxy proxy.Input
	// Reach is everything L3 was given, EXCEPT the addresses: those do not exist
	// until L1 has run, and Wire supplies them below.
	Reach tcp.Input
	// Handshake is everything L4 was given, EXCEPT the addresses. The same seam
	// again, one layer further along: L3 produces them and Wire supplies them.
	//
	// ITS ServerName MUST BE THE RAW HOST FROM THE TARGET, never the masked one.
	// That name goes out in SNI and decides which certificate the server chooses,
	// so a run under --redact would otherwise ask every server on earth for a
	// certificate issued to [host-1].
	Handshake handshake.Input
	// Trust is everything L5 was given, EXCEPT the presented chain: that does not
	// exist until L4 has run, and Wire supplies it below. The same seam a third
	// time, which is the point - no layer learns the shape of the one above it.
	Trust trust.Input
	// Authorise is told the addresses L1 found, before L3 is asked to connect to
	// any of them.
	//
	// IT IS A FUNCTION FROM THE ENTRY POINT BECAUSE THE SET OF PLACES THIS RUN
	// MAY REACH IS ASSEMBLED THERE - inviolable rule 16 - and because turning an
	// address into something dialable means joining it to a port, which is work
	// this package may not do: internal/app may not import net, and the layer
	// guard says so by name.
	//
	// A nil one is legal and means nothing is authorised, so L3 refuses every
	// address and says which rule refused it. That is the safe direction: a
	// forgotten wire cannot widen what this program may reach.
	Authorise func([]string)
}

// Wire returns the behaviour of all eight layers: the ones that are written
// doing their work, and the rest saying they are not written.
//
// IT IS BUILT ON TOP OF NotImplemented RATHER THAN BESIDE IT. The unwritten
// layers keep answering exactly as before, and a ninth layer added to the
// registry still cannot appear in the report without a row, because the base is
// still built from the registry rather than listed here by hand.
//
// THE ONE PIECE OF STATE HERE IS THE SEAM BETWEEN TWO LAYERS, and it is worth
// knowing about before anything in this walk goes parallel. L1 finds the
// addresses; L3 connects to them; they exist only in between. The orchestrator
// walks layers in registry order, sequentially - ADR15 - so L1 has finished
// before L3 is called, and that ORDER IS NOW LOAD-BEARING rather than an
// implementation detail. A test pins it.
//
// The alternative was for L3 to import L1 and ask it directly, which needs no
// state and welds the two layers together: L3 would then know how a DNS answer
// is shaped, and neither could move without the other.
func Wire(w Wiring) Layers {
	layers := NotImplemented()
	layers[layer.Context] = func(context.Context) Answer {
		return answerFrom(machine.Read(w.Environment))
	}

	var resolved []string
	// L1 receives a context carrying the layer's deadline, which is where its
	// budget arithmetic starts. Everything else it needs arrived in the Input the
	// entry point built - the ports, the raw host, and this machine's resolvers,
	// which had to be enumerated before the walk so the masking could be told
	// about them.
	layers[layer.Resolution] = func(ctx context.Context) Answer {
		result := resolve.Ask(ctx, w.Resolution)
		answer := answerFromResolution(result)
		// NOTHING CROSSES A SEAM UNTIL THE ANSWER HAS SURVIVED ITS OWN CONTRACT,
		// AND HERE THAT IS NOT TIDINESS - IT IS INVIOLABLE RULE 16.
		//
		// The orchestrator judges this answer AFTER this function returns, and an
		// answer that breaks the contract has every finding thrown away and the
		// layer reported as "nothing it reported was used". This used to widen the
		// set of places this program may connect to from that same answer: a layer
		// the run had just called unusable was still deciding where the run may
		// dial. Whatever else that set is, it cannot be built out of data the
		// program itself refused.
		if contractBreach(answer) != "" {
			return answer
		}
		resolved = result.Addresses
		// AUTHORISED HERE, BEFORE L3 EXISTS AS A POSSIBILITY, and never inside
		// L3 itself. A layer that adds its own targets to the allowed set is a
		// layer permitting itself, which would make the set a description of what
		// happened rather than a rule about what may.
		if w.Authorise != nil {
			w.Authorise(resolved)
		}
		return answer
	}

	// L2 IS THE ONE WRITTEN LAYER WITH NO SEAM ON EITHER SIDE OF IT, and that is
	// worth noticing rather than passing over. It reads this machine's own
	// configuration, which nothing above it produces and nothing below it
	// consumes: L3 connects to the addresses L1 found whether a proxy is
	// configured or not, because reading a proxy variable must never change where
	// this program connects - docs/14 section 3, checked from outside by the
	// bench.
	layers[layer.Proxy] = func(ctx context.Context) Answer {
		return answerFromProxy(proxy.Ask(ctx, w.Proxy))
	}

	// THE SECOND SEAM, AND IT IS DELIBERATELY THE SAME SHAPE AS THE FIRST. L3
	// answers which addresses accepted a connection; L4 hand shakes with those
	// and no others - ADR45. An address that refused has nothing to hand shake
	// with, and a row about it would report our own arithmetic as a fact about
	// somebody's TLS.
	var connected []string
	reach := w.Reach
	reach.Addresses = func() []string { return resolved }
	layers[layer.TCP] = func(ctx context.Context) Answer {
		result := tcp.Ask(ctx, reach)
		answer := answerFromReach(result)
		// The same gate, for the same reason, and here it also keeps L4 from
		// being handed an empty list by a layer that was thrown away - which
		// reads to L4 exactly like "nobody accepted a connection".
		if contractBreach(answer) != "" {
			return answer
		}
		connected = result.Connected
		return answer
	}

	var presented [][]byte
	var whole bool
	var leaf *report.Certificate
	shake := w.Handshake
	shake.Addresses = func() []string { return connected }
	layers[layer.TLS] = func(ctx context.Context) Answer {
		result := handshake.Ask(ctx, shake)
		answer := answerFromHandshake(result)
		// The same gate again. A chain that came back inside an answer this run
		// refused is a chain no store should be asked about, and L5 would have
		// judged it without ever learning where it came from.
		if contractBreach(answer) != "" {
			return answer
		}
		presented, whole, leaf = result.Presented, result.ChainWhole, result.Leaf
		return answer
	}

	// THE THIRD SEAM. L4 says what the server presented, L5 says what each store
	// on this machine makes of it - and it judges the SAME chain the report shows,
	// never a different one. An empty slice means no handshake completed, which L5
	// reports as nothing to judge rather than as a store failing.
	//
	// IT ALSO CARRIES WHETHER THAT CHAIN WAS WHOLE, and that half is what keeps a
	// remediation command off a row that is red through no fault of this machine.
	// Both are read at walk time from the same run of L4, so they cannot describe
	// two different handshakes.
	// IT ALSO CARRIES THE LEAF ITSELF, rendered once by L4 rather than twice.
	// Who signed a chain is a question about that one certificate, and the
	// issuer and fingerprint the report already shows are the answer.
	trusted := w.Trust
	trusted.PresentedChain = func() [][]byte { return presented }
	trusted.ChainComplete = func() bool { return whole }
	trusted.PresentedLeaf = func() *report.Certificate { return leaf }
	layers[layer.TrustMatrix] = func(ctx context.Context) Answer {
		return answerFromTrust(trust.Ask(ctx, trusted))
	}
	return layers
}

// answerFrom carries a core result across into what the orchestrator expects.
//
// IT IS THE WHOLE OF THE BOUNDARY AND IT DELIBERATELY DOES NOTHING ELSE. It does
// not mask, because evidence crosses this line raw and the assembly path takes
// credentials out of it once - ADR18. It does not grade, because the grade was
// worked out in the core where it can be tested on recorded evidence - ADR7. And
// it does not attach an identifier, because a layer never gets to say which
// layer it is; the orchestrator reads that off the registry.
//
// The findings slice is passed along as it is, nil and all. Nil means the layer
// did not look and an empty slice means it looked and found nothing, and the
// orchestrator's own copy is what keeps those two apart from here on - ADR20.
func answerFrom(result machine.Result) Answer {
	return answerOf(result.Status, result.Reason, result.Detail, result.Findings)
}

// answerFromResolution is the same boundary for L1.
//
// EACH LAYER HAS ITS OWN RESULT TYPE AND THEY SHARE ONE CROSSING, and the second
// half of that sentence was written by the mutation register rather than by
// judgement. This started as a copy of the function above, with a comment
// arguing that two small functions cannot drift. What it actually did was make
// three EXISTING entries ambiguous - the same rule now matched in two places, so
// each of them reported SKIP and stopped proving anything. A duplicated rule
// duplicates itself for the register too, and the register says so by going
// quiet.
//
// So the rule lives once, in answerOf, and both layers go through it.
func answerFromResolution(result resolve.Result) Answer {
	return answerOf(result.Status, result.Reason, result.Detail, result.Findings)
}

// answerFromProxy is the same boundary for L2.
func answerFromProxy(result proxy.Result) Answer {
	return answerOf(result.Status, result.Reason, result.Detail, result.Findings)
}

// answerFromReach is the same boundary for L3.
func answerFromReach(result tcp.Result) Answer {
	return answerOf(result.Status, result.Reason, result.Detail, result.Findings)
}

// answerFromHandshake is the same boundary for L4.
//
// FOUR LAYERS NOW GO THROUGH ONE CROSSING, and that is the point rather than a
// coincidence. The first two started as copies of each other, with a comment
// arguing two small functions could not drift; what they actually did was make
// three EXISTING mutation entries ambiguous, so each reported SKIP and stopped
// proving anything. The rule lives once, in answerOf.
func answerFromHandshake(result handshake.Result) Answer {
	return answerOf(result.Status, result.Reason, result.Detail, result.Findings)
}

func answerFromTrust(result trust.Result) Answer {
	return answerOf(result.Status, result.Reason, result.Detail, result.Findings)
}

// answerOf is the crossing itself: four fields, carried across unchanged.
//
// It masks nothing (ADR18), grades nothing (ADR7) and attaches no identifier -
// a layer never gets to say which layer it is. The findings slice is passed
// along as it is, NIL AND ALL: nil means the layer did not look and an empty
// slice means it looked and found nothing (ADR20).
func answerOf(state status.Status, reason status.Reason, detail string, findings []report.Finding) Answer {
	return Answer{Status: state, Reason: reason, Detail: detail, Findings: findings}
}
