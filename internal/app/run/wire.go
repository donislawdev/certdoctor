package run

import (
	"context"

	"github.com/donislawdev/certdoctor/internal/core/layer"
	"github.com/donislawdev/certdoctor/internal/core/machine"
	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/resolve"
	"github.com/donislawdev/certdoctor/internal/core/status"
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
func Wire(environment machine.Lookup, resolution resolve.Input) Layers {
	layers := NotImplemented()
	layers[layer.Context] = func(context.Context) Answer {
		return answerFrom(machine.Read(environment))
	}
	// L1 receives a context carrying the layer's deadline, which is where its
	// budget arithmetic starts. Everything else it needs arrived in the Input the
	// entry point built - the ports, the raw host, and this machine's resolvers,
	// which had to be enumerated before the walk so the masking could be told
	// about them.
	layers[layer.Resolution] = func(ctx context.Context) Answer {
		return answerFromResolution(resolve.Ask(ctx, resolution))
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

// answerOf is the crossing itself: four fields, carried across unchanged.
//
// It masks nothing (ADR18), grades nothing (ADR7) and attaches no identifier -
// a layer never gets to say which layer it is. The findings slice is passed
// along as it is, NIL AND ALL: nil means the layer did not look and an empty
// slice means it looked and found nothing (ADR20).
func answerOf(state status.Status, reason status.Reason, detail string, findings []report.Finding) Answer {
	return Answer{Status: state, Reason: reason, Detail: detail, Findings: findings}
}
