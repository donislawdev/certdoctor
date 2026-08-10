package run

import (
	"context"

	"github.com/donislawdev/certdoctor/internal/core/layer"
	"github.com/donislawdev/certdoctor/internal/core/machine"
	"github.com/donislawdev/certdoctor/internal/core/resolve"
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
	return Answer{
		Status:   result.Status,
		Reason:   result.Reason,
		Detail:   result.Detail,
		Findings: result.Findings,
	}
}

// answerFromResolution is the same boundary for L1.
//
// IT IS A SECOND FUNCTION AND NOT A SHARED ONE, and that is worth a sentence
// because the two bodies are identical today. Each layer's result is its own
// type, and the day one of them grows a field this boundary has to think about,
// a shared function would have to grow a way of not thinking about it for the
// other. Two small functions cost four lines and cannot drift into that.
func answerFromResolution(result resolve.Result) Answer {
	return Answer{
		Status:   result.Status,
		Reason:   result.Reason,
		Detail:   result.Detail,
		Findings: result.Findings,
	}
}
