// Package machine describes the context a run happens in: the environment
// variables on this machine that decide what is trusted and what is proxied.
//
// IT IS A PURE FUNCTION OF WHAT IT IS HANDED. Reading the real environment means
// touching the operating system, and the core is not allowed to - the layer
// guard forbids it os import by import, so that assessment stays testable
// without a broken machine to reproduce. The environment arrives through a
// Lookup that the entry point fills with the real one and a test fills with a
// map.
//
// WHAT IT DOES NOT DO. It never says whether a setting is good, dangerous or
// wrong, and it never says this is a container. Judging trust belongs to L5 and
// judging containers to L6; L0 says what is there and how strongly it knows it.
// A layer that graded these values would be answering a question no evidence it
// holds can settle, and it would answer it first, at the top of the report.
//
// It also never masks anything. Evidence is handed over raw and the assembly
// path takes the credentials out of it once - ADR18. That is why this package
// does not import the masking package, and why a guard refuses the import
// rather than trusting anybody to remember.
package machine

import (
	"fmt"

	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// Lookup is the port this package sees the environment through.
//
// The signature is the standard library's, so the entry point can pass the real
// one with nothing in between to get wrong. Two return values rather than one:
// a variable set to nothing and a variable that is absent are different facts,
// and some tools stop proxying on the first and carry on with the second.
type Lookup func(name string) (value string, set bool)

// Result is what L0 established, before anything has been masked.
//
// It carries an assessment as well as findings because working the verdict out
// from evidence is the core's job - ADR7. A layer handing back bare data and
// letting the orchestrator grade it would put assessment in the one place that
// cannot be tested on recorded evidence.
type Result struct {
	Status status.Status
	// Reason is set only when Status needs one, and it comes from the closed
	// list.
	Reason status.Reason
	// Detail is the one line of English specific to this result.
	Detail string
	// Findings is one entry per declared variable, whether or not it is set.
	//
	// Nil means this layer did not look, and an empty slice means it looked and
	// found nothing. The two encode identically in Go until something asks, so
	// the difference is kept deliberately rather than left to a convenient copy
	// - ADR20.
	Findings []report.Finding
}

// unreadableEnvironment is what L0 answers when it was given no way to look.
//
// IT IS UNKNOWN AND NOT PASS, and that is rule 15 rather than caution. A run
// that could not read the environment has established nothing about this
// machine's context, and reporting that as a pass would be the product's
// central promise broken in the first row of the report. Findings stay nil,
// because nil is how a layer says nobody looked.
const unreadableEnvironment = "no way to read the environment was supplied, so nothing about this machine's context was established"

// Read collects every declared variable and reports what it found.
//
// The only failure it can have is the one below. Asking the environment for a
// name cannot fail - there is no system call underneath to refuse - so the list
// of failure modes here is one entry long, and it is a defect on our side
// rather than anything about the machine being diagnosed.
//
// There is deliberately no check of a deadline. The orchestrator already tests
// the context before each layer, and reading from memory does not take time, so
// a timeout branch here could never be reached - and an unreachable branch with
// a mutation entry behind it turns "no survivors" into a number nobody reads.
func Read(lookup Lookup) Result {
	if lookup == nil {
		return Result{
			Status: status.Unknown,
			Reason: status.ReasonProbeError,
			Detail: unreadableEnvironment,
		}
	}

	// Length zero and capacity for the lot: the slice is non-nil from the first
	// line, so a future list that read nothing would still say "looked, found
	// nothing" rather than "did not look".
	findings := make([]report.Finding, 0, len(variables))
	for _, name := range variables {
		findings = append(findings, findingFor(name, lookup))
	}
	return Result{
		Status: status.Pass,
		// Counted rather than written down, so the sentence cannot go stale the
		// day the list changes. It says how much was looked at, which is the
		// only thing a passing context layer has to report - the findings say
		// the rest.
		Detail:   fmt.Sprintf("read %d environment variables that decide trust and proxying", len(variables)),
		Findings: findings,
	}
}

// findingFor asks about one variable and wraps the answer.
func findingFor(name string, lookup Lookup) report.Finding {
	value, set := lookup(name)
	// A port answering "not set" while handing over a value has answered two
	// things at once, and the "not set" half is the one that decides: an absent
	// variable has no value by definition. The real environment never does this;
	// a stand-in for it can, and without this line the finding it produced would
	// break its own contract and cost the whole layer its row.
	if !set {
		value = ""
	}

	return report.Finding{
		Kind:    report.FindingEnvironmentVariable,
		Summary: summaryFor(name, value, set),
		Source:  sourceFor(set),
		EnvironmentVariable: &report.EnvironmentVariable{
			Name: name,
			// RAW. The orchestrator masks this and fills in whether anything was
			// removed, from this same text, so the two cannot disagree.
			Value: value,
			Set:   set,
		},
	}
}

// summaryFor says which of the three states this variable is in.
//
// IT HAS TO, BECAUSE THE VALUE COLUMN CANNOT. A renderer prints the value only
// when there is one, so a variable that is absent and a variable set to nothing
// both print an empty column - and those two states send some tools down
// different paths entirely. The summary is the one line every surface renders
// without knowing the kind, so this is where that difference has to survive.
func summaryFor(name, value string, set bool) string {
	switch {
	case !set:
		return name + " is not set"
	case value == "":
		return name + " is set to nothing"
	default:
		return name + " is set"
	}
}

// sourceFor says how strongly this finding is known.
//
// A variable that is present was observed here. A variable that is absent was
// also observed - what applies then is whatever the tool reading it does with no
// setting, which is what "default" means. Neither is derived and neither is read
// out of somebody's configuration file, so the other two sources would both be
// stronger claims than we have.
func sourceFor(set bool) report.Source {
	if set {
		return report.SourceDetected
	}
	return report.SourceDefault
}
