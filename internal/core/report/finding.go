package report

import "fmt"

// FindingKind says what sort of fact a finding carries.
//
// The list is closed and has a registry, for the same reason NoteKind does: a
// consumer has to be able to branch on it without reading English. It is also
// the discriminator of a union - the body of a finding is typed per kind, and
// the kind is what says which body to expect.
type FindingKind string

const (
	// FindingEnvironmentVariable - one environment variable that decides trust
	// or proxying, exactly as it was found.
	FindingEnvironmentVariable FindingKind = "environment_variable"
)

// findingKindMeanings is the registry. The registry test refuses a kind that is
// declared without one.
var findingKindMeanings = map[FindingKind]string{
	FindingEnvironmentVariable: "an environment variable that decides trust or proxying",
}

// AllFindingKinds lists every kind exactly once, in declaration order.
//
// THERE IS EXACTLY ONE TODAY AND THE MACHINERY STILL EARNS ITS PLACE. A flat
// shape of name and value would carry this kind and break on the next one: a TCP
// result is a refusal reason AND a duration, and a TLS result is a certificate,
// which is a record with a dozen fields. Squeezing that into a pair gives either
// one row per certificate field with the relationship glued into the key, or an
// untyped blob - and then the schema stops saying anything. The case that breaks
// the simpler shape is named and dated rather than imagined.
var AllFindingKinds = []FindingKind{
	FindingEnvironmentVariable,
}

// Valid reports whether k is one of the declared kinds.
func (k FindingKind) Valid() bool {
	_, ok := findingKindMeanings[k]
	return ok
}

// Meaning returns the English text for k, or the empty string outside the
// registry.
func (k FindingKind) Meaning() string { return findingKindMeanings[k] }

// String makes FindingKind printable without a conversion at every call site.
func (k FindingKind) String() string { return string(k) }

// Source says how we know a finding.
//
// THIS IS RULE 18 WRITTEN INTO THE DATA. Every claim this program makes about
// somebody else's machine has to carry where it came from, and a field is the
// only form of that which survives being pasted into a ticket. "Measured" and
// "read out of a configuration file" are different strengths of claim, and a
// report that shows them identically is inviting the reader to trust the weaker
// one as much as the stronger.
type Source string

const (
	// SourceDetected - observed directly on this machine.
	SourceDetected Source = "detected"
	// SourceConfigured - read from configuration somebody wrote.
	SourceConfigured Source = "configured"
	// SourceDerived - worked out from something else rather than observed. In a
	// container the host's view of DNS can only be derived.
	SourceDerived Source = "derived"
	// SourceDefault - nothing set it, this is what applies in that case.
	SourceDefault Source = "default"
)

var sourceMeanings = map[Source]string{
	SourceDetected:   "observed directly on this machine",
	SourceConfigured: "read from configuration somebody wrote",
	SourceDerived:    "worked out from something else rather than observed",
	SourceDefault:    "nothing set it, so this is what applies",
}

// AllSources lists every source exactly once, in declaration order.
var AllSources = []Source{SourceDetected, SourceConfigured, SourceDerived, SourceDefault}

// Valid reports whether s is one of the declared sources.
func (s Source) Valid() bool {
	_, ok := sourceMeanings[s]
	return ok
}

// Meaning returns the English text for s, or the empty string outside the
// registry.
func (s Source) Meaning() string { return sourceMeanings[s] }

// String makes Source printable without a conversion at every call site.
func (s Source) String() string { return string(s) }

// Finding is one fact a layer established about this machine.
//
// THE SHAPE IS AN ENVELOPE PLUS A TYPED BODY. Kind, Summary and Source are
// common to every finding and are what a renderer can show WITHOUT KNOWING THE
// KIND - that is what keeps the three output surfaces at parity by default
// rather than by discipline. The body is one field per kind, and exactly one of
// them is set.
//
// Summary is always present and is not decoration. It is the sentence a terminal
// or a markdown report prints when it has no special handling for this kind, so
// a finding added later renders somewhere useful on every surface from the day
// it exists.
type Finding struct {
	Kind    FindingKind
	Summary string
	Source  Source

	// EnvironmentVariable is set when Kind is FindingEnvironmentVariable.
	EnvironmentVariable *EnvironmentVariable
}

// EnvironmentVariable is the body of an environment variable finding.
type EnvironmentVariable struct {
	// Name is the spelling exactly as it was looked up, never normalised.
	//
	// HTTP_PROXY AND http_proxy ARE NOT TWO SPELLINGS OF ONE THING. curl
	// honours the http one ONLY in lower case, deliberately, so that a Proxy
	// header arriving in a CGI request cannot become a variable. On Linux the
	// two are separate variables and the upper case one is ignored for http. On
	// Windows the environment is case-insensitive, so they are one variable and
	// it is honoured. The same configuration therefore behaves differently on
	// the two systems, which is exactly the class of divergence this tool
	// exists to report - and a row that merged the spellings would be true and
	// misleading at once.
	Name string
	// Value is what the variable holds, after masking. Empty string and unset
	// are different facts and Set is what tells them apart.
	Value string
	// Set distinguishes a variable that is absent from one set to nothing.
	// HTTPS_PROXY= with no value turns proxying off in some tools, so the two
	// are not the same answer.
	Set bool
	// CarriedCredentials records that masking removed something. The fact that a
	// proxy URL carries credentials is half the answer to "why do I get a 407",
	// and it is the half that can be said without saying the secret.
	//
	// IT IS FILLED IN ON THE ASSEMBLY PATH, NOT BY THE LAYER. Answering it means
	// asking the masking rules whether they would remove anything, and a layer is
	// not allowed to reach the masking package - ADR18. The layer hands back the
	// raw value and the orchestrator answers this alongside masking it, from the
	// same text, so the two can never disagree.
	CarriedCredentials bool
}

// findingBodies says, for each declared kind, whether that kind's body is
// present in a finding.
//
// WHY A TABLE RATHER THAN AN if. The union has one member today and the whole
// reason it is a union is the second one - a certificate in L4 is a record with
// a dozen fields. A hand written condition would go on passing when that member
// arrives, because it would simply not mention it. This is walked against the
// declared list of kinds, so a kind added without an entry here is a red
// registry test rather than a body nothing checks.
var findingBodies = map[FindingKind]func(Finding) bool{
	FindingEnvironmentVariable: func(f Finding) bool { return f.EnvironmentVariable != nil },
}

// Breach names what is wrong with a finding, or returns the empty string for one
// that is well formed. The wording continues a sentence naming the finding, so
// it says what the finding does rather than what was checked.
//
// IT IS USED IN TWO PLACES AND BOTH ARE NEEDED. The orchestrator asks it of an
// answer a layer just handed over, and degrades that layer alone if it is wrong.
// The report validator asks it again of the assembled report, before anything is
// printed. The first keeps one layer's mistake from taking the run down, the
// second is what stands there if a finding ever reaches a report by some other
// route.
func (f Finding) Breach() string {
	switch {
	case !f.Kind.Valid():
		return fmt.Sprintf("carries the kind %q, which is outside the registry", f.Kind)
	case f.Summary == "":
		return "carries no summary, and the summary is the one line a surface can render without knowing the kind"
	case !f.Source.Valid():
		return fmt.Sprintf("carries the source %q, so it does not say how strongly it is known", f.Source)
	}

	// Walked in declaration order rather than over the map, so that a finding
	// with two defects is always described the same way.
	for _, kind := range AllFindingKinds {
		present, declared := findingBodies[kind]
		if !declared {
			return fmt.Sprintf("is of a kind %q whose body nothing knows how to find", kind)
		}
		switch {
		case kind == f.Kind && !present(f):
			return fmt.Sprintf("says it is %s and carries no body of that kind", kind)
		case kind != f.Kind && present(f):
			return fmt.Sprintf("says it is %s and carries a %s body as well", f.Kind, kind)
		}
	}
	return f.bodyBreach()
}

// bodyBreach asks the body itself, once the envelope is known to be sound.
func (f Finding) bodyBreach() string {
	if f.EnvironmentVariable != nil {
		return f.EnvironmentVariable.breach()
	}
	return ""
}

// breach refuses the two states that would say something nobody measured.
//
// A variable that is not set cannot carry a value and cannot have had anything
// masked out of it. Either combination renders as an ordinary row and reads as a
// fact, which is the quiet failure this whole type exists to prevent.
func (e EnvironmentVariable) breach() string {
	switch {
	case e.Name == "":
		return "carries an environment variable with no name, which would render as a row with nothing in front of it"
	case !e.Set && e.Value != "":
		return fmt.Sprintf("says %s is not set and carries a value for it anyway", e.Name)
	case !e.Set && e.CarriedCredentials:
		return fmt.Sprintf("says %s is not set and that masking took something out of it", e.Name)
	}
	return ""
}
