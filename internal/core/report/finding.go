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
	// FindingNameResolution - one answer to "what does this name resolve to",
	// seen through one of the two lenses L1 looks through.
	FindingNameResolution FindingKind = "name_resolution"
)

// findingKindMeanings is the registry. The registry test refuses a kind that is
// declared without one.
var findingKindMeanings = map[FindingKind]string{
	FindingEnvironmentVariable: "an environment variable that decides trust or proxying",
	FindingNameResolution:      "one answer to what a name resolves to, through one named lens",
}

// AllFindingKinds lists every kind exactly once, in declaration order.
//
// THE MACHINERY WAS BUILT FOR A SECOND KIND AND THE SECOND KIND HAS ARRIVED. A
// flat shape of name and value carried the first one and would have broken on
// this one: a resolution answer is a view, a resolver, a record type, a response
// code, a list of addresses and a duration. Squeezing that into a pair gives
// either one row per field with the relationship glued into the key, or an
// untyped blob - and then the schema stops saying anything.
//
// WHAT IS WORTH KNOWING IS WHERE IT CAME FROM. The justification written when
// this had one member named a CERTIFICATE IN L4 as the case that would break the
// simpler shape - named and dated rather than imagined, which was the point. It
// was the right argument about the wrong layer: L1 broke it first, three
// milestones earlier. The lesson is not to argue harder about which case it will
// be, but that a shape chosen for a named future case earns its keep even when
// the case that arrives is a different one.
var AllFindingKinds = []FindingKind{
	FindingEnvironmentVariable,
	FindingNameResolution,
}

// ResolutionView says which of the two lenses an answer was seen through.
//
// EXACTLY TWO, AND THE THIRD ONE PEOPLE REACH FOR IS A MISTAKE - ADR23. In a
// container the system view cannot be measured and has to be rebuilt from
// resolv.conf and nsswitch.conf, which is tempting to call a third view. It is
// not: it is still the system view, and how strongly we know it is what Source
// already carries. Two fields saying the same thing drift apart the first time
// one of them is edited.
type ResolutionView string

const (
	// ViewSystem - asked the way the user's runtime would ask, so the answer is
	// what their runtime gets.
	ViewSystem ResolutionView = "system"
	// ViewDirect - our own query to one named resolver, so the answer is what is
	// actually in DNS.
	ViewDirect ResolutionView = "direct"
)

var resolutionViewMeanings = map[ResolutionView]string{
	ViewSystem: "asked the way this system asks, so it is what the user's runtime gets",
	ViewDirect: "our own query to one named resolver, so it is what is actually in DNS",
}

// AllResolutionViews lists every view exactly once, in declaration order.
var AllResolutionViews = []ResolutionView{ViewSystem, ViewDirect}

// Valid reports whether v is one of the two.
func (v ResolutionView) Valid() bool {
	_, ok := resolutionViewMeanings[v]
	return ok
}

// Meaning returns the English text for v, or the empty string outside the two.
func (v ResolutionView) Meaning() string { return resolutionViewMeanings[v] }

// String makes ResolutionView printable without a conversion at every call site.
func (v ResolutionView) String() string { return string(v) }

// NoAnswer says why a query has no response code.
//
// SILENCE IS NOT A RESPONSE CODE, AND THAT IS THE WHOLE REASON THIS TYPE EXISTS
// RATHER THAN A FEW MORE STRINGS IN ResponseCode - ADR30. NODATA lives in that
// field legitimately because it is read OUT OF A PACKET THAT ARRIVED: the name
// exists and there is no record of the type asked for. Here no packet arrived at
// all, so there is nothing to read, and a reader of --json would have to guess
// which values came off the wire and which we invented.
//
// It is measured rather than reasoned: a forward to an unroutable address
// produces SILENCE, not SERVFAIL - docs/17 section 6d, on the coredns bench. A
// layer that folded the two together would send somebody to their resolver when
// the answer is their firewall.
//
// THE LIST IS CLOSED, unlike ResponseCode, and for the mirror-image reason:
// these reasons are OURS. They describe what this program did or failed to do,
// so an unrecognised one is a defect here rather than news from the network.
type NoAnswer string

const (
	// NoAnswerTimeout - the query went out and nothing came back in time.
	NoAnswerTimeout NoAnswer = "timeout"
	// NoAnswerRefusedByRule - the allowed set refused this address, so nothing
	// was ever sent. It is a fact about US, and reporting it as a network
	// failure would accuse a working resolver.
	NoAnswerRefusedByRule NoAnswer = "refused_by_rule"
	// NoAnswerTransportError - sending or receiving failed outright.
	NoAnswerTransportError NoAnswer = "transport_error"
	// NoAnswerUnreadableAnswer - something came back and could not be read as an
	// answer to the question that was asked.
	NoAnswerUnreadableAnswer NoAnswer = "unreadable_answer"
	// NoAnswerNotAsked - the layer ran out of its budget before this query.
	//
	// IT IS REPORTED RATHER THAN OMITTED, and that is inviolable rule 1. Three
	// resolvers times two record types at three seconds each is eighteen seconds
	// against a ten second layer budget, so queries WILL be dropped on a slow
	// network - and a report that simply had fewer rows would read as a machine
	// with fewer resolvers.
	NoAnswerNotAsked NoAnswer = "not_asked"
)

// Divergence is how the two views of a name differ - D13, which asks this layer
// to CLASSIFY the difference rather than to compare the views for equality.
//
// WHY NOT A BOOLEAN, AND THIS IS THE WHOLE OF D13. Probe S4 measured the two
// views disagreeing on five names out of five, so "the views differ" is the
// normal state of a working machine and a warning built on it would fire in
// nearly every run on Windows. That is the shape ADR4 warns about: a tool that
// cries wolf is switched off within a week. Three of these classes carry a
// verdict and the rest are named and left alone - the ratio is the decision,
// and the count is deliberately not written here because it has already gone
// stale twice, once per class added.
//
// THE LIST IS CLOSED AND IT DESCRIBES OUR OWN COMPARISON, so an unrecognised
// value is a defect here rather than news from anybody's network.
type Divergence string

const (
	// DivergenceAgree - both views answered with the same addresses.
	DivergenceAgree Divergence = "agree"
	// DivergenceSuperset - one view has everything the other has, and more.
	//
	// IT IS USUALLY A FACT ABOUT OUR INSTRUMENT RATHER THAN ABOUT THE MACHINE.
	// AAAA records show up in the direct view because we ask for them by name,
	// while the platform hands back a filtered list. Calling that a finding would
	// accuse somebody's network of a property of ours.
	DivergenceSuperset Divergence = "superset"
	// DivergenceDisjoint - both views answered and share no address at all.
	//
	// THE ONE CLASS THAT IS A FINDING. Split horizon DNS and a leak past a VPN
	// both look like this, and both are worth somebody's attention.
	DivergenceDisjoint Divergence = "disjoint"
	// DivergenceOneSided - one view answered and the other did not.
	//
	// Also usually ours: the direct view never reads the hosts file, so a name
	// that lives only there is unresolvable to it and resolvable to the platform.
	DivergenceOneSided Divergence = "one_sided"
	// DivergenceNeitherAnswered - the name resolved no way at all.
	DivergenceNeitherAnswered Divergence = "neither_answered"
	// DivergenceOverlap - both views answered, they share an address, and each
	// has one the other lacks.
	//
	// D13 NAMES FIVE CLASSES AND THIS IS A SIXTH, ADDED WHEN THE CLASSIFIER WAS
	// WRITTEN AND THE FIVE TURNED OUT NOT TO COVER THE SPACE. A load balancer
	// handing out rotating subsets produces it routinely: our own queries get two
	// addresses of four, the platform gets two others, and one is in both.
	//
	// IT IS DELIBERATELY NOT disjoint. That class means "these two views share
	// nothing", which is the split horizon signal and carries a warning. Raising
	// it on a rotating subset would put a warning in nearly every run against a
	// large site - the exact failure mode D13 was written to avoid, arriving
	// through the gap in its own list.
	DivergenceOverlap Divergence = "overlap"
	// DivergenceAgreeNone - both views answered, and neither answer carried an
	// address.
	//
	// A SEVENTH CLASS, AND IT WAS MEASURED RATHER THAN REASONED ABOUT. Running
	// the binary against a name under .invalid produced four NXDOMAIN rows, a
	// system view with no address, and the sentence "both views resolved this
	// name to the same addresses" - about a name that resolves nowhere. Two
	// empty sets compare equal, so the classifier reached agree, which carries
	// a pass. That is the shape OBS39 named in a byte comparison, arriving here.
	//
	// IT IS NOT neither_answered, AND THE DISTINCTION IS THE POINT. That class
	// means nobody replied - a cable, a firewall, a resolver that stayed silent.
	// Here BOTH resolvers replied, promptly and authoritatively, and what they
	// said was "there is no such name". Folding the two together would be the
	// same move ADR38 refused for disjoint: a new fact pushed into a class that
	// means something else, where it reads as a measurement of the wire.
	//
	// IT CARRIES A VERDICT, and that is D13 read literally: a name that resolves
	// no way at all is a failure. The user typed a URL and there is nothing to
	// connect to - which is a diagnosis, and usually a typo or a name that only
	// exists inside a network this machine is not on.
	DivergenceAgreeNone Divergence = "agree_none"
)

var divergenceMeanings = map[Divergence]string{
	DivergenceAgree:           "both views resolved this name to the same addresses",
	DivergenceSuperset:        "one view returned everything the other did and more",
	DivergenceDisjoint:        "both views answered and share no address",
	DivergenceOneSided:        "one view resolved this name and the other did not",
	DivergenceNeitherAnswered: "neither view resolved this name",
	DivergenceOverlap:         "both views answered, share an address, and each has one the other lacks",
	DivergenceAgreeNone:       "both views answered and neither found an address for this name",
}

// AllDivergences lists every class exactly once, in declaration order.
var AllDivergences = []Divergence{
	DivergenceAgree,
	DivergenceSuperset,
	DivergenceDisjoint,
	DivergenceOneSided,
	DivergenceNeitherAnswered,
	DivergenceOverlap,
	DivergenceAgreeNone,
}

// Valid reports whether d is one of the named classes.
//
// The count used to be written here and went stale twice, once per class added
// - the list itself is above and does not need restating in a sentence nobody
// updates.
func (d Divergence) Valid() bool {
	_, ok := divergenceMeanings[d]
	return ok
}

// Meaning returns the English sentence for d, or the empty string outside the
// list.
func (d Divergence) Meaning() string { return divergenceMeanings[d] }

// String makes Divergence printable without a conversion at every call site.
func (d Divergence) String() string { return string(d) }

var noAnswerMeanings = map[NoAnswer]string{
	NoAnswerTimeout:          "the query was sent and nothing came back in time",
	NoAnswerRefusedByRule:    "this address was not in the allowed set, so nothing was sent",
	NoAnswerTransportError:   "sending the query or reading the reply failed",
	NoAnswerUnreadableAnswer: "a reply arrived and could not be read as an answer to this question",
	NoAnswerNotAsked:         "the layer ran out of time before this query was asked",
}

// AllNoAnswers lists every reason exactly once, in declaration order.
var AllNoAnswers = []NoAnswer{
	NoAnswerTimeout,
	NoAnswerRefusedByRule,
	NoAnswerTransportError,
	NoAnswerUnreadableAnswer,
	NoAnswerNotAsked,
}

// Valid reports whether n is one of the declared reasons.
func (n NoAnswer) Valid() bool {
	_, ok := noAnswerMeanings[n]
	return ok
}

// Meaning returns the English text for n, or the empty string outside the
// registry.
func (n NoAnswer) Meaning() string { return noAnswerMeanings[n] }

// String makes NoAnswer printable without a conversion at every call site.
func (n NoAnswer) String() string { return string(n) }

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
	// NameResolution is set when Kind is FindingNameResolution.
	NameResolution *NameResolution
}

// NameResolution is the body of a name resolution finding: one answer, through
// one lens, from one place.
//
// ONE FINDING PER ANSWER RATHER THAN ONE PER NAME. The direct view asks each
// resolver separately and asks for A and AAAA separately, because that is where
// the divergences live - a resolver that answers for one record type and not
// the other is the "hangs thirty seconds, then works" class. Folding those into
// one row would need a nested array inside the body and would cost the property
// that makes findings work: that Summary is a sentence every surface can render
// without knowing the kind.
type NameResolution struct {
	// Name is the name that was resolved.
	Name string
	// View says which lens this answer came through.
	View ResolutionView
	// Resolver is which resolver was asked. It is EMPTY FOR THE SYSTEM VIEW and
	// that is not a gap: the operating system resolves the name and does not
	// tell us which of its configured servers answered. Filling this in for the
	// system view would be inventing the most useful part of the row.
	Resolver string
	// QueryType is the record type asked for - "A", "AAAA". Empty for the system
	// view, which does not split by type and hands back a mixed list.
	//
	// It is a plain string rather than a closed registry on purpose: which types
	// we ask for will grow, and a closed list here would be a promise to break.
	QueryType string
	// ResponseCode is what the resolver answered - NOERROR, NXDOMAIN, SERVFAIL,
	// NODATA and whatever else arrives.
	//
	// EMPTY FOR THE SYSTEM VIEW, and this is the whole reason the direct view
	// exists. net.Resolver collapses NXDOMAIN and SERVFAIL into one "no such
	// host", so the system lens genuinely cannot tell us which happened - ADR24.
	// It is not a closed registry because it comes off the wire: an unknown code
	// is reported as itself rather than refused.
	ResponseCode string
	// NoAnswer says why there is no response code, and is empty when there is
	// one. The direct view carries exactly one of the two - see breach.
	NoAnswer NoAnswer
	// Addresses is what came back, in a stable order.
	Addresses []string
	// DurationMS is how long this one answer took, in whole milliseconds.
	//
	// MILLISECONDS ARE DELIBERATELY COARSE. D13 forbids putting two views' times
	// side by side as a comparison, because the second query always benefits
	// from whatever the first warmed - measured twice, in S4 and again in S8.
	// A unit that cannot express the difference between two warm cache hits is a
	// unit that does not invite the comparison. It is the same unit the run's own
	// duration uses, so the document has one way of saying "how long".
	DurationMS int64
	// Divergence is how this view differs from the other one - D13, ADR37.
	//
	// IT LIVES ON THE SYSTEM ROW AND NOWHERE ELSE, and the reason is that there
	// is exactly one comparison per run while there are many direct rows. The
	// system row is the one that completes it: it arrives last, after the union
	// of the direct answers exists (ADR31), and reads literally as "this is how
	// the platform's answer differs from ours".
	//
	// EMPTY MEANS NO COMPARISON WAS POSSIBLE, not "the views agree". A run with
	// one lens produces no system row at all, so there is nowhere for a value to
	// sit - which is more honest than a sixth class meaning "not compared".
	Divergence Divergence
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
	FindingNameResolution:      func(f Finding) bool { return f.NameResolution != nil },
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
//
// The resolution body is handed the envelope's Source as well, and it is the
// first rule in this file that spans the two. The reason is ADR23: how strongly
// an answer is known lives in the envelope, WHICH LENS it came through lives in
// the body, and one combination of the two is a claim nobody could have made.
func (f Finding) bodyBreach() string {
	switch {
	case f.EnvironmentVariable != nil:
		return f.EnvironmentVariable.breach()
	case f.NameResolution != nil:
		return f.NameResolution.breach(f.Source)
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

// breach refuses the combinations that would state something nobody could have
// established.
//
// THE THREE RULES ABOUT THE SYSTEM VIEW ARE THE POINT OF THIS FUNCTION. The
// operating system answers a name and tells us nothing else: not which of its
// resolvers replied, not which record type it asked for, not what response code
// came back. Every one of those is the most useful column in the row, so every
// one of them is what a plausible-looking mistake would fill in - and a filled
// in row reads as a measurement rather than as an invention.
func (n NameResolution) breach(source Source) string {
	switch {
	case n.Name == "":
		return "carries a resolution answer for no name, which would render as a row with nothing in front of it"
	case !n.View.Valid():
		return fmt.Sprintf("was seen through the view %q, so it does not say which of the two lenses it came from", n.View)
	case n.DurationMS < 0:
		return fmt.Sprintf("says resolving %s took %d milliseconds", n.Name, n.DurationMS)
	}

	// CHECKED BEFORE THE PER-VIEW RULES, because a class outside the closed list
	// is a defect in our own comparison whichever row it turned up on.
	if n.Divergence != "" && !n.Divergence.Valid() {
		return fmt.Sprintf("says the two views of %s diverge as %q, which is outside the closed list of classes "+
			"this program names", n.Name, n.Divergence)
	}
	if n.View == ViewDirect && n.Divergence != "" {
		// THE COMPARISON HAPPENS ONCE AND THIS IS WHERE IT WOULD QUIETLY HAPPEN
		// FOUR TIMES. Two resolvers times two record types is four direct rows,
		// and a class copied onto each of them is one fact in four places -
		// which stays true exactly until somebody edits one of them.
		return fmt.Sprintf("is a direct query for %s and carries the divergence %q, which describes the pair of "+
			"views rather than this one answer", n.Name, n.Divergence)
	}

	if n.View == ViewSystem {
		switch {
		case n.Resolver != "":
			return fmt.Sprintf("is the system view of %s and names %s as the resolver that answered, which this system "+
				"does not report", n.Name, n.Resolver)
		case n.ResponseCode != "":
			return fmt.Sprintf("is the system view of %s and carries the response code %s, which the system resolver "+
				"does not hand back", n.Name, n.ResponseCode)
		case n.QueryType != "":
			return fmt.Sprintf("is the system view of %s and says it asked for %s, which that view does not split by",
				n.Name, n.QueryType)
		}
	}

	if n.View == ViewDirect {
		switch {
		case source == SourceDerived:
			return fmt.Sprintf("is our own query for %s and says it was derived rather than observed", n.Name)
		case n.Resolver == "":
			return fmt.Sprintf("is a direct query for %s and cannot say which resolver was asked", n.Name)
		case n.QueryType == "":
			return fmt.Sprintf("is a direct query for %s and does not say which record type it asked for", n.Name)
		// EXACTLY ONE OF THE TWO, AND BOTH HALVES OF THAT ARE WORTH A BRANCH -
		// ADR30. Neither means the row says nothing about what happened, which is
		// the one thing this view exists to establish. Both means it claims the
		// resolver answered AND that it never did, and a reader would believe
		// whichever column they looked at first.
		case n.ResponseCode == "" && n.NoAnswer == "":
			return fmt.Sprintf("is a direct query for %s and says neither what the resolver answered nor why it did "+
				"not, which is the one thing this view exists to establish", n.Name)
		case n.ResponseCode != "" && n.NoAnswer != "":
			return fmt.Sprintf("is a direct query for %s carrying the response code %s and also the reason %q for "+
				"having none", n.Name, n.ResponseCode, n.NoAnswer)
		}
	}

	// Checked for every view, because the system view can fail to answer too and
	// the reason it gives has to come from the same closed list.
	if n.NoAnswer != "" && !n.NoAnswer.Valid() {
		return fmt.Sprintf("says resolving %s produced no answer because %q, which is outside the closed list",
			n.Name, n.NoAnswer)
	}
	// AN ANSWER THAT NEVER ARRIVED CANNOT HAVE BROUGHT ADDRESSES. This is the
	// same shape as the NXDOMAIN rule below and catches the likelier mistake: a
	// caller that fills in the reason for a timeout while leaving the addresses
	// from the query before it.
	if n.NoAnswer != "" && len(n.Addresses) > 0 {
		return fmt.Sprintf("says resolving %s produced no answer (%s) and lists %d address(es) from it",
			n.Name, n.NoAnswer, len(n.Addresses))
	}

	// A name that does not exist has no addresses. Reporting both is the kind of
	// contradiction that renders as an ordinary row and gets believed.
	if n.ResponseCode == ResponseNXDomain && len(n.Addresses) > 0 {
		return fmt.Sprintf("says %s does not exist and lists %d address(es) for it", n.Name, len(n.Addresses))
	}
	return ""
}

// ResponseNXDomain is the one response code this package names, because it is
// the one a rule here depends on.
//
// The rest are deliberately not constants: they arrive off the wire, the list is
// not ours to close, and an unknown code is reported as itself.
const ResponseNXDomain = "NXDOMAIN"
