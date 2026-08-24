package report

import (
	"fmt"
	// net/netip parses an address and reaches nothing, which is why the reach
	// guard does not list it beside net - the same reason net/url is absent from
	// that list. It is here so a connection row can refuse a host name where an
	// address belongs.
	"net/netip"
	// strings is here for one question only: whether a placeholder a fix
	// declares can actually be FOUND in the command it belongs to. A list of
	// things to replace that names something not present is a list nobody can
	// act on.
	"strings"
	// time carries certificate validity bounds. They are REPORTED and never
	// judged here: whether "expired" means anything depends on a clock this
	// package does not own, and the layers take their clock as a port for
	// exactly that reason.
	"time"
)

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
	// FindingTCPConnect - one attempt to open a TCP connection to one address.
	FindingTCPConnect FindingKind = "tcp_connect"

	// FindingTLSHandshake - what one server presented when the connection was
	// upgraded to TLS. THE KIND THIS WHOLE DISCRIMINATED UNION WAS BUILT FOR:
	// docs/18 named L4 by name back in P2, when there was exactly one kind and
	// the machinery looked oversized, because a certificate chain is the case a
	// flat {kind, name, value} envelope cannot carry.
	FindingTLSHandshake FindingKind = "tls_handshake"

	// FindingTrustStore - ONE trust store belonging to ONE instance of one
	// runtime, and what it makes of the chain L4 saw. The unit is the STORE, not
	// the runtime, because a machine holds many - measured 2026-08-18: six Java
	// stores and two curl binaries on this one, ADR48. A kind per runtime would
	// have made "does java trust this" a single answer, which is the claim this
	// product exists to disprove.
	FindingTrustStore FindingKind = "trust_store"

	// FindingSigningAuthority - WHO signed the leaf, and how widely the stores
	// on this machine hold that signer. One per run rather than one per store,
	// because the question is about the machine as a whole.
	//
	// IT IS NAMED FOR WHAT IT MEASURES RATHER THAN FOR WHAT IT MIGHT MEAN, and
	// that is ADR53 rather than timidity. Measured 2026-08-19 on the bench: an
	// intercepting middlebox and an honest internal server under a company's own
	// certificate authority produce the SAME answer in every field this program
	// has - same holding, same refusal, same repair, and once the middlebox is
	// given an intermediate, the same complete chain. A kind called
	// "interception" would therefore be an accusation printed on the ordinary
	// case, which inviolable rule 21 calls harm rather than a defect.
	FindingSigningAuthority FindingKind = "signing_authority"
)

// findingKindMeanings is the registry. The registry test refuses a kind that is
// declared without one.
var findingKindMeanings = map[FindingKind]string{
	FindingEnvironmentVariable: "an environment variable that decides trust or proxying",
	FindingNameResolution:      "one answer to what a name resolves to, through one named lens",
	FindingTCPConnect:          "one attempt to open a TCP connection to one address",
	FindingTLSHandshake:        "what one server presented when the connection to one address was upgraded to TLS",
	FindingTrustStore:          "one trust store of one runtime instance, and what it makes of the presented chain",
	FindingSigningAuthority:    "who signed the leaf, and how widely the trust stores on this machine hold that signer",
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
	FindingTCPConnect,
	FindingTLSHandshake,
	FindingTrustStore,
	FindingSigningAuthority,
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
	// DivergenceAgreeNone - neither view found an address, and at least one of
	// them said so rather than staying silent.
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
	// Here somebody replied, promptly and authoritatively, and what they said was
	// "there is no such name". Folding the two together would be the same move
	// ADR38 refused for disjoint: a new fact pushed into a class that means
	// something else, where it reads as a measurement of the wire.
	//
	// IT WIDENED ONCE, IN ADR42, AND THE WIDENING IS WORTH KNOWING. It used to
	// require BOTH views to have answered. A SERVFAIL from the only resolver
	// beside a system view that said nothing therefore fell through to one_sided,
	// which claims one lens resolved the name - and neither had. What the class
	// asserts now is narrower and truer: no address anywhere, and we know it
	// because somebody answered rather than because everybody went quiet.
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
	DivergenceDisjoint:        "both views found addresses and share none of them",
	DivergenceOneSided:        "one view resolved this name and the other did not",
	DivergenceNeitherAnswered: "neither view got any answer at all for this name",
	DivergenceOverlap:         "both views found addresses, share one, and each has one the other lacks",
	DivergenceAgreeNone:       "neither view found an address for this name, and at least one of them said so",
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
	// TCPConnect is set when Kind is FindingTCPConnect.
	TCPConnect *TCPConnect
	// TLSHandshake is set when Kind is FindingTLSHandshake.
	TLSHandshake *TLSHandshake
	// TrustStore is set when Kind is FindingTrustStore.
	TrustStore *TrustStore
	// SigningAuthority is set when Kind is FindingSigningAuthority.
	SigningAuthority *SigningAuthority
}

// ConnectOutcome is what happened when we tried to open one TCP connection.
//
// THE LIST IS CLOSED, UNLIKE ResponseCode AND FOR THE OPPOSITE REASON. A DNS
// response code arrives ON THE WIRE, so a value nobody recognises is news from
// somebody's network and is reported as itself. An outcome here is a name WE
// give to what the operating system told us, so a value outside this list is a
// defect in our own translation.
type ConnectOutcome string

const (
	// OutcomeConnected - the connection was established. It says nothing about
	// what is listening there, which is L4's question.
	OutcomeConnected ConnectOutcome = "connected"
	// OutcomeRefused - something answered and said no. The address is reachable
	// and nothing is accepting on that port.
	OutcomeRefused ConnectOutcome = "refused"
	// OutcomeTimeout - nothing answered before the deadline. It is the shape a
	// silently dropping firewall makes, and it is NOT the same as refused: one
	// means "reached, and declined", the other "we never found out".
	OutcomeTimeout ConnectOutcome = "timeout"
	// OutcomeReset - the connection was torn down rather than refused or
	// accepted. Some middleboxes do this to traffic they dislike.
	OutcomeReset ConnectOutcome = "reset"
	// OutcomeUnreachable - the network said there is no route. The commonest
	// honest cause is an IPv6 address on a machine with no IPv6.
	OutcomeUnreachable ConnectOutcome = "unreachable"
	// OutcomeRefusedByRule - the allowed set refused this address, so nothing was
	// ever sent.
	//
	// IT IS A FACT ABOUT US AND MUST NEVER READ AS ONE ABOUT THEIR NETWORK. The
	// same distinction NoAnswerRefusedByRule draws for L1: "we were not allowed
	// to ask" and "we asked and nobody answered" send a reader to two different
	// places, and only one of them is their firewall.
	OutcomeRefusedByRule ConnectOutcome = "refused_by_rule"
	// OutcomeNotAttempted - the layer ran out of its budget before this address.
	//
	// IT IS REPORTED RATHER THAN OMITTED, inviolable rule 1, and it is DELIBERATELY
	// NOT timeout. A timeout is a statement about somebody's network: we asked and
	// nothing came back. This is a statement about us: we never asked, because an
	// earlier address spent the time. Folding it into timeout would put our own
	// arithmetic into a row a reader takes as a measurement of their firewall -
	// the same confusion ADR36 fixed for L1 after measuring it.
	OutcomeNotAttempted ConnectOutcome = "not_attempted"
)

var connectOutcomeMeanings = map[ConnectOutcome]string{
	OutcomeConnected:     "the connection was established",
	OutcomeRefused:       "something answered and refused the connection",
	OutcomeTimeout:       "nothing answered before the deadline",
	OutcomeReset:         "the connection was reset rather than refused or accepted",
	OutcomeUnreachable:   "the network reported no route to this address",
	OutcomeRefusedByRule: "this run was not allowed to connect to this address",
	OutcomeNotAttempted:  "this address was never tried, because the layer ran out of time first",
}

// AllConnectOutcomes lists every outcome exactly once, in declaration order.
var AllConnectOutcomes = []ConnectOutcome{
	OutcomeConnected,
	OutcomeRefused,
	OutcomeTimeout,
	OutcomeReset,
	OutcomeUnreachable,
	OutcomeRefusedByRule,
	OutcomeNotAttempted,
}

// Valid reports whether o is one of the declared outcomes.
func (o ConnectOutcome) Valid() bool {
	_, ok := connectOutcomeMeanings[o]
	return ok
}

// Meaning returns the English sentence for o, or the empty string outside the
// list.
func (o ConnectOutcome) Meaning() string { return connectOutcomeMeanings[o] }

// String makes ConnectOutcome printable without a conversion at every call site.
func (o ConnectOutcome) String() string { return string(o) }

// Reached reports whether the attempt actually left this machine.
//
// It is the difference between a row that says something about the target and a
// row that says something about us. A refusal by our own allowed set never
// reached anybody.
func (o ConnectOutcome) Reached() bool {
	return o != OutcomeRefusedByRule && o != OutcomeNotAttempted
}

// TCPConnect is the body of a connection finding: one attempt, to one address.
//
// ONE FINDING PER ADDRESS, for the same reason L1 produces one per answer. A
// name behind four addresses where one is unreachable is the "hangs, then works"
// class of fault, and a single folded row would report it as either working or
// broken - both of which are wrong.
type TCPConnect struct {
	// Address is where we tried to connect, and it is an ADDRESS.
	//
	// NEVER A HOST NAME, and the contract refuses one. L3 connects to addresses
	// that L1 resolved; a name here would be a second, quieter answer to the
	// question L1 already answered, and the two would drift.
	Address string
	// Port is the port that was tried.
	//
	// It repeats on every row although every row in one run shares it, for the
	// same reason the body sits under a key equal to its kind: this document is
	// read in a ticket, without the schema beside it.
	Port int
	// Outcome is what happened, from the closed list above.
	Outcome ConnectOutcome
	// DurationMS is how long the attempt took, in whole milliseconds.
	//
	// IT IS ZERO WHEN NOTHING WAS ATTEMPTED, and the contract refuses anything
	// else in that case. A duration beside "we were not allowed to try" would be
	// a measurement of something that did not happen.
	//
	// ONE OBSERVATION, NEVER A COMPARISON - D13 part 2, decided for L1 and
	// binding here for the same measured reason: the second attempt benefits from
	// whatever the first one warmed.
	DurationMS int64
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
// Certificate is one certificate exactly as a server presented it.
//
// NOTHING HERE SAYS WHETHER IT IS TRUSTED, and the absence is the contract
// rather than a gap - ADR46. Trust is one answer per runtime, not one per
// certificate, and it belongs to L5. A "trusted" field here would quietly claim
// this machine has a single trust store, which is the claim the whole product
// exists to disprove.
type Certificate struct {
	// Subject and Issuer are rendered by ONE function, on the adapter side, and
	// that is what makes comparing them sound. Two spellings of one distinguished
	// name would make a complete chain look broken - the same failure tcp.Target
	// exists to prevent one layer down.
	//
	// SUBJECT MAY BE EMPTY AND THAT IS LEGAL RATHER THAN BROKEN - ADR47. RFC 5280
	// section 4.1.2.6 REQUIRES an empty subject when the identity lives only in a
	// critical subjectAltName, so a contract refusing it would refuse a correctly
	// issued certificate - and, because a refused finding degrades the layer,
	// certdoctor would answer "I could not assess this" about a server that is
	// perfectly fine. Measured on 2026-08-18: crypto/x509 mints exactly that shape
	// and marks the extension critical by itself.
	Subject string
	// Issuer is required, and it is the asymmetry that makes the rule above safe:
	// RFC 5280 section 4.1.2.4 says the issuer field MUST contain a non-empty
	// distinguished name. An empty one is therefore either a malformed certificate
	// or a defect on our side, and it is also the value chain completeness is
	// compared against.
	Issuer string
	// DNSNames is what the certificate says it is FOR - the subjectAltName DNS
	// entries, in the order presented.
	//
	// IT IS THE FIELD A MODERN CLIENT ACTUALLY MATCHES ON, and leaving it out was
	// the real defect ADR47 found while looking at something else. RFC 6125
	// section 6.4.4: a client MUST NOT match on the common name when the
	// certificate presents a DNS-ID. A report showing only the subject was
	// therefore showing the deprecated field and hiding the authoritative one -
	// in a product whose whole question is why somebody's client will not accept
	// this server.
	//
	// EMPTY IS A STATEMENT, NEVER "we did not look": this is read off the
	// certificate every time, so an empty list means the certificate presents no
	// DNS name at all.
	DNSNames []string
	// NotBefore and NotAfter are reported, never judged. Whether "expired" means
	// anything depends on a clock this program does not own.
	NotBefore time.Time
	NotAfter  time.Time
	// FingerprintSHA256 identifies this certificate exactly, and is the evidence
	// inviolable rule 21 requires beside any claim about interception. IT IS
	// NEVER MASKED: it is the answer somebody came here for, and it names no
	// person, host or network.
	FingerprintSHA256 string
	// IsCA is the basic constraint as presented.
	IsCA bool
}

// TLSHandshake is what one address presented when the connection was upgraded.
//
// ONE ROW PER ADDRESS, AND THE FULL CHAIN ON ONE OF THEM - ADR45. Measured on
// 2026-08-17: every address of example.com and of cloudflare.com presented a
// byte-identical leaf, so agreement is the norm and repeating four chains would
// be four times the page for none of the information. MatchesFirstAddress
// carries the comparison instead, and a false there is a finding rather than a
// footnote: it is the only signal this program has for a middlebox sitting on
// one path and not another.
type TLSHandshake struct {
	// Address and Port are present on every row, including one where nothing
	// happened - a row that cannot be attributed is a row nobody can act on.
	Address string
	Port    int
	// Completed says whether a handshake happened at all.
	Completed bool
	// NotCompleted is the short English phrase saying why not, and is set only
	// when Completed is false. Silence about a failure is forbidden - inviolable
	// rule 1 - so the two fields are checked against each other below.
	NotCompleted string

	// Version is the negotiated version as a name, and it is the ONE place in
	// this program where a name rather than a number is the identity. The reason
	// is that the set is closed and tiny - four values, standardised, unchanged
	// for years - unlike the cipher suite registry, which is open and large. A
	// consumer branching on the version string is branching on a closed list;
	// one branching on a cipher name would be parsing our rendering of a number.
	Version string
	// CipherSuite is the IANA number that came off the wire. THE NUMBER IS THE
	// FACT - inviolable rule 19. Branch on this.
	CipherSuite uint16
	// CipherSuiteName is our rendering of that number, for a person reading the
	// report. Never branch on it.
	CipherSuiteName string
	// ALPN is the protocol agreed, or empty when none was.
	ALPN string
	// ServerName is what WE sent in SNI - ours, not theirs. It says which name
	// the certificate below was chosen for.
	ServerName string
	// ClientCertificateRequested says the server asked us to authenticate. It is
	// one of the commonest causes of "works in the browser, fails in the tool",
	// and it is invisible from a browser that already holds a certificate.
	ClientCertificateRequested bool
	// LeafFingerprintSHA256 is present on every completed row, including the ones
	// that carry no chain, because it is what the comparison below is made of.
	LeafFingerprintSHA256 string
	// ChainComplete is a STRUCTURAL verdict answered from the presented bytes
	// alone: the issuer of the leaf is among the certificates that arrived, or
	// the leaf signed itself. No trust store is consulted, which is exactly why
	// this question belongs to L4 and trust does not.
	ChainComplete bool
	// MatchesFirstAddress is nil on the row carrying the chain and set on every
	// other completed row.
	MatchesFirstAddress *bool
	// Chain is what the server sent, leaf first, on one row only.
	Chain []Certificate
}

// breach is the half of this body that is PROHIBITIONS, and that is where its
// value is - the same shape the resolution and connection bodies have.
func (t *TLSHandshake) breach() string {
	switch {
	case t.Address == "":
		return "carries no address, and a row nobody can attribute is a row nobody can act on"
	case t.Port < 1 || t.Port > 65535:
		return fmt.Sprintf("reports port %d, which is not a port", t.Port)
	}

	if !t.Completed {
		// NOTHING WAS NEGOTIATED, SO NOTHING MAY BE FILLED IN. A version beside a
		// handshake that did not happen is a measurement of something that did
		// not occur - the same rule that keeps a duration off a connection which
		// never left this machine.
		switch {
		case t.NotCompleted == "":
			return "says no handshake completed and does not say why, and silence about a failure is forbidden"
		case t.Version != "" || t.CipherSuite != 0 || t.ALPN != "":
			return "says no handshake completed and still reports what was negotiated, which would be a measurement of something that did not happen"
		case len(t.Chain) != 0 || t.LeafFingerprintSHA256 != "":
			return "says no handshake completed and still carries a certificate, which nothing could have presented"
		case t.ChainComplete:
			return "says no handshake completed and calls the chain complete, and there was no chain"
		}
		return ""
	}

	switch {
	case t.NotCompleted != "":
		return "says the handshake completed and also says why it did not"
	case t.LeafFingerprintSHA256 == "":
		return "says the handshake completed and carries no leaf fingerprint, and the fingerprint is what identifies what was presented"
	case len(t.Chain) > 0 && t.MatchesFirstAddress != nil:
		return "carries the full chain and a comparison against the first address, and the row carrying the chain IS the first address"
	case len(t.Chain) == 0 && t.MatchesFirstAddress == nil:
		return "carries neither the chain nor a comparison against the one that does, so it says nothing about what this address presented"
	case len(t.Chain) > 0 && t.Chain[0].FingerprintSHA256 != t.LeafFingerprintSHA256:
		return "reports a leaf fingerprint that is not the fingerprint of the first certificate in its own chain"
	}
	for i, c := range t.Chain {
		if c.Issuer == "" {
			// THE SUBJECT IS DELIBERATELY NOT CHECKED HERE ANY MORE - ADR47. It
			// used to be, and that rule refused a certificate RFC 5280 requires to
			// look exactly that way. The issuer stays required because the same
			// RFC forbids an empty one, so it can only mean a malformed
			// certificate or a defect here.
			return fmt.Sprintf("carries a certificate at position %d with no issuer at all, which RFC 5280 forbids - "+
				"so nothing can say who signed it", i)
		}
		if c.FingerprintSHA256 == "" {
			return fmt.Sprintf("carries a certificate at position %d with no fingerprint, and the fingerprint is the evidence a claim about interception has to travel with", i)
		}
	}
	return ""
}

// TrustStore is one trust store, belonging to one instance of one runtime, and
// what that store makes of the chain L4 saw.
//
// THE UNIT IS THE STORE AND THAT IS THE WHOLE DESIGN - ADR48. Measured on the
// owner's machine 2026-08-18: SIX Java stores (four JDKs plus a JRE 8 in both
// bitnesses) and TWO curl binaries on PATH, one of them shipped beside git - and
// git, from that same install, reads a different store than the curl next to it.
// A shape of one row per runtime would have had to pick one of the six and call
// it "java", which is the single-store claim this product exists to disprove.
//
// NOTHING HERE IS A PATH WE INVENTED. StorePath is read off this machine, because
// the last column of the matrix is worth nothing if the path is a template -
// docs/20 rule 6.
type TrustStore struct {
	// Runtime is the family - "java", "curl", "git". Several instances share it,
	// so it is NOT an identity on its own.
	Runtime string
	// Instance is what tells two stores of one runtime apart, and it is the
	// identity a person reads. Required for the same reason an address is
	// required on a TCP row: a row nobody can attribute is a row nobody can act
	// on.
	Instance string
	// Variant is the kind within the family - "jdk" or "jre" for java - and is
	// empty for a runtime that has no variants. It exists because a fix aimed at
	// the wrong variant edits the wrong file.
	Variant string
	// Architecture tells apart two installs that differ ONLY by "Program Files
	// (x86)". Measured: jre1.8.0_501 exists in both bitnesses, with separate
	// stores and therefore separate answers.
	Architecture string

	// StorePath is where this store lives on THIS machine, and is empty only
	// when StoreForm says the store is not a file.
	StorePath string
	// StoreForm says whether the store is a file we can point at or the
	// platform's own. It decides whether StorePath can be empty, so it is
	// checked rather than trusted.
	StoreForm StoreForm
	// Backend is the TLS implementation the runtime chose, where it chooses one
	// - "schannel" or "openssl" - and is empty where it does not. IT DECIDES
	// WHICH STORE APPLIES, so it is load bearing rather than descriptive:
	// measured, git says openssl and reads its own bundle while the curl in the
	// same install is on schannel and asks Windows.
	Backend string
	// TrustAnchorCount is how many anchors this store holds. It is evidence, not
	// a verdict, and it is not a secret - it is not redacted, for the same
	// reason a fingerprint is not.
	TrustAnchorCount int

	// TrustsPresentedChain is L5's answer and is nil when the store could not be
	// assessed at all. NIL IS A THIRD STATE, not a false: "this store does not
	// trust the chain" and "this store could not be read" send a person to two
	// different places. Same shape as MatchesFirstAddress above.
	TrustsPresentedChain *bool
	// NotAssessed is the short English phrase saying why there is no answer, and
	// is set exactly when TrustsPresentedChain is nil. Silence about a failure is
	// forbidden - inviolable rule 1 - so the two are checked against each other.
	NotAssessed string

	// SelectedBy names what points AT this instance - "JAVA_HOME", "PATH". It is
	// never nil and an empty slice is an answer: this store belongs to an
	// instance nothing on this machine selects by default, which is true of five
	// of the six Java stores measured here.
	//
	// IT IS NOT A DETECTION MECHANISM AND MUST NOT BE READ AS ONE - ADR48 part
	// 4. Measured: JAVA_HOME names one of six, PATH names one of two curls.
	SelectedBy []string

	// TrustFailure says WHICH WAY this store refused the chain, and is set
	// exactly when TrustsPresentedChain is a false.
	//
	// A REFUSAL WITH NO REASON IS THE SAME SILENCE NotAssessed EXISTS TO PREVENT,
	// one field over. "The issuer is nobody I have heard of" and "I know this
	// issuer and the certificate expired" send a person to two different places,
	// and only the first is something a trust store can be made to fix.
	TrustFailure TrustFailure
	// Fix is the command that would make THIS store accept THIS chain, and is
	// nil whenever there is nothing honest to say.
	//
	// NIL IS THE COMMON CASE AND THAT IS DELIBERATE. Measured on the bench
	// 2026-08-19: a server that withheld its intermediate turned every trust row
	// red, and not one of them had a fix - the fault was the server's, and a
	// command here would have sent somebody to edit a store that was fine. The
	// conditions that have to hold together before this is filled in live in one
	// file, which is what the remediation guard defends.
	Fix *Fix
}

// TrustFailure is the way a store refused a chain.
//
// The list is closed and has a registry, like every other closed list here. It
// exists because the answer decides whether a fix is even possible: only an
// unknown authority is something adding a certificate can repair.
type TrustFailure string

const (
	// UnknownAuthority - the store holds nothing that signed what arrived. THE
	// ONLY FAILURE A TRUST STORE FIX ADDRESSES.
	UnknownAuthority TrustFailure = "unknown_authority"
	// Expired - a certificate in the path is past its validity. Importing a
	// certificate does not move a clock.
	Expired TrustFailure = "expired"
	// NotYetValid - a certificate in the path starts later than now, which is
	// usually a wrong clock at one of the two ends.
	NotYetValid TrustFailure = "not_yet_valid"
	// OtherFailure - the path could not be built for a reason this program does
	// not classify. It is an honest answer and it is NOT a licence to guess a
	// fix.
	OtherFailure TrustFailure = "other"
)

var trustFailureMeanings = map[TrustFailure]string{
	UnknownAuthority: "the store holds no certificate that signed what the server sent",
	Expired:          "a certificate in the path is past its validity",
	NotYetValid:      "a certificate in the path is not valid yet",
	OtherFailure:     "the path could not be built, for a reason this program does not classify",
}

// Valid reports whether the failure is one this program declared.
func (f TrustFailure) Valid() bool {
	_, ok := trustFailureMeanings[f]
	return ok
}

// Meaning returns the declared meaning, for a surface that wants to explain it.
func (f TrustFailure) Meaning() string { return trustFailureMeanings[f] }

// String makes TrustFailure printable without a conversion at every call site.
func (f TrustFailure) String() string { return string(f) }

// Fix is a command this program produces and a PERSON RUNS.
//
// IT IS THE ONLY THING HERE THAT LEAVES THE REPORT AND ACTS. Everything else
// this program emits is a description that is wrong at worst; a command is wrong
// AND executed. That difference is why the fields below are shaped to make the
// uncomfortable half impossible to omit: what has to be filled in by hand, and
// what rights it needs, are fields rather than sentences somebody might trim.
type Fix struct {
	// Command is the literal command line, carrying REAL paths from this machine
	// - docs/20 rule 6. A template with a specimen path in it is worth nothing,
	// because the whole value of the last column is that it names the file that
	// is actually there.
	Command string
	// Placeholders names every part of Command the person must replace, spelled
	// exactly as it appears there. It is NEVER nil, and an empty slice says the
	// command is ready to paste.
	//
	// IT IS A FIELD RATHER THAN PROSE because a consumer must be able to tell a
	// ready command from a draft without reading English. At least one entry is
	// normal: the certificate to import is not on the wire - a middlebox root
	// never is - and inviolable rule 14 forbids this program writing it out.
	Placeholders []string
	// RequiresElevation says the command needs administrator or root rights, and
	// Elevation says why in one sentence. docs/20 rule 5 wants that said BEFORE
	// the command is run, because finding out from a permission error is finding
	// out too late. Elevation is set exactly when RequiresElevation is true.
	RequiresElevation bool
	Elevation         string
	// Caveat is a limit worth knowing that does not stop the command working,
	// and is empty when there is none. It is where docs/08 section 4 lands: an
	// option that behaves differently in somebody's arrangement has to say so.
	Caveat string
}

func (f *Fix) breach() string {
	switch {
	case f.Command == "":
		return "carries a remediation with no command in it"
	case f.Placeholders == nil:
		return "carries a remediation with no placeholder list, and an empty one is the answer for a command that is ready to paste"
	case f.RequiresElevation && f.Elevation == "":
		return "says its remediation needs elevated rights and does not say why"
	case !f.RequiresElevation && f.Elevation != "":
		return "says its remediation needs no elevated rights and explains why it does"
	}
	for _, placeholder := range f.Placeholders {
		if placeholder == "" {
			return "names an empty placeholder, which no reader could find in the command"
		}
		if !strings.Contains(f.Command, placeholder) {
			return fmt.Sprintf("names the placeholder %q, which does not appear in the command it belongs to", placeholder)
		}
	}
	return ""
}

// StoreForm says what sort of thing the store is.
//
// The list is closed and has a registry, like every other closed list here: a
// value outside it is a defect in OUR translation, not news from a machine.
type StoreForm string

const (
	// StoreFile - a file this program can name and a person can edit.
	StoreFile StoreForm = "file"
	// StoreSystem - the platform's own store, which has no path to hand out.
	StoreSystem StoreForm = "system"
)

var storeFormMeanings = map[StoreForm]string{
	StoreFile:   "a file on this machine that holds the anchors",
	StoreSystem: "the platform's own store, which has no path to point at",
}

// Valid reports whether the form is one this program declared.
func (f StoreForm) Valid() bool {
	_, ok := storeFormMeanings[f]
	return ok
}

// Meaning returns the declared meaning, for a surface that wants to explain it.
func (f StoreForm) Meaning() string { return storeFormMeanings[f] }

// String makes StoreForm printable without a conversion at every call site.
func (f StoreForm) String() string { return string(f) }

func (t *TrustStore) breach() string {
	switch {
	case t.Runtime == "":
		return "carries no runtime, and a store belonging to nothing is a row nobody can act on"
	case t.Instance == "":
		return "carries no instance, and a runtime alone cannot tell two stores of it apart"
	case !t.StoreForm.Valid():
		return fmt.Sprintf("carries the store form %q, which is outside the registry", t.StoreForm)
	case t.StoreForm == StoreFile && t.StorePath == "":
		return "calls the store a file and gives no path, and a path is the one thing a person needs to act"
	case t.TrustAnchorCount < 0:
		return fmt.Sprintf("reports %d trust anchors, which is not a count", t.TrustAnchorCount)
	// NEVER nil, and an empty slice is the answer. A nil here would be a
	// statement about US - that nobody looked - dressed as one about the machine.
	case t.SelectedBy == nil:
		return "carries no selection list at all, and an empty one is the answer when nothing selects this instance"
	}

	// THE THIRD STATE IS CHECKED IN BOTH DIRECTIONS. An unassessed store with no
	// reason is silence about a failure, and an assessed one carrying a reason
	// says two things at once - either way a consumer cannot tell "does not
	// trust" from "could not be read", which is the one distinction this row
	// exists to make.
	switch {
	case t.TrustsPresentedChain == nil && t.NotAssessed == "":
		return "gives no verdict on the presented chain and does not say why, and silence about a failure is forbidden"
	case t.TrustsPresentedChain != nil && t.NotAssessed != "":
		return "gives a verdict on the presented chain and also says why it could not"
	case t.TrustsPresentedChain == nil && t.TrustAnchorCount != 0:
		return "could not read the store and still counts anchors in it, which nothing could have counted"
	}

	// A REFUSAL SAYS WHICH WAY, AND ONLY A REFUSAL MAY. The pairing is checked in
	// both directions for the same reason NotAssessed is: a store that refused a
	// chain and will not say how is silence about a failure, and one that
	// accepted it while naming a failure says two things at once.
	refused := t.TrustsPresentedChain != nil && !*t.TrustsPresentedChain
	switch {
	case refused && t.TrustFailure == "":
		return "refuses the presented chain and does not say in which way, and only one of those ways is fixable"
	case !refused && t.TrustFailure != "":
		return "names a way of refusing the presented chain that it did not refuse"
	case t.TrustFailure != "" && !t.TrustFailure.Valid():
		return fmt.Sprintf("carries the trust failure %q, which is outside the registry", t.TrustFailure)
	}

	return t.remediationBreach()
}

// remediationBreach is where the contract refuses a command that would waste
// somebody's time or send them to the wrong place.
//
// THESE ARE NOT STYLE RULES. Each one is a measured way this program could hand
// out a command that does nothing. A fix on a store with no path names no file.
// A fix on a store that ACCEPTS the chain fixes nothing. A fix on a store that
// refused for a reason other than an unknown authority - an expired certificate,
// a clock that is wrong - asks somebody to import a certificate that will not
// help, and they will wait for an effect that is never coming.
//
// THE CONDITION THIS CANNOT CHECK IS SAID HERE RATHER THAN LEFT OUT. Whether the
// chain the server sent was structurally COMPLETE is a fact about L4, not about
// a store, so it cannot live on this row - and it is the condition that
// separates "your store is missing a CA" from "the server did not send its
// intermediate". It is enforced where the fix is built, and it has its own test.
func (t *TrustStore) remediationBreach() string {
	if t.Fix == nil {
		return ""
	}
	refused := t.TrustsPresentedChain != nil && !*t.TrustsPresentedChain
	switch {
	case !refused:
		return "carries a remediation command for a store that did not refuse the presented chain"
	case t.TrustFailure != UnknownAuthority:
		return fmt.Sprintf(
			"carries a remediation command for a store that refused the chain because %s, which importing a certificate does not repair",
			t.TrustFailure.Meaning())
	case t.StoreForm != StoreFile:
		return "carries a remediation command for a store that is not a file, so the command could only name a file nobody chose"
	case t.StorePath == "":
		return "carries a remediation command for a store with no path, and docs/20 rule 6 is that the path is the real one"
	}
	if broken := t.Fix.breach(); broken != "" {
		return broken
	}
	return ""
}

// SigningAuthority says who signed the leaf and how widely this machine holds
// that signer. ONE PER RUN, because the question is about the machine.
//
// WHAT IT IS FOR. The commonest failure this product exists to explain is one
// tool accepting a name and another refusing it on the same machine at the same
// moment. That happens when the signer is present in some stores here and not in
// others, and this is the row that says so in one line, with the evidence
// somebody would paste into a ticket.
//
// WHAT IT DELIBERATELY DOES NOT SAY. It never concludes that traffic is being
// intercepted. Measured on the bench 2026-08-19: a middlebox re-signing traffic
// and an honest internal server under a company's own certificate authority
// produce identical values in every field here, and the structural difference
// that remained - an incomplete chain - disappeared as soon as the middlebox was
// given an intermediate to sign with. Accusing on these fields would accuse
// scenario S-3, which is an ordinary corporate machine working as intended.
type SigningAuthority struct {
	// Issuer is the distinguished name of whoever signed the leaf. Required:
	// RFC 5280 section 4.1.2.4 forbids an empty issuer, so an empty one here
	// means a broken certificate or a defect of ours - the same asymmetry
	// Certificate carries.
	//
	// IT IS EVIDENCE AND NOT A TEST. Nothing in this program branches on the
	// text of it, and O11 is why: recognising interception by an issuer's name
	// would mean every appliance nobody has heard of goes unnoticed.
	Issuer string
	// LeafFingerprint is the SHA-256 of the leaf, so the claim above can be
	// checked by somebody else with their own tools. Required, and not redacted
	// - it is the evidence the reader came for, like every other fingerprint
	// here.
	LeafFingerprint string
	// HeldBy is the measurement: how many of the stores that could be assessed
	// hold an anchor closing this chain.
	HeldBy AnchorHolding
	// TrustingStores and RefusingStores name the stores on each side, so that
	// "some of them" is never left as an adjective. NEITHER IS EVER NIL and an
	// empty slice is an answer - the same shape SelectedBy and DNSNames have.
	//
	// THEY CARRY INSTANCE NAMES, WHICH ARE OFTEN PATHS, so they go through
	// redaction like every other borrowed string.
	TrustingStores []string
	RefusingStores []string
	// Caveat is the one sentence saying what this measurement does NOT settle,
	// and it is required on every holding rather than only on the awkward one.
	//
	// IT IS HOW INVIOLABLE RULE 21 TRAVELS. That rule asks for the heuristic to
	// be named as a heuristic IN THE REPORT, and a hedge that lives only in the
	// terminal renderer is a hedge the --json consumer never sees - the same
	// parity rule 12 states for every other finding. It is our own prose, names
	// nobody, and is therefore never redacted.
	Caveat string
}

// AnchorHolding is how widely this machine holds the signer of a chain.
//
// THE LIST IS CLOSED AND EVERY VALUE IS A COUNT RATHER THAN A CONCLUSION. This
// is the same discipline CipherSuite follows by carrying the IANA number with
// the name beside it: what came off the machine is one thing, what it might mean
// is another, and a consumer that branches on the first cannot be broken by us
// changing our mind about the second.
type AnchorHolding string

const (
	// HeldByAllStores - every store that could be assessed holds an anchor for
	// this chain. The ordinary answer for a public certificate authority, and
	// the ordinary answer on a healthy machine.
	HeldByAllStores AnchorHolding = "all_stores"
	// HeldBySomeStores - some hold it and some do not, which is why one tool
	// works here and another does not.
	//
	// THIS IS THE INTERESTING VALUE AND IT IS STILL NOT AN ACCUSATION. It says
	// the signer is present on this machine and did not arrive with every
	// runtime, which is true of an inspection appliance and equally true of a
	// company's own certificate authority.
	HeldBySomeStores AnchorHolding = "some_stores"
	// HeldByNoStores - nothing here holds it, so nothing here accepts the name.
	// A browser on this machine would refuse it too, which is worth saying
	// because it tells the reader this is not a per-runtime problem.
	HeldByNoStores AnchorHolding = "no_stores"
)

var anchorHoldingMeanings = map[AnchorHolding]string{
	HeldByAllStores:  "every trust store that could be assessed holds an anchor for this chain",
	HeldBySomeStores: "some stores here hold an anchor for this chain and others do not",
	HeldByNoStores:   "no trust store on this machine holds an anchor for this chain",
}

// Valid reports whether this is one of the declared holdings.
func (h AnchorHolding) Valid() bool {
	_, known := anchorHoldingMeanings[h]
	return known
}

// Meaning is the one line the schema publishes for this value.
func (h AnchorHolding) Meaning() string { return anchorHoldingMeanings[h] }

// String is the wire spelling.
func (h AnchorHolding) String() string { return string(h) }

// AllAnchorHoldings lists every holding exactly once, in declaration order.
var AllAnchorHoldings = []AnchorHolding{HeldByAllStores, HeldBySomeStores, HeldByNoStores}

// breach refuses the states in which the counted answer and the named stores
// would be telling two different stories.
//
// THE THREE CROSS-CHECKS ARE THE POINT OF THIS FUNCTION. A holding is a summary
// of two lists, so a holding that disagrees with its own lists is either a
// counting mistake of ours or an accusation assembled by hand somewhere it
// should not have been. The guard on the file keeps the judgement in one place
// and this keeps the shape honest wherever it arrives from.
func (a *SigningAuthority) breach() string {
	switch {
	case a.Issuer == "":
		return "names no issuer, and RFC 5280 section 4.1.2.4 forbids a certificate with an empty one"
	case a.LeafFingerprint == "":
		return "carries no fingerprint, so the claim it makes could not be checked against anybody else's tools"
	case !a.HeldBy.Valid():
		return fmt.Sprintf("says the signer is held by %q, which is outside the registry", a.HeldBy)
	case a.TrustingStores == nil:
		return "leaves the trusting stores unset, and an empty list is an answer while a missing one is not"
	case a.RefusingStores == nil:
		return "leaves the refusing stores unset, and an empty list is an answer while a missing one is not"
	case a.Caveat == "":
		return "carries no caveat, and a claim of this sort travels with what it does not settle or it does not travel"
	}

	switch a.HeldBy {
	case HeldByAllStores:
		if len(a.TrustingStores) == 0 || len(a.RefusingStores) > 0 {
			return "says every store holds the signer while naming a store that refused it"
		}
	case HeldBySomeStores:
		if len(a.TrustingStores) == 0 || len(a.RefusingStores) == 0 {
			return "says some stores hold the signer and some do not, and does not name both sides"
		}
	case HeldByNoStores:
		if len(a.TrustingStores) > 0 || len(a.RefusingStores) == 0 {
			return "says no store holds the signer while naming a store that does"
		}
	}
	return ""
}

var findingBodies = map[FindingKind]func(Finding) bool{
	FindingEnvironmentVariable: func(f Finding) bool { return f.EnvironmentVariable != nil },
	FindingNameResolution:      func(f Finding) bool { return f.NameResolution != nil },
	FindingTCPConnect:          func(f Finding) bool { return f.TCPConnect != nil },
	FindingTLSHandshake:        func(f Finding) bool { return f.TLSHandshake != nil },
	FindingTrustStore:          func(f Finding) bool { return f.TrustStore != nil },
	FindingSigningAuthority:    func(f Finding) bool { return f.SigningAuthority != nil },
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
	case f.TCPConnect != nil:
		return f.TCPConnect.breach()
	case f.TLSHandshake != nil:
		return f.TLSHandshake.breach()
	case f.TrustStore != nil:
		return f.TrustStore.breach()
	case f.SigningAuthority != nil:
		return f.SigningAuthority.breach()
	}
	return ""
}

// breach refuses the states that would make a connection row say something
// nobody measured.
//
// HALF OF THIS IS PROHIBITIONS AND THAT IS WHERE ITS VALUE IS, the same shape
// the resolution body has. The two most useful columns of this row - the address
// and the time - are the two a plausible mistake fills in wrongly, and a filled
// in row reads like a measurement.
func (t *TCPConnect) breach() string {
	if t.Address == "" {
		return "carries a connection attempt to no address at all"
	}
	if _, err := netip.ParseAddr(t.Address); err != nil {
		// THE ONE THAT MATTERS: a host name where an address belongs. L1 answers
		// what a name resolves to; this layer connects to what came back. A name
		// here would be a second answer to L1's question, arriving from a layer
		// that never asked it.
		return fmt.Sprintf("says it connected to %q, which is a name rather than an address - "+
			"this layer connects to what the previous one resolved", t.Address)
	}
	switch {
	case t.Port < 1 || t.Port > 65535:
		return fmt.Sprintf("carries port %d, which is not a port", t.Port)
	case !t.Outcome.Valid():
		return fmt.Sprintf("carries the outcome %q, which is outside the closed list", t.Outcome)
	case t.DurationMS < 0:
		return fmt.Sprintf("says connecting to %s took %d milliseconds", t.Address, t.DurationMS)
	case !t.Outcome.Reached() && t.DurationMS != 0:
		// An attempt that never left this machine - refused by our own rule, or
		// never tried at all - has nothing whose duration this could be.
		return fmt.Sprintf("says %s was never actually tried (%s) and still reports %d milliseconds spent",
			t.Address, t.Outcome, t.DurationMS)
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
