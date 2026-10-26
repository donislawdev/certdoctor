package proxy

import (
	"context"
	"fmt"
	"strings"

	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// EnvironmentRules are the readings of NO_PROXY this program reports for the
// environment stack.
//
// THE ENVIRONMENT STACK CARRIES NO RULE OF ITS OWN AND THAT IS THE PRODUCT.
// Lens.Rule is a property of the place a list lives in, and it is empty here
// because one NO_PROXY is read differently by different runtimes - so the
// reading belongs to whoever is being asked about rather than to the variable.
//
// THERE ARE TWO OF THEM AND NOT THREE. Go reads that variable a third way and
// its wording is quoted beside RuleNoProxyCurl, but Go is not one of the
// thirteen probes this program asks about, so a row reporting its reading would
// be an answer about a runtime nothing here examines - the rule ADR88 wrote down
// for this vocabulary, read from the reporting end.
var EnvironmentRules = []Rule{RuleNoProxyCurl, RuleNoProxyDotNet}

// Input is everything L2 was given by the entry point.
type Input struct {
	// Lenses hands back what each place on this machine says about proxying.
	//
	// IT IS A PORT AND NOT A FIELD, so that reading a machine's configuration
	// happens INSIDE this layer's budget rather than before the walk starts. On
	// macOS that reading runs somebody else's process, and a subprocess started
	// outside the walk would spend time no layer is accountable for.
	//
	// A nil one is a defect here rather than an answer about a machine, and is
	// reported as one.
	Lenses func(context.Context) []Lens
	// Target is what the user asked about, in the spelling that goes on the
	// wire. Every exception list rule below is asked about THIS host, because a
	// list is only ever an answer about one target.
	Target Target
	// Evaluate fetches one automatic configuration script and runs it against
	// this run's target.
	//
	// IT IS A PORT FOR TWO REASONS AND THE SECOND IS THE BINDING ONE. Fetching
	// reaches the network and running is this program's single deliberate
	// exception to "we execute nobody else's code", so both live in an adapter
	// this package may not import. And like Lenses, it is called INSIDE this
	// layer's budget: a request started before the walk would spend time no
	// layer is accountable for.
	//
	// A nil one is legal and is reported as ours: every script comes back
	// unfetched with a sentence saying the gap is in certdoctor. That is the
	// safe direction - a forgotten wire cannot make a machine look like it has
	// no script.
	Evaluate Evaluate
	// ScriptURL is an address the USER named, and it is the only input to this
	// layer that does not come off the machine.
	//
	// IT EXISTS BECAUSE THE MACHINE IS NOT ALWAYS ABLE TO NAME ONE. Only the
	// Windows stacks carry an AutoConfigURL; a Linux machine has no place all
	// its programs read, so a run there could never reach this half of the
	// layer - and neither could the bench, which is Linux. It is also the
	// question a helpdesk actually has: somebody is handed a script address and
	// wants to know where it sends one URL.
	//
	// ITS ADDRESS IS IN THE ALLOWED SET BEFORE THE WALK STARTS, because the
	// user typed it - the same footing as the target itself, and the one input
	// here that needs no widening during the run.
	ScriptURL string
	// Challenge asks one proxy whether it wants credentials.
	//
	// IT IS A PORT FOR THE REASON Evaluate IS ONE: the exchange reaches the
	// network, so it lives in an adapter this package may not import, and it is
	// called INSIDE this layer's budget rather than before the walk.
	//
	// A nil one is legal and is reported as ours: every endpoint comes back
	// unasked with a sentence saying the gap is in certdoctor. That is the safe
	// direction - a forgotten wire cannot make a proxy look as though it let
	// this run through.
	Challenge ChallengeAsk
}

// Result is what L2 established.
type Result struct {
	Status   status.Status
	Reason   status.Reason
	Detail   string
	Findings []report.Finding
	// Endpoints are the proxies this run concluded would be used for this
	// target, deduplicated and in report order.
	//
	// IT IS NOT A FINDING AND THAT IS THE POINT OF IT. The orchestrator reads
	// this list to widen the set of places this program may connect to, before
	// asking the second half of this layer to speak to any of them - so the
	// widening happens where every other widening in this program happens, and
	// never inside the layer that benefits from it.
	Endpoints []Endpoint
}

// Sentences for the cases where the layer establishes nothing.
const (
	noLenses = "no way to read this machine's proxy configuration was supplied, so no place was asked"
	noPlaces = "the reading of this machine's proxy configuration came back naming no place at all, " +
		"and this program always asks at least about its own environment"
	noReading = "this layer was asked for its answer before this machine's proxy configuration had been " +
		"read at all, which is a gap in certdoctor rather than anything about this machine"
)

// Reading is what this machine's proxy configuration says, before anything has
// been asked of the network.
//
// IT EXISTS SO THAT THE ORCHESTRATOR HAS SOMEWHERE TO STAND BETWEEN READING AND
// REACHING. Both halves of what this layer connects to - the address of a script
// this machine names, and the proxies that reading arrives at - are learned
// DURING the walk and cannot be in the allowed set before it. Somebody has to
// put them there, and inviolable rule 16 says who: the entry point, through the
// orchestrator, never the layer itself.
//
// ONLY Scripts IS EXPORTED, and the rest is deliberately not. What the caller
// needs is the list of addresses it must authorise; the lenses and the script
// entries behind them are this package's own working, and a caller holding them
// would be a second place able to decide what this layer looked at.
type Reading struct {
	// Scripts are the addresses of the automatic configuration scripts this run
	// will ask about, deduplicated, in report order, with any credential
	// already cut off where it was read.
	Scripts []string

	lenses  []Lens
	scripts []script
	failure string
}

// Read asks every place this machine keeps proxy configuration what it holds,
// and names the scripts that reading points at. It reaches nothing.
//
// IT IS THE FIRST OF THIS LAYER'S THREE STEPS AND THE ONLY ONE THAT TOUCHES NO
// NETWORK, which is what makes it the right thing to call before the allowed set
// has been widened by anything this walk discovered.
func Read(ctx context.Context, in Input) Reading {
	if in.Lenses == nil {
		return Reading{failure: noLenses}
	}
	lenses := in.Lenses(ctx)
	if len(lenses) == 0 {
		return Reading{failure: noPlaces}
	}
	scripts := scriptsNamed(in, lenses)
	return Reading{Scripts: addresses(scripts), lenses: lenses, scripts: scripts}
}

// whyNothingWasRead names the gap, in this program's words.
//
// A Reading NOBODY PRODUCED IS OUR DEFECT AND SAYS SO. The zero value can only
// arrive here by way of a caller that skipped Read, and reporting that as a
// machine whose configuration could not be read would put our own wiring fault
// into the report as a fact about somebody's computer.
func whyNothingWasRead(reading Reading) string {
	if reading.failure != "" {
		return reading.failure
	}
	return noReading
}

// Ask says what every place this machine keeps proxy configuration makes of this
// target, and asks whatever automatic configuration scripts it named.
//
// IT REPORTS AND IT DOES NOT REROUTE, which is docs/14 section 3 turned into
// behaviour: proxy variables are diagnostic INPUT, so nothing this layer reads
// changes where any other layer connects. A run of the same target with these
// variables set and without them has to come out the same everywhere else, and
// the bench checks exactly that from outside.
//
// IT TAKES A Reading RATHER THAN DOING THE READING, AND THAT IS THE SEAM THIS
// SLICE ADDED. Between Read and here, the orchestrator authorises the script
// addresses this machine named; between here and Challenge, it authorises the
// proxies this answer arrived at. WPAD discovery still does not happen, it
// arrives with its own slice, and this layer says out loud where that leaves its
// answer short.
func Ask(ctx context.Context, in Input, reading Reading) Result {
	if len(reading.lenses) == 0 {
		return Result{Status: status.Unknown, Reason: status.ReasonProbeError, Detail: whyNothingWasRead(reading)}
	}
	lenses := reading.lenses

	// THE TARGET IS PASSED ON AS IT ARRIVED, AND THE FIRST DRAFT NORMALISED IT
	// HERE. Bypasses does that itself, on every one of its six readings, so a
	// second call could not change a single answer - the shape OBS112 measures,
	// found by the selective mutation run rather than by reading. ServerFor
	// lower cases the protocol for the same reason. What is left for this layer
	// is the summary, and there the spelling somebody typed is the right one to
	// show, exactly as L1 shows the name as it was written.
	findings := make([]report.Finding, 0, len(lenses)+1)
	for _, lens := range lenses {
		findings = append(findings, findingFor(lens, in.Target))
	}
	if class, compared := Compare(lenses); compared {
		findings = append(findings, divergenceFinding(class, lenses))
	}

	// THE SCRIPTS COME AFTER THE PLACES AND THAT IS REPORT ORDER, not an
	// implementation detail: a reader has to see what the machine holds before
	// being told that a file overrides it. Resolving them needs the lenses
	// anyway, because most script addresses are read off a stack.
	scripts := askScripts(ctx, in.Evaluate, reading.scripts)
	for _, one := range scripts {
		findings = append(findings, scriptFinding(one, in.Target))
	}
	result := gradeOf(lenses, scripts, findings, in.Target)
	result.Endpoints = endpointsOf(lenses, scripts, in.Target)
	return result
}

// findingFor turns one lens into one row.
//
// THE SOURCE IS ALWAYS "detected" AND THAT IS ONE DECISION RATHER THAN A
// REPEATED CONSTANT. The four sources grade how strongly a value is known, and
// for this kind the body already carries that grading in Read and Detail. A
// second grading in the envelope would be a second answer to one question, and
// the two would drift - which is the whole reason the glossary allows one name
// per concept.
func findingFor(lens Lens, target Target) report.Finding {
	body := report.ProxyStack{
		Stack:  lens.Stack.String(),
		Read:   lens.Read,
		Detail: lens.Detail,
	}
	if !lens.Read {
		return report.Finding{
			Kind:       report.FindingProxyStack,
			Summary:    fmt.Sprintf("%s could not be read, so what it says about proxying is unknown", lens.Stack.Meaning()),
			Source:     report.SourceDetected,
			ProxyStack: &body,
		}
	}

	body.Servers = serversOf(lens.Servers)
	if selected, ok := ServerFor(lens.Servers, target.Scheme); ok {
		chosen := serverOf(selected)
		body.Selected = &chosen
	}
	body.Bypass, body.BypassSet = lens.Bypass, lens.BypassSet
	body.BypassRules = bypassRulesOf(lens, target)
	body.PACURL = lens.PACURL
	body.AutoDetect = autoDetectOf(lens.AutoDetect)
	body.Caveats = caveatsOf(lens)

	return report.Finding{
		Kind:       report.FindingProxyStack,
		Summary:    summaryOf(lens, body, target),
		Source:     report.SourceDetected,
		ProxyStack: &body,
	}
}

// serversOf carries a lens's list across into the shape a report promises.
//
// NIL STAYS NIL AND EMPTY STAYS EMPTY - ADR20, and here the two mean "this place
// was not read" and "this place was read and names no proxy". A conversion
// producing an empty slice for both would erase the one distinction Lens exists
// to keep.
func serversOf(servers []Server) []report.ProxyServer {
	if servers == nil {
		return nil
	}
	out := make([]report.ProxyServer, 0, len(servers))
	for _, server := range servers {
		out = append(out, serverOf(server))
	}
	return out
}

func serverOf(server Server) report.ProxyServer {
	return report.ProxyServer{
		Protocol:           server.Protocol,
		Scheme:             server.Scheme,
		Address:            server.Address,
		CarriedCredentials: server.CarriedCredentials,
	}
}

// bypassRulesOf asks how this target fares under every reading that applies to
// this place.
//
// ONE PLACE, SEVERAL READINGS, AND ONLY FOR THE ENVIRONMENT. A system stack
// holds its list under one documented rule, so there is one answer. The
// environment holds NO_PROXY, which curl and .NET read differently - measured
// and sourced in this package - so a single "bypassed: yes" there would be true
// of one runtime on the machine and false of another.
func bypassRulesOf(lens Lens, target Target) []report.ProxyBypassRule {
	if !lens.BypassSet {
		return nil
	}
	rules := []Rule{lens.Rule}
	if lens.Stack == StackEnvironment {
		rules = EnvironmentRules
	}
	out := make([]report.ProxyBypassRule, 0, len(rules))
	for _, rule := range rules {
		// An error here is a rule this program does not know or a target with no
		// host, and both are defects on our side rather than facts about a
		// machine - so the row is left out instead of reporting "not excused",
		// which would put our own defect in the report as somebody's proxy
		// setting. ErrUnknownRule says exactly that at the other end.
		bypasses, err := Bypasses(rule, lens.Bypass, target)
		if err != nil {
			continue
		}
		out = append(out, report.ProxyBypassRule{Rule: rule.String(), Bypasses: bypasses})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// autoDetectOf carries this package's three-valued answer across into the report
// contract's own three-valued one.
//
// TWO TYPES FOR ONE CONCEPT IS THE PRICE OF THE ARROW RUNNING ONE WAY. The
// report cannot import this package, so it declares its own Tristate - and both
// of them keep "this place does not answer that question" apart from "it answers
// no", which is the only thing the conversion has to preserve.
func autoDetectOf(state Tristate) report.Tristate {
	switch state {
	case On:
		return report.DeterminedTrue
	case Off:
		return report.DeterminedFalse
	default:
		return report.NotDetermined
	}
}

// caveatsOf is what this row does not settle, said in this program's words.
//
// BOTH SENTENCES BELOW ARE MEASURED OBSERVATIONS RATHER THAN CAUTION. Printing
// them costs a line; leaving them out costs somebody a morning.
func caveatsOf(lens Lens) []string {
	var caveats []string
	if lens.PACURL != "" {
		// OBS111, measured 2026-09-05 by probe S14: writing AutoConfigURL into
		// the registry without touching any enabling switch makes the Windows
		// API hand it straight back, because the switch lives in a blob this
		// program does not read. So the address is a fact of configuration and
		// never a conclusion about behaviour.
		caveats = append(caveats,
			"this place names an automatic configuration script, and naming one is not proof that anything uses it")
	}
	if lens.AutoDetect == On {
		// OBS108, measured the same day: fAutoDetect comes back set on a machine
		// where the registry value does not exist at all, because Windows has
		// WPAD on by default.
		caveats = append(caveats,
			"this place has automatic proxy discovery on, and certdoctor does not perform that discovery, "+
				"so a proxy found that way would not appear here")
	}
	if invalidatedByPath(lens) {
		// OBS109, read at the vendor 2026-09-05: Microsoft says the Internet
		// Settings exception list "is intended to bypass servers, and not URLs",
		// and that entries carrying one are "invalidating the whole list
		// otherwise".
		//
		// IT IS SAID AND NOT ACTED ON. Dropping the whole list on the strength of
		// one sentence nobody here has measured would make this program claim an
		// exception does not exist where it may - inviolable rule 18 read from
		// the side it is easiest to break.
		caveats = append(caveats,
			"an entry of this exception list carries a path, and Microsoft documents such an entry as "+
				"invalidating the whole list - so the exceptions below may not apply on this machine at all")
	}
	return caveats
}

// invalidatedByPath reports whether a Windows exception list holds an entry that
// names a URL rather than a server.
//
// IT ASKS ONLY THE PLACE THE VENDOR WROTE ABOUT. The sentence is about Internet
// Settings, so applying it to a NO_PROXY or to a macOS list would be our reading
// carried somewhere nobody documented it.
func invalidatedByPath(lens Lens) bool {
	return lens.Rule == RuleWinINET && strings.Contains(lens.Bypass, "/")
}

// summaryOf is the one line a surface prints when it knows nothing about this
// kind. It says what the place holds, never what a program will therefore do.
//
// NO SENTENCE HERE NAMES THE PROXY, AND THAT IS A MASKING RULE RATHER THAN
// BREVITY. A summary crosses the assembly path through Redaction.Text, which
// pseudonymises the names it was told about and any host it finds INSIDE A URL -
// and a proxy entry is a bare "host:port" that arrives during the walk, so it is
// neither. Measured on the binary while writing this: a summary carrying the
// address printed proxy.corp.internal:8080 in a document stamped redacted, next
// to a body where the same value had become [host-2]. The address belongs in the
// body, which has a masking rule that can see it, and the surfaces read it from
// there.
//
// EVERY SENTENCE IS BUILT WITH A COLON RATHER THAN A VERB, and that is grammar
// rather than style. A stack's meaning is a noun phrase whose head word is
// sometimes singular and sometimes plural - "the proxy environment VARIABLES",
// "the current user's Internet SETTINGS, which Edge, Chrome and .NET follow" -
// so any verb glued to it agrees with one of them and not the other. The first
// run of this layer printed "Internet Settings ... follow names no proxy at
// all", and a report that reads as broken English is one a reader trusts less
// than they should.
func summaryOf(lens Lens, body report.ProxyStack, target Target) string {
	switch {
	case body.Selected != nil:
		return fmt.Sprintf("%s: a proxy applies to %s", lens.Stack.Meaning(), describe(target))
	case len(body.Servers) > 0:
		return fmt.Sprintf("%s: %d proxy server(s) named, none applying to %s",
			lens.Stack.Meaning(), len(body.Servers), describe(target))
	case lens.PACURL != "":
		return fmt.Sprintf("%s: no proxy named directly, and an automatic configuration script to ask",
			lens.Stack.Meaning())
	default:
		return fmt.Sprintf("%s: no proxy named at all", lens.Stack.Meaning())
	}
}

// describe names the target the way the rules were asked about it.
func describe(target Target) string {
	if target.Scheme == "" {
		return target.Host
	}
	return target.Scheme + "://" + target.Host
}

// divergenceFinding is the one row that compares places rather than describing
// one.
//
// ITS SOURCE IS "derived" AND EVERY OTHER ROW OF THIS LAYER IS "detected",
// which is the distinction those two words exist for: nobody observed a
// divergence on this machine, it was worked out from two things that were.
func divergenceFinding(class Divergence, lenses []Lens) report.Finding {
	var compared []string
	for _, lens := range lenses {
		if lens.Read {
			compared = append(compared, lens.Stack.String())
		}
	}
	return report.Finding{
		Kind:    report.FindingStackDivergence,
		Summary: fmt.Sprintf("comparing %d place(s) this machine keeps proxy settings in: %s", len(compared), class.Meaning()),
		Source:  report.SourceDerived,
		StackDivergence: &report.StackDivergence{
			Class:  class.String(),
			Stacks: compared,
		},
	}
}

// gradeOf works out what the rows add up to.
//
// THE TWO QUESTIONS ARE KEPT APART ON PURPOSE, and mixing them is how a layer
// like this starts overstating itself. The first is what the configuration SAYS,
// which is a fact and can be graded. The second is whether this run resolved
// everything that could still name a proxy - a script it did not fetch, a
// discovery it did not run - and where the answer is no, no arrangement of the
// first question makes the layer's own question answered.
func gradeOf(lenses []Lens, scripts []script, findings []report.Finding, target Target) Result {
	var named, discovery bool
	var readable int
	for _, lens := range lenses {
		if !lens.Read {
			continue
		}
		readable++
		named = named || lens.NamesAProxy()
		discovery = discovery || lens.AutoDetect == On
	}

	// A SCRIPT THIS RUN READ NO LONGER COUNTS AGAINST THE ANSWER, AND THAT IS
	// THE BEHAVIOUR THIS SLICE CHANGES. Until it existed, an address pointing
	// at a script was permanently unresolved, because nothing could fetch one -
	// so a machine naming a script could never be told anything better than
	// "and this run did not look". Discovery is still counted, because nothing
	// here performs it yet.
	var answered, open int
	for _, one := range scripts {
		if one.settled() {
			answered++
			continue
		}
		open++
	}
	incomplete := open > 0 || discovery

	switch {
	case readable == 0:
		return Result{
			Status: status.Unknown, Reason: status.ReasonUndetermined, Findings: findings,
			Detail: fmt.Sprintf("all %d of this machine's proxy configuration places refused to be read, "+
				"so which proxy applies here was not established", len(lenses)),
		}
	case !named && answered == 0 && !incomplete:
		return nothingNamed(readable, len(lenses), findings)
	case !named && answered == 0:
		// THE REASON COMES OFF THE SCRIPT WHEN A SCRIPT IS WHAT BLOCKED THE
		// ANSWER, and that is what the ninth and the first reasons are for. A
		// file that will not parse is unrecognized_output - the word
		// testbed/expected/pac-broken.txt fixed before this code existed - and
		// one stopped by a ceiling of ours is limit_exceeded, never a timeout
		// unless a clock is what ran out.
		return Result{
			Status: status.Unknown, Reason: openReason(scripts), Findings: findings,
			Detail: "no place names a proxy directly, and " + unresolved(scripts, discovery) +
				" - so a proxy may still apply to this URL and this run did not establish which",
		}
	case incomplete:
		return Result{
			Status: status.Warn, Findings: findings,
			Detail: whatIsKnown(answered, scripts, target) + ", and " + unresolved(scripts, discovery) +
				" - so what is listed below may not be the whole answer",
		}
	}

	class, compared := Compare(lenses)
	if compared && (class == DivergeOneSided || class == DivergeConflicting) {
		return Result{
			Status: status.Warn, Findings: findings,
			Detail: fmt.Sprintf("this machine's proxy settings do not agree with each other: %s - "+
				"so two programs on it will do different things with the same URL", class.Meaning()),
		}
	}
	return Result{
		Status: status.Pass, Findings: findings,
		Detail: agreementOf(readable, compared, class, scripts, target),
	}
}

// nothingNamed is the answer for a machine whose places name no proxy, no
// automatic configuration script and no automatic discovery - the ordinary
// Linux machine.
//
// IT IS A PASS, AND UNTIL ADR108 IT WAS UNKNOWN nothing_to_check. This layer
// asks which proxy applies to this URL, and "none, it is reached directly" is an
// answer to that question rather than the absence of one - so a healthy target
// on such a machine ended its run with code 5 over a question that was settled.
//
// EVERY PLACE HAS TO HAVE BEEN READ, AND THAT IS WHERE THIS DIFFERS FROM A NAMED
// PROXY. "A proxy applies" needs one place that says so, and the rows name which
// one. "No proxy applies" is a claim about all of them, and a place that refused
// to be read is one this run cannot speak for - inviolable rule 15.
func nothingNamed(readable, total int, findings []report.Finding) Result {
	if readable < total {
		return Result{
			Status: status.Unknown, Reason: status.ReasonUndetermined, Findings: findings,
			Detail: fmt.Sprintf("no place this machine could read names a proxy, an automatic configuration "+
				"script or automatic discovery, but %d of its %d places refused to be read - so a proxy may "+
				"still apply to this URL and this run did not establish which", total-readable, total),
		}
	}
	return Result{
		Status: status.Pass, Findings: findings,
		Detail: "no place this machine keeps proxy settings in names a proxy, an automatic configuration " +
			"script or automatic discovery, so a program that follows these settings reaches this URL directly",
	}
}

// openReason is the word for the first thing this run could not settle.
//
// THE FIRST RATHER THAN A COMBINATION, and a layer carries one reason, so a
// second script failing differently is a row of its own to read. The order is
// report order, and the command line comes first there, so a script the user
// asked about decides the word over one the machine merely mentions.
func openReason(scripts []script) status.Reason {
	for _, one := range scripts {
		if !one.settled() {
			return one.reason()
		}
	}
	// Nothing open among the scripts means discovery is what is missing, and
	// nothing has performed it - the question was never put rather than
	// answered badly.
	return status.ReasonUndetermined
}

// whatIsKnown is the first half of a WARN sentence: what this run DID settle.
//
// A SCRIPT'S ANSWER OUTRANKS A STACK'S LIST HERE, because it outranks it on the
// machine. A report that led with "this machine names a proxy" while a script
// sent this URL past it would be telling somebody the opposite of what happens
// on their computer - the fault testbed/expected/proxy-pac-direct.txt calls the
// reason this product exists.
// IT TAKES NO "named" FLAG, AND THE FIRST DRAFT DID. The branch below is only
// reached when a proxy was named OR a script answered, so the second arm implies
// the first and the argument could not change an answer - an argument that
// decides nothing, which is the shape OBS112 names, met in this slice's own new
// code rather than in something old.
func whatIsKnown(answered int, scripts []script, target Target) string {
	if answered > 0 {
		return "an automatic configuration script decides this URL: " + scriptOutcome(scripts, target)
	}
	return "this machine names a proxy"
}

// unresolved names what this run left open, rather than saying "incomplete".
//
// IT NAMES THE THING AND NOT THE COUNT. "one place is incomplete" sends a reader
// nowhere; "points at a script this run did not fetch" tells them what to look
// at next and what a later version of this tool will do for them.
func unresolved(scripts []script, discovery bool) string {
	var open bool
	for _, one := range scripts {
		open = open || !one.settled()
	}
	switch {
	case open && discovery:
		return "this machine both points at an automatic configuration script this run did not settle and has " +
			"automatic proxy discovery on, which this run did not perform"
	case open:
		return "this machine points at an automatic configuration script this run did not settle, " +
			"and the row below says why"
	default:
		return "this machine has automatic proxy discovery on, which this run did not perform"
	}
}

// scriptOutcome is what the first settled script said, in one clause.
//
// IT NAMES NO ENDPOINT, the masking rule summaryOfScript states: a verdict
// crosses the assembly path through Redaction.Text, which cannot see a bare
// "host:port". The address is in the row, which has a rule that can.
func scriptOutcome(scripts []script, target Target) string {
	for _, one := range scripts {
		if !one.settled() {
			continue
		}
		// A SETTLED SCRIPT ALWAYS HAS AN ENTRY TO FOLLOW - settled asks for one
		// since ADR114 - so the answer "nothing recognised" left this function
		// with it, and DIRECT is told by its keyword rather than by an empty
		// address.
		chosen, _ := firstUsable(one.answer.Result.Directives)
		if chosen.Kind == "DIRECT" {
			return "it sends " + describe(target) + " past every proxy this machine names"
		}
		return "it sends " + describe(target) + " through a proxy of its own choosing, named in the row below"
	}
	return ""
}

// agreementOf is the sentence for a run that settled the question.
//
// IT SAYS WHETHER ANYTHING WAS COMPARED, and that is ADR65 in the wording rather
// than only in the class. One place naming a proxy is a complete answer about
// that place and no answer at all about whether this machine is consistent, and
// a sentence that did not distinguish the two would let a reader believe a
// comparison happened.
func agreementOf(readable int, compared bool, class Divergence, scripts []script, target Target) string {
	// A SCRIPT THAT ANSWERED IS THE HEADLINE AND THE STACKS ARE THE BACKGROUND,
	// because that is the order they decide in. Leading with "all places agree"
	// on a machine whose script overrides them would be an accurate sentence
	// about the wrong question.
	if said := scriptOutcome(scripts, target); said != "" {
		return "an automatic configuration script decides this URL: " + said
	}
	if !compared {
		return fmt.Sprintf("this machine keeps proxy settings in %d readable place, so there was nothing to "+
			"compare it against and it is the whole of what this machine says", readable)
	}
	return fmt.Sprintf("all %d readable places this machine keeps proxy settings in say the same thing: %s",
		readable, class.Meaning())
}
