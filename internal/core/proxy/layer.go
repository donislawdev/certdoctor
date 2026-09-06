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
}

// Result is what L2 established.
type Result struct {
	Status   status.Status
	Reason   status.Reason
	Detail   string
	Findings []report.Finding
}

// Sentences for the cases where the layer establishes nothing.
const (
	noLenses = "no way to read this machine's proxy configuration was supplied, so no place was asked"
	noPlaces = "the reading of this machine's proxy configuration came back naming no place at all, " +
		"and this program always asks at least about its own environment"
)

// Ask reads every place this machine keeps proxy configuration and says what
// each of them makes of this target.
//
// IT REPORTS AND IT DOES NOT REROUTE, which is docs/14 section 3 turned into
// behaviour: proxy variables are diagnostic INPUT, so nothing this layer reads
// changes where any other layer connects. A run of the same target with these
// variables set and without them has to come out the same everywhere else, and
// the bench checks exactly that from outside.
//
// IT OPENS NO CONNECTION. Fetching an automatic configuration script, running
// WPAD discovery and asking a proxy whether it wants credentials are all work
// that reaches the network, and each of them widens the set of places this
// program may connect to. They arrive with their own slices; until then this
// layer says what the configuration SAYS and says out loud where that stops
// short of an answer.
func Ask(ctx context.Context, in Input) Result {
	if in.Lenses == nil {
		return Result{Status: status.Unknown, Reason: status.ReasonProbeError, Detail: noLenses}
	}
	lenses := in.Lenses(ctx)
	if len(lenses) == 0 {
		return Result{Status: status.Unknown, Reason: status.ReasonProbeError, Detail: noPlaces}
	}

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
	return gradeOf(lenses, findings)
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
func gradeOf(lenses []Lens, findings []report.Finding) Result {
	var named, incomplete bool
	var readable int
	for _, lens := range lenses {
		if !lens.Read {
			continue
		}
		readable++
		named = named || lens.NamesAProxy()
		incomplete = incomplete || lens.PACURL != "" || lens.AutoDetect == On
	}

	switch {
	case readable == 0:
		return Result{
			Status: status.Unknown, Reason: status.ReasonUndetermined, Findings: findings,
			Detail: fmt.Sprintf("all %d of this machine's proxy configuration places refused to be read, "+
				"so which proxy applies here was not established", len(lenses)),
		}
	case !named && !incomplete:
		return Result{
			Status: status.Unknown, Reason: status.ReasonNothingToCheck, Findings: findings,
			Detail: "no place this machine keeps proxy settings in names a proxy, an automatic " +
				"configuration script or automatic discovery, so there was no proxying to examine",
		}
	case !named:
		return Result{
			Status: status.Unknown, Reason: status.ReasonUndetermined, Findings: findings,
			Detail: "no place names a proxy directly, and " + unresolved(lenses) +
				" - so a proxy may still apply to this URL and this run did not establish which",
		}
	case incomplete:
		return Result{
			Status: status.Warn, Findings: findings,
			Detail: "this machine names a proxy, and " + unresolved(lenses) +
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
		Detail: agreementOf(readable, compared, class),
	}
}

// unresolved names what this run left open, rather than saying "incomplete".
//
// IT NAMES THE THING AND NOT THE COUNT. "one place is incomplete" sends a reader
// nowhere; "points at a script this run did not fetch" tells them what to look
// at next and what a later version of this tool will do for them.
func unresolved(lenses []Lens) string {
	var script, discovery bool
	for _, lens := range lenses {
		if !lens.Read {
			continue
		}
		script = script || lens.PACURL != ""
		discovery = discovery || lens.AutoDetect == On
	}
	switch {
	case script && discovery:
		return "this machine both points at an automatic configuration script and has automatic discovery on, " +
			"neither of which this run followed"
	case script:
		return "this machine points at an automatic configuration script, which this run did not fetch"
	default:
		return "this machine has automatic proxy discovery on, which this run did not perform"
	}
}

// agreementOf is the sentence for a run that settled the question.
//
// IT SAYS WHETHER ANYTHING WAS COMPARED, and that is ADR65 in the wording rather
// than only in the class. One place naming a proxy is a complete answer about
// that place and no answer at all about whether this machine is consistent, and
// a sentence that did not distinguish the two would let a reader believe a
// comparison happened.
func agreementOf(readable int, compared bool, class Divergence) string {
	if !compared {
		return fmt.Sprintf("this machine keeps proxy settings in %d readable place, so there was nothing to "+
			"compare it against and it is the whole of what this machine says", readable)
	}
	return fmt.Sprintf("all %d readable places this machine keeps proxy settings in say the same thing: %s",
		readable, class.Meaning())
}
