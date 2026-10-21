// Package run walks the diagnostic layers once and assembles the report.
//
// It takes its ports as parameters - the clock, the layer functions, the
// metadata - and writes to no channel of its own. Nothing here prints, and
// nothing here reads an environment variable or a file. That is what makes a
// run reproducible from what the caller passed in.
//
// WHY THIS IS SEQUENTIAL, AND WHY THE CONCURRENCY GUARD'S ALLOWLIST IS STILL
// EMPTY. certdoctor is concurrent by nature and this walk will not stay
// single-threaded: thirteen probes, each starting a subprocess, will not fit in
// a sixty second budget one after another. But the parallelism does not belong
// at this level. L1 hands addresses to L3 and L3 hands a connection to L4, so
// the layers are a pipeline, and the fan-out lives inside a layer - one branch
// per address, one per probe. Putting this file on the allowlist today would
// take the guard off it permanently and buy a wait group around work that
// finishes in microseconds.
//
// What makes the later change an addition rather than a rewrite is one rule
// followed from the first line: results are assembled BY IDENTIFIER, in the
// order the registry declares, never in the order the work finished.
package run

import (
	"context"
	"fmt"
	"time"

	"github.com/donislawdev/certdoctor/internal/core/layer"
	"github.com/donislawdev/certdoctor/internal/core/redact"
	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// Answer is what one layer hands back.
//
// It deliberately carries no identifier. The orchestrator attaches that from
// the registry, so a layer cannot report itself as a different layer and no
// check is needed to catch it doing so.
type Answer struct {
	Status status.Status
	Reason status.Reason
	Detail string
	// Findings is what the layer established about this machine, RAW.
	//
	// A layer never masks its own output - ADR18. It hands back what it found
	// and this package takes the credentials out afterwards, once, in order.
	// A layer that reached for the masking package would be two goroutines away
	// from writing to the same unsynchronised map, and a racing map in Go kills
	// the process with no report at all.
	//
	// Nil and empty say different things and the layer chooses which. Nil means
	// this layer did not look. A slice of length zero means it looked and there
	// was nothing.
	Findings []report.Finding
}

// Layer walks one diagnostic layer.
//
// It is synchronous by contract. It receives a context carrying a deadline, it
// does its work, and it returns. It must not start a goroutine and it must not
// outlive the call - a subprocess surviving the run is a leak the user finds in
// their task manager.
type Layer func(ctx context.Context) Answer

// Layers is the behaviour of every declared layer, keyed by identifier.
//
// A map rather than a slice on purpose: the order of the report comes from the
// registry and from nowhere else, so this collection cannot decide it. A layer
// missing from the map is a loud failure rather than a row that quietly does
// not appear.
type Layers map[layer.ID]Layer

// Options is everything one walk needs.
type Options struct {
	Tool      report.Tool
	Target    string
	Platform  report.Platform
	Privilege report.PrivilegeLevel

	// Redaction takes the credentials out of everything the layers produced.
	//
	// IT LIVES HERE AND NOT IN A LAYER - ADR18. One instance per report, because
	// a pseudonym has to mean the same machine everywhere in it, and it is used
	// on the assembly path only: a Redaction holds unsynchronised maps, and the
	// fan-out this program is heading for lives INSIDE a layer, so two branches
	// calling it would race on a map. That is a fatal error in Go, not a wrong
	// value, and recover cannot catch it.
	//
	// Nil is allowed and means the floor: credentials are removed, names are
	// not. A forgotten assignment therefore masks less, never nothing.
	Redaction *redact.Redaction

	// Budget limits the whole walk. Zero or less means no limit, which is what
	// the flag documents.
	Budget time.Duration
	// LayerBudget limits one layer. It is capped by whatever is left of Budget,
	// because a layer allowed ten seconds inside a run with two seconds left
	// would spend the run's time and report a timeout of its own.
	LayerBudget time.Duration

	// Now is the clock, taken as a port so the budget is testable without
	// waiting for real time to pass.
	Now func() time.Time

	// Layers holds one function per declared layer.
	Layers Layers

	// Notes are the shortfalls the caller already knows about, before the walk
	// starts - an option accepted that does nothing, a field it could not
	// determine. The walk appends its own.
	Notes []report.Note
}

// Execute walks every declared layer in report order and returns the assembled
// report.
//
// It returns an error only for a defect on our side or for a cancelled run.
// Neither produces a report, because a partial report is indistinguishable from
// a complete one once it is in a file.
func Execute(ctx context.Context, o Options) (report.Report, error) {
	if o.Now == nil {
		return report.Report{}, fmt.Errorf("no clock was supplied to the run")
	}
	if o.Redaction == nil {
		o.Redaction = redact.New(redact.Credentials)
	}

	started := o.Now()
	results := make([]report.LayerResult, 0, len(layer.All))
	notes := append([]report.Note{}, o.Notes...)
	exceeded := false

	for _, id := range layer.All {
		walk, declared := o.Layers[id]
		if !declared {
			return report.Report{}, fmt.Errorf("layer %s has no function - every declared layer needs a row", id)
		}
		if err := ctx.Err(); err != nil {
			return report.Report{}, err
		}

		remaining := o.remaining(started)
		if o.Budget > 0 && remaining <= 0 {
			exceeded = true
			results = append(results, budgetSkipResult(id))
			notes = append(notes, budgetSkipNote(id))
			continue
		}
		result, broken := o.walkOne(ctx, id, walk, remaining)
		results = append(results, result)
		if broken != nil {
			notes = append(notes, *broken)
		}
		// A LAYER THAT RAN AND GAVE UP HALFWAY SAYS SO IN THE NOTES, not only in
		// its own row - ADR58, inviolable rule 1.
		//
		// THE FLAG ABOVE IS NOT THE PLACE FOR THIS, AND THAT IS THE WHOLE REASON
		// THIS NOTE EXISTS. run.BudgetExceeded says the RUN ran out of its overall
		// time, which is a different fact with a different consequence, and
		// widening it to cover a layer spending its own budget would make a
		// documented field mean two things. So the flag keeps its meaning and the
		// silence is broken here instead.
		//
		// The wholly skipped layer above has its own note already, and this branch
		// cannot double it: that path never reaches walkOne.
		if result.Reason == status.ReasonSkippedBudget {
			notes = append(notes, report.Note{
				Kind:   report.NoteSkipped,
				Layer:  id,
				Reason: status.ReasonSkippedBudget,
				Detail: "this layer ran out of its own time budget partway through and did not finish asking, " +
					"so what it reports is what it managed rather than what there is",
			})
		}
	}

	// MASKED HERE, ONCE, AFTER EVERY LAYER HAS ANSWERED. This is the whole of
	// ADR18 in one line: probes hand back raw evidence and this is the only
	// place that takes credentials out of it. Doing it per layer would put the
	// masking package inside the code that is going to become concurrent.
	//
	// AND EVERYTHING FROM HERE ON IS OUTSIDE --timeout, WHICH IS WORTH SAYING
	// WHERE THE FIRST STEP OF IT IS. The context above bounds the LAYER WALK.
	// Masking, assembly, the report's own validation, encoding, the schema check
	// and writing the bytes all happen afterwards, with no deadline and nothing
	// able to interrupt them - a reader of "--timeout 60" has every right to
	// assume otherwise.
	//
	// IT IS NAMED RATHER THAN FIXED, AND THE REASON IS MEASURED. The external
	// review of 2026-09-02 called this dangerous because masking cost grows with
	// the number of sensitive names and the list was unbounded. The list is
	// bounded since 2026-09-04 - see resolve.MaxNameservers - and the cost is
	// linear rather than quadratic in it: 14.4 microseconds per masked string at
	// two names, 1.25 milliseconds at 1025, recorded in the redact package's own
	// benchmark. At the handful of names this program can now hold, the whole of
	// this phase is well under a millisecond, so a deadline here would guard
	// nothing and would add a way for a finished run to produce no report.
	o.mask(results, notes)

	return o.assemble(started, results, notes, exceeded), nil
}

// mask rewrites in place everything the layers produced, and nothing else.
//
// The verdict is not masked here and MUST NOT BE, for a reason that changed
// shape on 2026-09-21 and kept its conclusion. Until then the verdict was built
// from counts of statuses and carried no text from anybody's machine. Since
// ADR99 it quotes the decisive layer - an issuer, a runtime, a proxy - and the
// order of the two phases is what keeps a redacted report redacted: masking
// runs first, assembly second, so Assess reads the rows the report is allowed
// to show and nothing else. The validator recomputes the sentence from those
// same rows and compares, so masking the sentence afterwards would be a
// difference with no cause, and building it before masking would put the raw
// name on the one line everybody reads. Both orders are pinned by a test that
// goes through Execute.
func (o Options) mask(results []report.LayerResult, notes []report.Note) {
	for i := range results {
		results[i].Detail = o.Redaction.Text(results[i].Detail)
		for j := range results[i].Findings {
			o.maskFinding(&results[i].Findings[j])
		}
	}
	// Notes carry no evidence today - they are written here and by the entry
	// point. They go through anyway, because the first note that quotes a path
	// or a host will be written by somebody who is not thinking about masking.
	for i := range notes {
		notes[i].Detail = o.Redaction.Text(notes[i].Detail)
	}
}

// maskFinding takes the credentials out of one finding.
//
// THE BODY IS REPLACED RATHER THAN WRITTEN THROUGH, and that is not tidiness.
// Copying the findings slice copies the POINTERS in it, so the body a layer
// handed over is the same object the report holds. Masking through that pointer
// would rewrite the layer's own evidence underneath it - harmless while layers
// are stateless, and a defect that appears the day one is not.
func (o Options) maskFinding(finding *report.Finding) {
	finding.Summary = o.Redaction.Text(finding.Summary)
	if mask, declared := maskedBodies[finding.Kind]; declared {
		mask(o.Redaction, finding)
	}
}

// maskedBodies says how each declared kind of finding gets masked.
//
// WHY A TABLE RATHER THAN A CHAIN OF nil CHECKS, and this one is paid for in
// advance rather than after the fact. The previous shape returned early when the
// body it knew about was absent, so a second kind of finding would have travelled
// the whole assembly path UNTOUCHED - the summary masked, the body not - and
// nothing anywhere would have said so. That is the exact shape of failure
// inviolable rule 17 exists to prevent, and it would have looked like working
// code.
//
// This map is walked against report.AllFindingKinds by a guard, so a kind
// declared without an entry here is a red test rather than a body nothing masks.
// It is the same construction findingBodies uses in the core, for the same
// reason.
// NEITHER ENTRY CHECKS ITS BODY FOR nil, AND THAT IS DELIBERATE. Every finding
// reaching this point has been through Finding.Breach, which refuses a finding
// whose body does not match its kind - and resultOf drops the findings of a
// layer that broke that contract before they get here. A nil check would
// therefore be a branch nothing can execute, which is the shape the mutation
// register caught twice in P3a: code that reads as caution and decides nothing.
//
// It also fails in the wrong direction. A nil body skipped quietly is evidence
// that crossed the assembly path unmasked - inviolable rule 17 - while the
// dereference is a panic the entry point already catches and maps to 1 RUNTIME.
// Loud and coded beats quiet and leaking.
var maskedBodies = map[report.FindingKind]func(*redact.Redaction, *report.Finding){
	report.FindingEnvironmentVariable: maskEnvironmentVariable,
	report.FindingNameResolution:      maskNameResolution,
	report.FindingTCPConnect:          maskTCPConnect,
	report.FindingTLSHandshake:        maskTLSHandshake,
	report.FindingTrustStore:          maskTrustStore,
	report.FindingSigningAuthority:    maskSigningAuthority,
	report.FindingProxyStack:          maskProxyStack,
	report.FindingStackDivergence:     maskStackDivergence,
	report.FindingPACScript:           maskPACScript,
	report.FindingProxyChallenge:      maskProxyChallenge,
}

// maskProxyChallenge is the THIRD entry that withholds a field outright, and the
// field it withholds is the same kind of thing as the other two: somebody else's
// free prose.
//
// THE ENDPOINT GOES THROUGH Authority BECAUSE IT IS A BARE "host:port", the same
// split maskProxyStack and maskPACScript make - and through the same pseudonym
// map, so a proxy this row asked, a proxy a stack named and a name from L1 all
// read as one machine rather than three.
//
// THE REALM IS WITHHELD AND THE SCHEME IS NOT, and that is the whole of this
// function's judgement. A scheme name is a token from the IANA registry -
// Basic, Digest, Negotiate, NTLM - so it is an identifier, and inviolable rule
// 19 is satisfied by printing it. A realm is free text an administrator typed
// into somebody else's proxy: routinely a company name, a site or a department,
// and no masking rule recognises prose as a machine, so Text would leave most of
// it standing in a document stamped redacted - a leak wearing a stamp.
//
// NOTHING HERE HAS TO MASK A CREDENTIAL, and that is not luck. CarriedCredentials
// is a boolean, and the value it is about was cut off where the address was read
// - ADR89 - so it never entered the structure this function is handed.
//
// THE CAVEATS ARE OUR OWN PROSE about somebody else's proxy and name nothing off
// the machine, so they are left alone.
func maskProxyChallenge(r *redact.Redaction, finding *report.Finding) {
	challenge := *finding.ProxyChallenge
	challenge.Endpoint = r.Authority(challenge.Endpoint)
	challenge.Detail = r.Text(challenge.Detail)
	challenge.Schemes = maskAuthSchemes(r, challenge.Schemes)
	finding.ProxyChallenge = &challenge
}

// maskAuthSchemes copies before touching, for the reason maskServers gives.
func maskAuthSchemes(r *redact.Redaction, schemes []report.ProxyAuthScheme) []report.ProxyAuthScheme {
	if schemes == nil {
		return nil
	}
	masked := make([]report.ProxyAuthScheme, 0, len(schemes))
	for _, scheme := range schemes {
		if scheme.Realm != "" && r.Mode() == redact.Everything {
			scheme.Realm = redact.Placeholder
		}
		masked = append(masked, scheme)
	}
	return masked
}

// maskPACScript is the second entry that withholds a field outright rather than
// masking it, and it withholds the same KIND of thing the first one does.
//
// THE SCRIPT'S ADDRESS GOES THROUGH Text BECAUSE IT IS A URL, which is the one
// shape that rule can find a host inside. The endpoints a script names go
// through Authority instead, because a PAC directive's "host:port" arrives bare
// - the same split maskProxyStack makes between PACURL and a proxy entry, and
// the same pseudonym map for both, so a proxy named by a script and a name from
// L1 still read as one machine.
//
// THE VERBATIM ANSWER IS WITHHELD. Answer exists so a report can quote the file
// rather than our reading of it, and that is exactly what makes it unmaskable:
// it is somebody else's sentence with a bare authority inside it, so Text would
// leave the address standing in a document stamped redacted - a leak wearing a
// stamp, which is the phrase maskProxyStack uses about the exception list for
// the same reason. Nothing diagnostic is lost, because Directives carries every
// entry of that answer with its endpoint pseudonymised.
//
// THE CAVEATS ARE OUR OWN PROSE about somebody else's file and name nothing off
// the machine, so they are left alone.
func maskPACScript(r *redact.Redaction, finding *report.Finding) {
	script := *finding.PACScript
	script.URL = r.Text(script.URL)
	script.Detail = r.Text(script.Detail)
	script.Directives = maskDirectives(r, script.Directives)
	if script.Selected != nil {
		selected := maskDirective(r, *script.Selected)
		script.Selected = &selected
	}
	if script.Answer != "" && r.Mode() == redact.Everything {
		script.Answer = redact.Placeholder
	}
	script.Asked = maskAskedNames(r, script.Asked)
	finding.PACScript = &script
}

// maskAskedNames pseudonymises the hosts a PAC file sent to a resolver.
//
// THESE ARE MASKED AND NOT WITHHELD, WHICH IS THE OPPOSITE OF WHAT HAPPENS TO
// Answer THREE LINES UP, and the difference is what the field holds. An answer
// is somebody else's sentence with a bare host:port buried in its grammar, which
// no rule here recognises as a machine. These are bare host names one per entry,
// which is precisely the shape Authority handles - so the pseudonym map can do
// its job, and a reader keeps what the field is FOR: how many names left this
// machine, and whether one of them repeats.
//
// NIL STAYS NIL, empty stays empty. ADR20 governs this field the same way it
// governs the directives beside it: a script that never ran asked nothing
// because nobody looked, and that is not the same document as a script that ran
// and asked about nothing.
func maskAskedNames(r *redact.Redaction, names []string) []string {
	if names == nil {
		return nil
	}
	masked := make([]string, 0, len(names))
	for _, name := range names {
		masked = append(masked, r.Authority(name))
	}
	return masked
}

// maskDirectives copies before touching, for the reason maskServers gives. NIL
// STAYS NIL: a script that was not fetched names no entries, and a script that
// answered DIRECT names one - ADR20 again, one row further along.
func maskDirectives(r *redact.Redaction, directives []report.PACDirective) []report.PACDirective {
	if directives == nil {
		return nil
	}
	masked := make([]report.PACDirective, 0, len(directives))
	for _, directive := range directives {
		masked = append(masked, maskDirective(r, directive))
	}
	return masked
}

// maskDirective pseudonymises the endpoint and leaves the rest. The keyword is
// a word out of the PAC grammar - "PROXY", "DIRECT" - and Recognised is a
// boolean this program set, so neither names anybody's machine.
func maskDirective(r *redact.Redaction, directive report.PACDirective) report.PACDirective {
	directive.Endpoint = r.Authority(directive.Endpoint)
	return directive
}

// maskProxyStack is the entry with the widest split so far between what goes
// through masking and what is withheld outright.
//
// THE PROXY IS INFRASTRUCTURE AND IS PSEUDONYMISED. ADR32 masks a RESOLVER's
// address for exactly this reason - it is a machine somebody's network owns
// rather than the answer the reader came for - and a proxy is the same kind of
// thing. It goes through Authority rather than Text because it arrives with no
// scheme in front of it, and through the same pseudonym map as everything else,
// so a reader of a masked report can still see that the proxy here and a name in
// L1 are one machine.
//
// THE EXCEPTION LIST IS WITHHELD RATHER THAN MASKED, AND THAT IS THE DECISION IN
// THIS FUNCTION. Its entries are wildcards, suffixes and abbreviated networks -
// "*.corp.internal", ".example.com", "169.254/16" - so there is no rule that
// recognises them as machines the way a URL's host is recognised. Masking them
// through Text would leave most of them untouched while the report says it is
// redacted, which is worse than saying nothing: it is a leak wearing a stamp.
// The diagnostic content survives, because BypassRules already carries the only
// thing a reader acts on - whether THIS target skips the proxy, under each
// runtime's reading of the list.
//
// THE CAVEATS ARE OUR OWN PROSE about somebody else's configuration and name
// nothing off the machine, so they are left alone for the reason
// maskSigningAuthority leaves the inspection body alone.
func maskProxyStack(r *redact.Redaction, finding *report.Finding) {
	stack := *finding.ProxyStack
	stack.Detail = r.Text(stack.Detail)
	stack.PACURL = r.Text(stack.PACURL)
	stack.Servers = maskServers(r, stack.Servers)
	if stack.Selected != nil {
		selected := maskServer(r, *stack.Selected)
		stack.Selected = &selected
	}
	if stack.Bypass != "" && r.Mode() == redact.Everything {
		stack.Bypass = redact.Placeholder
	}
	finding.ProxyStack = &stack
}

// maskServers copies the list before touching it, for the reason maskEach gives:
// masking in place would rewrite the layer's own evidence underneath it. NIL
// STAYS NIL, because nil and empty are two different facts here - ADR20.
func maskServers(r *redact.Redaction, servers []report.ProxyServer) []report.ProxyServer {
	if servers == nil {
		return nil
	}
	masked := make([]report.ProxyServer, 0, len(servers))
	for _, server := range servers {
		masked = append(masked, maskServer(r, server))
	}
	return masked
}

// maskServer pseudonymises the address and leaves the rest.
//
// Protocol and Scheme are words out of a URL grammar - "http", "https", "socks"
// - and CarriedCredentials is a boolean this program set. None of the three
// names anything on anybody's network.
func maskServer(r *redact.Redaction, server report.ProxyServer) report.ProxyServer {
	server.Address = r.Authority(server.Address)
	return server
}

// maskStackDivergence is the second entry written in order to say that a body
// needs nothing masked, and the reason maskTCPConnect gives applies unchanged: a
// missing entry and a deliberate no-op look identical from outside.
//
// EVERY FIELD IN IT IS A WORD THIS PROGRAM CHOSE. The class comes from a closed
// list declared in internal/core/proxy and the stack names come from another
// one. Neither arrived from the machine being diagnosed, so there is nothing
// here that masking could protect - and replacing our own vocabulary with a
// pseudonym would take the sentence a reader pastes into a ticket.
func maskStackDivergence(*redact.Redaction, *report.Finding) {}

// maskSigningAuthority masks the borrowed names and leaves the evidence alone.
//
// WHAT GOES THROUGH MASKING. The issuer is a distinguished name out of somebody
// else's certificate, which is where a host name lives when it is not in a URL -
// the same reason maskTLSHandshake masks the subject and issuer of every row of
// the chain. The two store lists carry INSTANCE NAMES, and an instance is
// routinely a path: measured on the bench, "/usr/bin/curl", and on Windows a
// Java instance is a directory under an account's own profile.
//
// WHAT NEVER DOES. The fingerprint, for the reason maskTLSHandshake gives: it is
// the evidence inviolable rule 21 requires to travel beside any claim about
// interception, and a masked report that names an authority and withholds the
// one value proving which one is a report that accuses without evidence. The
// holding is a word from a closed list this program declares.
//
// THE SAME Redaction DOES BOTH LISTS AND THE SUMMARY, so a store named in a list
// and the same store named in its own row come out as ONE pseudonym - they are
// keyed by the real name rather than by the field they were found in.
//
// THE INSPECTION BODY IS LEFT ALONE, AND THAT IS THE SECOND DECISION IN THIS
// FUNCTION RATHER THAN AN OVERSIGHT. Neither of its two values came off this
// machine: the product name is written in our own list and the matched attribute
// is one of two literals this program chose. Masking them would replace our own
// prose with a pseudonym for our own prose - and it would take the one sentence
// the reader pastes into a ticket, in the one finding where being unable to say
// what was found makes the rest of the report pointless. What that ticket must
// not carry is the issuer and the store paths, and those are masked above.
func maskSigningAuthority(r *redact.Redaction, finding *report.Finding) {
	authority := *finding.SigningAuthority
	authority.Issuer = r.Text(authority.Issuer)
	authority.TrustingStores = maskEach(r, authority.TrustingStores)
	authority.RefusingStores = maskEach(r, authority.RefusingStores)
	finding.SigningAuthority = &authority
}

// maskEach rebuilds a list of borrowed names rather than editing it in place.
//
// THE REBUILD IS THE POINT, not the loop. The finding is a copy, but the slice
// header inside it still refers to the core's own array, so writing through it
// would rewrite the layer's evidence underneath it - the same trap maskFinding
// records for bodies, one level further in. An empty list stays an empty list
// rather than becoming nil, because the contract refuses nil there.
func maskEach(r *redact.Redaction, names []string) []string {
	masked := make([]string, 0, len(names))
	for _, name := range names {
		masked = append(masked, r.Text(name))
	}
	return masked
}

// maskTLSHandshake is the first entry that has to say YES TO SOME FIELDS AND NO
// TO OTHERS, and the split is the decision rather than the code.
//
// WHAT GOES THROUGH MASKING. A subject and an issuer are text out of somebody
// else's certificate and they routinely carry host names - a distinguished name
// is where a host name lives when it is not in a URL. The server name is the one
// WE sent in SNI, which is the host the user typed. All three are the shape
// --redact exists for.
//
// WHAT NEVER DOES, AND THIS HALF IS THE ONE WORTH DEFENDING. A fingerprint is
// the evidence inviolable rule 21 requires to travel beside any claim about
// interception - it is the answer somebody came here for, and it names no
// person, no host and no network. Masking it would leave a report that accuses a
// middlebox and withholds the one value proving it. The addresses are left alone
// for the reason maskTCPConnect gives one layer down: an address a name resolved
// to is the diagnosis, not infrastructure.
//
// The chain is rebuilt rather than written through, for the reason maskFinding
// gives: copying a findings slice copies the pointers in it, so writing through
// one would rewrite the layer's own evidence underneath it. A nil chain stays
// nil - the row that carries no chain must not grow an empty one, because those
// two are different statements (ADR45, ADR20).
func maskTLSHandshake(r *redact.Redaction, finding *report.Finding) {
	shake := *finding.TLSHandshake
	shake.ServerName = r.Text(shake.ServerName)
	if shake.Chain != nil {
		chain := make([]report.Certificate, 0, len(shake.Chain))
		for _, certificate := range shake.Chain {
			certificate.Subject = r.Text(certificate.Subject)
			certificate.Issuer = r.Text(certificate.Issuer)
			// THE NAMES ARE HOST NAMES BY DEFINITION, so they go the same way as
			// the two above - ADR47. They are also the field most likely to carry
			// an internal name that appears nowhere else in the report, because a
			// certificate for one host routinely lists several.
			certificate.DNSNames = maskedNames(r, certificate.DNSNames)
			chain = append(chain, certificate)
		}
		shake.Chain = chain
	}
	finding.TLSHandshake = &shake
}

// maskedNames puts every name through masking and keeps nil as nil.
//
// The nil is not tidiness: an empty list says the certificate presents no DNS
// name, and rebuilding one for a certificate that had none would be masking
// inventing a fact - the same distinction the chain itself carries.
func maskedNames(r *redact.Redaction, names []string) []string {
	if names == nil {
		return nil
	}
	masked := make([]string, 0, len(names))
	for _, name := range names {
		masked = append(masked, r.Text(name))
	}
	return masked
}

// maskTrustStore is the entry where the masked half is a PATH rather than a
// name, which is a first for this table.
//
// WHAT GOES THROUGH MASKING. StorePath is read off this machine and routinely
// contains the account name - a per-user keystore, a venv, a .gitconfig under
// C:\Users\<somebody>. Instance is masked for the same reason and it is easy to
// miss: for java it is a version like "jdk-25" and harmless, but for curl the
// thing that tells two instances apart IS THE PATH TO THE BINARY, so the field
// carries whatever the path carried. NotAssessed is an English sentence written
// about a store that could not be read, and the most useful such sentence names
// the file it failed on.
//
// WHAT NEVER DOES, AND THIS HALF IS THE DECISION. TrustAnchorCount is a number
// about somebody's configuration and names no person, host or network - it is
// the same call the fingerprint got one entry up, and masking it would remove
// evidence while protecting nobody. Runtime, Variant, Architecture, StoreForm
// and Backend come from closed lists this program declares, so they cannot carry
// an identity that was not already ours. SelectedBy holds the NAMES of
// environment variables - "JAVA_HOME", "PATH" - never their values, which is the
// distinction ADR19 draws: the name is the thing that decides, the value is the
// thing that leaks.
func maskTrustStore(r *redact.Redaction, finding *report.Finding) {
	store := *finding.TrustStore
	store.StorePath = r.Text(store.StorePath)
	store.Instance = r.Text(store.Instance)
	store.NotAssessed = r.Text(store.NotAssessed)
	// THE DETAIL OF A REFUSAL NAMES A CERTIFICATE out of somebody else's chain,
	// and a subject is where a host name lives when it is not in a URL - the
	// reason maskTLSHandshake masks the subjects of the chain.
	store.RefusalDetail = r.Text(store.RefusalDetail)
	// THE COMMAND CARRIES THE PATH, so masking the path and not the command would
	// leave the same directory in the document twice, once masked and once not -
	// and the unmasked copy would be in the line most likely to be pasted into a
	// ticket. It goes through the SAME Redaction, so the store path and the path
	// inside the command come out as one pseudonym rather than two: they are
	// keyed by the real name, not by the field they were found in.
	//
	// A COPY RATHER THAN AN EDIT IN PLACE. The finding is a copy already, but the
	// pointer inside it is not, and masking through it would rewrite the row the
	// core still holds - which would make the masked and unmasked reports the
	// same object.
	if store.Fix != nil {
		fix := *store.Fix
		fix.Command = r.Text(fix.Command)
		store.Fix = &fix
	}
	// TrustFailure is not masked and neither is anything else in a Fix. The
	// failure is a word from a closed list this program declares; the elevation
	// sentence and the caveat name no path, no host and no account - they are
	// about what a store IS, not about where it lives.
	finding.TrustStore = &store
}

// maskTCPConnect is the entry that had to be WRITTEN in order to say that this
// body needs nothing masked.
//
// EVERY FIELD IN IT IS EITHER AN ADDRESS OR A NUMBER. Addresses a name resolved
// to are never masked - they are the answer somebody came for, decided at ADR26
// and narrowed at ADR32, which masks a RESOLVER's address because that one is
// infrastructure rather than an answer. There is no resolver here: this layer
// connects to the target's own addresses.
//
// SO WHY EXIST AT ALL, RATHER THAN LEAVING THE KIND OUT OF THE TABLE. Because a
// missing entry and a deliberate no-op look identical from outside, and only one
// of them is a decision. The guard walking this map against the registry turned
// red the moment the third kind was declared, which is the whole point of it -
// and answering that with silence would waste the guard.
func maskTCPConnect(*redact.Redaction, *report.Finding) {}

func maskEnvironmentVariable(r *redact.Redaction, finding *report.Finding) {
	variable := *finding.EnvironmentVariable
	// A variable that is not set has no value and cannot have carried anything,
	// which is a rule the report validator enforces from the other side.
	if variable.Set {
		// The NAME goes in beside the value and is never glued to it - ADR19
		// and D8. Masking the value alone would leave a secret whose name is the
		// only thing saying it is one, and gluing them back together is what
		// deleted the finding in NODE_TLS_REJECT_UNAUTHORIZED=0.
		variable.Value, variable.CarriedCredentials = r.SettingValue(variable.Name, variable.Value)
	}
	finding.EnvironmentVariable = &variable
}

// maskNameResolution puts the resolution body through the same masking as
// everything else on this path.
//
// WHAT IT DOES NOT DO TODAY, WRITTEN HERE RATHER THAN DISCOVERED LATER. Under
// --redact a host name is supposed to become a pseudonym, and Text does that for
// a host sitting INSIDE A URL - which is where every host in this report has
// lived until now. A bare name in a field of its own goes through unchanged
// unless it was handed to redact.New as sensitive, and that list is empty
// (OBS37). So this call is correct and currently has nothing to do to a name
// like example.com. A test pins that, so the day the reach is widened it is a
// decision and not a side effect.
//
// Addresses are deliberately left alone. An address is the diagnosis - the same
// argument that kept trust store paths readable - and a report that masked them
// would answer "what does this resolve to" with "[address-1]".
func maskNameResolution(r *redact.Redaction, finding *report.Finding) {
	answer := *finding.NameResolution
	answer.Name = r.Text(answer.Name)
	answer.Resolver = r.Text(answer.Resolver)
	finding.NameResolution = &answer
}

// remaining is how much of the overall budget is left, or a negative duration
// meaning "unlimited" when no budget was set.
func (o Options) remaining(started time.Time) time.Duration {
	if o.Budget <= 0 {
		return -1
	}
	return o.Budget - o.Now().Sub(started)
}

// walkOne runs one layer under the tighter of the two deadlines.
//
// The tighter one matters: a layer allowed ten seconds inside a run with two
// seconds left would spend the run's remaining time and then report a timeout
// of its own, which reads as a slow machine rather than as a budget we set.
func (o Options) walkOne(ctx context.Context, id layer.ID, walk Layer, remaining time.Duration) (report.LayerResult, *report.Note) {
	limit := effectiveLimit(o.LayerBudget, remaining)
	if limit <= 0 {
		return resultOf(id, walk(ctx))
	}

	layerCtx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	return resultOf(id, walk(layerCtx))
}

// effectiveLimit picks the deadline one layer actually gets.
//
// A negative remaining means the run has no overall budget. A limit of zero or
// less means no deadline at all, which is what both budgets being switched off
// produces. Everything else takes the smaller of the two.
//
// It is a separate function because it is the whole of the budget arithmetic,
// and arithmetic tested through a real clock is arithmetic tested loosely.
func effectiveLimit(layerBudget, remaining time.Duration) time.Duration {
	if remaining < 0 {
		return layerBudget
	}
	if layerBudget <= 0 || remaining < layerBudget {
		return remaining
	}
	return layerBudget
}

// resultOf attaches the identifier the registry declared and keeps one layer's
// mistake from taking the report down with it.
//
// A layer never gets to say which layer it is, and it never gets to end the run.
// An answer that breaks the contract - a status outside the vocabulary, a
// problem reported without a reason from the closed list, a problem with no
// detail line - becomes an unknown with a reason, and a note names the layer and
// what it did.
//
// WHY THIS IS NOT LEFT TO PANIC, WHICH IS WHAT USED TO HAPPEN BY ACCIDENT.
// Assess folds the statuses, folding asks each one for its severity, and
// severity panics on a value outside the four. So a layer returning a zero
// Answer ended the entire run with no report at all: seven working layers, the
// verdict and every note thrown away because the eighth forgot a field. That is
// the reverse of the rule this product is built on - a probe that cannot answer
// degrades, and it degrades ALONE. It also meant the validator's own branch for
// a status outside the vocabulary could never run in production, because the
// panic always arrived first.
func resultOf(id layer.ID, answer Answer) (report.LayerResult, *report.Note) {
	broken := contractBreach(answer)
	if broken == "" {
		return report.LayerResult{
			ID:       id,
			Status:   answer.Status,
			Reason:   answer.Reason,
			Detail:   answer.Detail,
			Findings: copyFindings(answer.Findings),
		}, nil
	}

	return report.LayerResult{
		ID:     id,
		Status: status.Unknown,
		Reason: status.ReasonProbeError,
		Detail: "the layer broke its own contract, so nothing it reported was used",
	}, &report.Note{
		Kind:   report.NoteDegraded,
		Layer:  id,
		Reason: status.ReasonProbeError,
		Detail: fmt.Sprintf("layer %s %s - it was recorded as unknown rather than ending the run", id, broken),
	}
}

// contractBreach names what is wrong with an answer, or returns empty for one
// that is well formed. The wording is the note's, so it says what the layer did
// rather than what this function checked.
func contractBreach(answer Answer) string {
	switch {
	case !answer.Status.Valid():
		return fmt.Sprintf("answered with the status %q, which is outside the vocabulary", answer.Status)
	case answer.Status.RequiresReason() && !answer.Reason.Valid():
		return fmt.Sprintf("reported %s with the reason %q, which is outside the closed list", answer.Status, answer.Reason)
	case !answer.Status.RequiresReason() && answer.Reason != "":
		return fmt.Sprintf("reported %s and still carried the reason %q", answer.Status, answer.Reason)
	case answer.Status.RequiresDetail() && answer.Detail == "":
		// THE SENTENCE IS REQUIRED OF EVERY STATUS BUT PASS, and it is asked here
		// rather than through RequiresReason because those two stopped being the
		// same question: a layer that ASSESSED something and found it wrong owes
		// the reader words, and owes the closed reason list nothing.
		return fmt.Sprintf("reported %s without a detail line saying what happened", answer.Status)
	}
	// The findings are checked HERE and not only in the report validator, and the
	// difference decides whether a run survives. A malformed finding reaching the
	// validator fails the whole report, so the process ends with an internal
	// error and prints nothing - seven working layers thrown away because the
	// eighth built one row badly. Caught here it costs that one layer.
	for i, finding := range answer.Findings {
		if breach := finding.Breach(); breach != "" {
			return fmt.Sprintf("returned a finding at position %d that %s", i, breach)
		}
	}
	return ""
}

// copyFindings takes the layer's slice out of the layer's hands, WITHOUT
// turning a nil into an empty one.
//
// Two reasons, and the second is the one that would be found late. The
// assembly path rewrites these values when it masks them, and rewriting a slice
// the layer still holds is a defect that only appears once a layer keeps state.
// And the nil stays nil because nil renders as null and empty renders as an
// empty array: the ordinary one-line copy would turn "nobody looked" into "we
// looked and found nothing" in every layer that never ran.
func copyFindings(findings []report.Finding) []report.Finding {
	if findings == nil {
		return nil
	}
	copied := make([]report.Finding, len(findings))
	copy(copied, findings)
	return copied
}

func (o Options) assemble(started time.Time, results []report.LayerResult, notes []report.Note, exceeded bool) report.Report {
	return report.Report{
		Tool: o.Tool,
		Run: report.Run{
			StartedAt:      started,
			Duration:       o.Now().Sub(started),
			Target:         o.Target,
			PrivilegeLevel: o.Privilege,
			Platform:       o.Platform,
			// Read off the redaction rather than carried as a second field, so
			// that the report cannot claim one thing while the masking did
			// another.
			Redacted:       o.Redaction.Mode() == redact.Everything,
			BudgetExceeded: exceeded,
		},
		Verdict: report.Assess(results),
		Layers:  results,
		Notes:   notes,
	}
}

func budgetSkipResult(id layer.ID) report.LayerResult {
	return report.LayerResult{
		ID:     id,
		Status: status.Unknown,
		Reason: status.ReasonSkippedBudget,
		Detail: "the run was out of time before this layer started",
	}
}

func budgetSkipNote(id layer.ID) report.Note {
	return report.Note{
		Kind:   report.NoteSkipped,
		Layer:  id,
		Reason: status.ReasonSkippedBudget,
		Detail: "the run exceeded its overall time budget and did not walk this layer",
	}
}
