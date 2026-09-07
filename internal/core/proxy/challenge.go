package proxy

import (
	"context"
	"fmt"
	"strings"

	"github.com/donislawdev/certdoctor/internal/core/report"
	"github.com/donislawdev/certdoctor/internal/core/status"
)

// NamedByScript is what a challenge row holds instead of a stack name when an
// automatic configuration script chose the proxy.
//
// IT IS DELIBERATELY NOT A Stack VALUE, for the reason NamedOnCommandLine is
// not one either: a Stack is a place a MACHINE keeps proxy configuration, and a
// script is not a place - it is a program that answers about one URL. The token
// lives here, beside the only field that carries it, and the closed list of
// stacks stays a list of places.
const NamedByScript = "pac"

// proxyAuthRequired is the one status code that answers this layer's question.
//
// IT IS A NUMBER AND NOT A SENTENCE - inviolable rule 19. A status line is
// somebody else's text and is routinely localised; measured in this tree
// already, a Polish Windows answers a refused connection in Polish.
const proxyAuthRequired = 407

// defaultProxyPorts is what a scheme means when a proxy entry names no port.
//
// IT IS DECLARED HERE RATHER THAN BORROWED, AND THE TWO OTHER SITES ARE NAMED SO
// THAT NOBODY HAS TO GO LOOKING. internal/adapter/pac has the same pair for the
// address a script is fetched from, and this package may not import an adapter;
// cmd/certdoctor has it for the port THIS RUN will try against the target, which
// is a different question about a URL a person typed. What is shared between the
// three is not a rule this project derived but a registered fact about two
// schemes, so a change to one of them would not be a change to the others.
//
// A SCHEME OUTSIDE THIS TABLE PRODUCES NO GUESS AT ALL. Vendors do not agree on
// what a bare "host" means in a proxy setting, so inventing a port here would
// make this program open a connection nobody named - and then report what it
// found there as a fact about somebody's proxy.
var defaultProxyPorts = map[string]string{"http": "80", "https": "443"}

// Query says which shape a question to a proxy takes.
//
// THERE ARE TWO AND THEY ARE NOT INTERCHANGEABLE - probe S15, measured
// 2026-09-07 against the bench's squid, before any of this code existed. An
// http:// client asks a proxy in absolute form; an https:// client asks for a
// tunnel with CONNECT. The measurement that made this a type rather than a
// detail: CONNECT to a port outside a proxy's SSL_ports came back refused on
// BOTH bench ports, including the one that wants no credentials at all, because
// squid ships a "deny CONNECT !SSL_ports" rule nobody on that bench wrote. A
// challenge blind to the scheme would have reported that refusal about a target
// this program reaches over plain http, through a proxy that lets it through,
// on a machine with no credential problem whatever - inviolable rule 21 broken
// from the proxy's side.
type Query string

const (
	// QueryAbsoluteForm is the request an http:// client makes of a proxy.
	QueryAbsoluteForm Query = "absolute_form"
	// QueryConnect is the tunnel an https:// client asks a proxy to open.
	QueryConnect Query = "connect"
)

// String makes Query printable without a conversion at every call site.
func (q Query) String() string { return string(q) }

// AllQueries lists every shape exactly once, in declaration order.
var AllQueries = []Query{QueryAbsoluteForm, QueryConnect}

// ChallengeRequest is one question to one proxy, complete.
//
// IT CARRIES THE AUTHORITY AND NOT THE URL THE USER TYPED, and that is a
// decision rather than an omission. What this layer asks about is an ORIGIN -
// "will you pass a request to this host and port" - and sending somebody's path
// and query string to a proxy that has not been established as theirs would put
// the most identifying part of the run on a wire nobody asked us to use. A HEAD
// of "/" is what probe S15 measured and what the answer turns on.
type ChallengeRequest struct {
	// Endpoint is the proxy, "host:port", to be dialled exactly as written.
	Endpoint string
	// Query is the shape of the question, decided by the target's scheme.
	Query Query
	// Authority is the target's "host:port", which is what CONNECT names and
	// what the absolute form is built around.
	Authority string
}

// ChallengeAnswer is what one proxy said, or why nothing was asked.
type ChallengeAnswer struct {
	// Asked says whether the exchange happened at all.
	Asked bool
	// Detail is why it did not, in this program's words, or an extra sentence
	// about what did.
	Detail string
	// Status is the status code the proxy answered with. It means nothing
	// unless Asked.
	Status int
	// Schemes are the ways the proxy offered to be told who is asking.
	Schemes []report.ProxyAuthScheme
}

// ChallengeAsk is the port that puts one question to one proxy.
//
// IT RETURNS AN ANSWER RATHER THAN AN ERROR, the same shape Evaluate has, and
// for the same reason: a proxy that could not be reached is a row in this
// report, not a failure of the run. The adapter behind it is the sixth place in
// this program that can open a connection, and it borrows the permission rule
// rather than copying it.
type ChallengeAsk func(ctx context.Context, request ChallengeRequest) ChallengeAnswer

// Endpoint is one proxy this run concluded would be used for this target.
//
// THE UNIT IS THE ENDPOINT AND NOT THE PLACE THAT NAMED IT, for the third time
// in this arc - ADR90 for the stacks, ADR91 for the scripts, and here for what
// they both arrive at. Two Windows stacks and a script routinely hold one
// "host:port", and asking it three times would open three connections and print
// three answers a proxy under load is entitled to make differ.
type Endpoint struct {
	// Address is "host:port" exactly as it will be dialled and exactly as it
	// goes into the allowed set. It is the entry's own spelling wherever the
	// entry named a port, and the entry's host joined to the port its scheme
	// implies wherever it did not.
	Address string
	// Query is the shape this endpoint must be asked in.
	Query Query
	// Authority is the target's "host:port" this endpoint would be asked about.
	Authority string
	// NamedBy are the things that arrived at this endpoint, in report order.
	NamedBy []string
	// CarriedCredentials records that an entry naming this endpoint held a user
	// and a password, which were dropped where they were read.
	CarriedCredentials bool
	// Skip is why this endpoint will not be asked, empty when it will be.
	//
	// IT IS A SENTENCE AND NOT A FLAG, because every one of them is printed. An
	// endpoint this run declined to ask is still a place a reader may be
	// wondering about, and inviolable rule 1 forbids passing over it in silence.
	Skip string
}

// Dialable names the endpoints this run will actually ask, in report order.
//
// IT IS A METHOD RATHER THAN A LOOP AT THE CALL SITE BECAUSE THE CALLER IS THE
// ORCHESTRATOR, and what it does with this list is widen the set of places this
// program may connect to. "Which of these will be dialled" is a rule about this
// layer's own work, so it belongs beside that work rather than in the wiring -
// where a second reading of it could drift and quietly authorise an address
// nothing was ever going to ask.
func (r Result) Dialable() []string {
	var out []string
	for _, endpoint := range r.Endpoints {
		if endpoint.Skip != "" {
			continue
		}
		out = append(out, endpoint.Address)
	}
	return out
}

// endpointsOf works out which proxies this target would actually go through.
//
// A PLACE THAT SENDS THIS TARGET PAST ITS PROXY CONTRIBUTES NOTHING HERE, and
// that is what keeps this list to the connections the run has a reason to make.
// The fact is not lost by leaving it out: the proxy_stack row for that place
// already carries bypass_rules, which is where a reader looks for it and which
// says it per reading rather than once - because one exception list is read at
// least two ways by runtimes this program asks about.
func endpointsOf(lenses []Lens, scripts []script, target Target) []Endpoint {
	var endpoints []Endpoint
	position := map[string]int{}
	query := queryFor(target)
	authority := authorityOf(target)

	add := func(raw, scheme, namer, refuse string, carried bool) {
		address, skip := dialableAddress(raw, scheme)
		if refuse != "" {
			address, skip = raw, refuse
		}
		if skip == "" && authority == "" {
			// This run could not work out which origin to ask about, which is
			// ours rather than anything about a machine: readTarget accepts only
			// the two schemes with a known default port, so arriving here means
			// something upstream handed this layer a target it does not describe.
			skip = "certdoctor could not work out which host and port to ask this proxy about, " +
				"which is a gap here rather than anything about this machine"
		}
		// THERE IS NO "AND IF IT IS EMPTY" GUARD HERE, AND ITS ABSENCE IS
		// MEASURED RATHER THAN AN OVERSIGHT - the same sentence scriptsNamed
		// carries one file over, and the same first draft. parseServer refuses
		// an entry with no address and the caller below refuses a directive with
		// no endpoint, so raw is never empty; dialableAddress hands back either
		// that string or a join, and a join is never empty either. The branch
		// could not be reached, which makes it the shape OBS112 names: a guard
		// that reads as caution, decides nothing, and would then take a mutation
		// entry down with it by surviving every mutation aimed at it.
		if at, seen := position[address]; seen {
			endpoints[at].NamedBy = append(endpoints[at].NamedBy, namer)
			endpoints[at].CarriedCredentials = endpoints[at].CarriedCredentials || carried
			return
		}
		position[address] = len(endpoints)
		endpoints = append(endpoints, Endpoint{
			Address:            address,
			Query:              query,
			Authority:          authority,
			NamedBy:            []string{namer},
			CarriedCredentials: carried,
			Skip:               skip,
		})
	}

	for _, lens := range lenses {
		if !lens.Read {
			continue
		}
		selected, ok := ServerFor(lens.Servers, target.Scheme)
		if !ok || bypassedEverywhere(lens, target) {
			continue
		}
		add(selected.Address, selected.Scheme, lens.Stack.String(), refusedScheme(selected.Scheme), selected.CarriedCredentials)
	}

	// THE SCRIPT COMES AFTER THE PLACES AND OUTRANKS THEM ON THE MACHINE, which
	// is why both are here rather than only the winner. A row per endpoint lets
	// a reader see that the script and a stack disagree about which proxy
	// applies, and that disagreement is the fault this product exists to show.
	for _, one := range scripts {
		if !one.settled() {
			continue
		}
		chosen, ok := firstRecognised(one.answer.Result.Directives)
		if !ok || chosen.Endpoint == "" {
			continue
		}
		add(chosen.Endpoint, schemeOfDirective(chosen.Kind), NamedByScript, refusedDirective(chosen.Kind), false)
	}
	return endpoints
}

// queryFor turns the target's scheme into the shape of the question.
func queryFor(target Target) Query {
	if lower(target.Scheme) == "https" {
		return QueryConnect
	}
	return QueryAbsoluteForm
}

// authorityOf is the target's "host:port", or empty when this run cannot say.
func authorityOf(target Target) string {
	host := unwrap(target.Host)
	if host == "" {
		return ""
	}
	port := target.Port
	if port == "" {
		port = defaultProxyPorts[lower(target.Scheme)]
	}
	if port == "" {
		return ""
	}
	return join(host, port)
}

// bypassedEverywhere reports whether every reading that applies to this place
// sends this target past its proxy.
//
// EVERY READING AND NOT ANY, and the difference is the whole reason bypass_rules
// is a list. One NO_PROXY is read at least two ways by runtimes this program
// asks about, so a target excused under one of them and not the other still goes
// through the proxy on that machine - for some of the programs on it.
func bypassedEverywhere(lens Lens, target Target) bool {
	rules := bypassRulesOf(lens, target)
	if len(rules) == 0 {
		return false
	}
	for _, rule := range rules {
		if !rule.Bypasses {
			return false
		}
	}
	return true
}

// refusedScheme says why a proxy entry's own scheme puts it outside this
// question, or returns empty when it does not.
//
// SOCKS IS THE ONE THAT MATTERS AND IT IS NOT PEDANTRY. A SOCKS proxy speaks a
// binary protocol on the same kind of socket, so an HTTP request sent to one
// gets an answer that is not HTTP at all - and a status code read out of that
// would be a number this program invented.
func refusedScheme(scheme string) string {
	if !strings.HasPrefix(lower(scheme), "socks") {
		return ""
	}
	return "this entry names a SOCKS proxy, and certdoctor asks this question over HTTP, " +
		"which a SOCKS proxy does not answer"
}

// refusedDirective is refusedScheme for a keyword out of a script's answer.
func refusedDirective(kind string) string {
	if !strings.HasPrefix(lower(kind), "socks") {
		return ""
	}
	return "this script chose a SOCKS proxy, and certdoctor asks this question over HTTP, " +
		"which a SOCKS proxy does not answer"
}

// schemeOfDirective says how a proxy named by a script keyword is reached.
//
// SOURCE: Mozilla's PAC documentation, read 2026-09-02 and quoted in
// internal/core/pac - PROXY is the original keyword for an HTTP proxy, and
// Firefox additionally accepts HTTP and HTTPS, where the second names a proxy
// reached over TLS. The keyword is the only thing a script says about how to
// reach the address, so it is the only thing this can be built from.
func schemeOfDirective(kind string) string {
	switch strings.ToUpper(kind) {
	case "HTTPS":
		return "https"
	case "PROXY", "HTTP":
		return "http"
	default:
		return ""
	}
}

// dialableAddress gives the string that will be dialled, or says why there is
// none.
// THE PORT IS TAKEN FROM THE SCHEME AND NEVER FROM A HABIT. An entry naming
// neither is left alone with a sentence, because the vendors do not agree: a
// bare name means one port to one runtime and another to the next, and a guess
// here would make this program open a connection nobody named and then report
// what it found there.
func dialableAddress(raw, scheme string) (string, string) {
	host, port := splitAuthority(raw)
	if port != "" {
		return raw, ""
	}
	fallback, known := defaultProxyPorts[lower(scheme)]
	if !known {
		return raw, "this entry names no port and no scheme that implies one, and runtimes do not agree " +
			"on what a bare proxy name means - so certdoctor did not guess a port for it"
	}
	return join(host, fallback), ""
}

// splitAuthority pulls a host and a port apart, with the brackets taken off an
// IPv6 literal so that join can put them back exactly once.
//
// THE RULE IS BORROWED AND NOT COPIED. splitWinINETEntry already decides when a
// trailing group of digits is a port and when it is the last field of a bare
// IPv6 literal - "::1" would otherwise become a host of "::" and a port of "1",
// which is an address this program would then dial. Writing that test a second
// time here is the shape OBS50 has measured six times in this tree: one rule in
// two places, and a mutation entry aimed at either of them stops proving
// anything. What this function adds is only the shape the caller needs.
func splitAuthority(raw string) (string, string) {
	_, host, port := splitWinINETEntry(raw)
	return unwrap(host), port
}

// join puts a host and a port back together, bracketing an IPv6 literal.
func join(host, port string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}

// Challenge asks every endpoint this run concluded would be used whether it
// wants credentials, and says what that does to the layer's answer.
//
// IT IS A SECOND FUNCTION AND NOT A SECOND HALF OF Ask, AND THE SEAM IS WHERE IT
// IS FOR ONE REASON: between the two, somebody has to widen the set of places
// this program may connect to, and that somebody may not be this layer. A layer
// that adds its own targets is a layer permitting itself, which would make the
// allowed set a description of what happened rather than a rule about what may -
// so the orchestrator does it, from a closure the entry point built, exactly as
// it does between L1 and L3.
//
// EVERYTHING THAT IS NOT A 407 LEAVES THE VERDICT ALONE - probe S15 again, and
// this is the half of that measurement nobody went looking for. A CONNECT the
// bench's proxy ALLOWED came back 503 because the origin was out of reach, and
// from the client's side that is indistinguishable from a refusal. The layer's
// own question - which proxy applies to this URL - was already settled by then,
// so a code that says nothing about credentials must not unsettle it.
func Challenge(ctx context.Context, in Input, result Result) Result {
	if len(result.Endpoints) == 0 {
		return result
	}
	var challenged, carried int
	for _, endpoint := range result.Endpoints {
		answer := askProxy(ctx, in.Challenge, endpoint)
		result.Findings = append(result.Findings, challengeFinding(endpoint, answer, in.Target))
		if answer.Asked && answer.Status == proxyAuthRequired {
			challenged++
			if endpoint.CarriedCredentials {
				carried++
			}
		}
	}
	if challenged == 0 {
		return result
	}
	return Result{
		Status:    status.Unknown,
		Reason:    status.ReasonCredentialsRequired,
		Detail:    demandDetail(challenged, carried),
		Findings:  result.Findings,
		Endpoints: result.Endpoints,
	}
}

// demandDetail is the sentence a run that met a challenge ends on.
//
// IT NAMES NO ENDPOINT, the masking rule every summary in this layer states: a
// verdict crosses the assembly path through Redaction.Text, which pseudonymises
// registered names and hosts INSIDE a URL, and a proxy entry is a bare
// "host:port" learned during the walk, so it is neither.
//
// THE SECOND CLAUSE IS NOT POLITENESS. This run cuts a credential out of a proxy
// address where it reads it - ADR89 - so a machine whose password works still
// meets a 407 here, and a verdict that stopped at the first clause would tell
// somebody their machine is missing something it has.
func demandDetail(challenged, carried int) string {
	said := fmt.Sprintf("%d of the proxies this URL goes through demands credentials before it will pass "+
		"a request, and this run offered none - so whether this URL can be reached through it was not established", challenged)
	if challenged == 1 {
		said = "the proxy this URL goes through demands credentials before it will pass a request, and this " +
			"run offered none - so whether this URL can be reached through it was not established"
	}
	if carried > 0 {
		said += ", and the configuration naming it carries a credential certdoctor cut off where it read it, " +
			"so this machine may not be missing anything"
	}
	return said
}

// askProxy puts one endpoint to the port, and answers for every way of not
// asking.
//
// A MISSING PORT IS OUR DEFECT AND THE SENTENCE SAYS SO, exactly as askScript
// says it one field over. It is not a fact about somebody's machine - the
// machine named the proxy perfectly well - so the row must not read as a proxy
// that refused to answer.
//
// AN ANSWER THAT CONTRADICTS ITSELF IS TURNED INTO OUR OWN GAP RATHER THAN
// PASSED ON. The report contract refuses a row that says a proxy was asked and
// does not say what it answered, and a refused row degrades the WHOLE layer -
// ADR66 - so a port that returns nonsense would cost the reader every proxy row
// in the report rather than one.
func askProxy(ctx context.Context, ask ChallengeAsk, endpoint Endpoint) ChallengeAnswer {
	if endpoint.Skip != "" {
		return ChallengeAnswer{Detail: endpoint.Skip}
	}
	if ask == nil {
		return ChallengeAnswer{Detail: "this run was given no way to ask a proxy whether it wants credentials, " +
			"which is a gap in certdoctor rather than anything about this machine"}
	}
	answer := ask(ctx, ChallengeRequest{
		Endpoint:  endpoint.Address,
		Query:     endpoint.Query,
		Authority: endpoint.Authority,
	})
	if !answer.Asked {
		if answer.Detail == "" {
			answer.Detail = "certdoctor did not ask this proxy and did not record why, " +
				"which is a gap here rather than anything about this machine"
		}
		return ChallengeAnswer{Detail: answer.Detail}
	}
	if answer.Status == 0 {
		return ChallengeAnswer{Detail: "certdoctor asked this proxy and did not record what it answered, " +
			"which is a gap here rather than anything about this machine"}
	}
	return answer
}

// challengeFinding turns one endpoint and one answer into one row.
func challengeFinding(endpoint Endpoint, answer ChallengeAnswer, target Target) report.Finding {
	body := report.ProxyChallenge{
		Endpoint:           endpoint.Address,
		NamedBy:            endpoint.NamedBy,
		Asked:              answer.Asked,
		Detail:             answer.Detail,
		CarriedCredentials: endpoint.CarriedCredentials,
		Caveats:            []string{},
	}
	if answer.Asked {
		body.Query = endpoint.Query.String()
		body.Status = answer.Status
		body.Schemes = answer.Schemes
	}
	body.Caveats = append(body.Caveats, caveatsOfChallenge(body)...)
	return report.Finding{
		Kind:           report.FindingProxyChallenge,
		Summary:        summaryOfChallenge(body, target),
		Source:         report.SourceDetected,
		ProxyChallenge: &body,
	}
}

// caveatsOfChallenge is what this row does not settle, said in this program's
// words.
func caveatsOfChallenge(body report.ProxyChallenge) []string {
	var caveats []string
	if !body.Asked {
		return caveats
	}
	if body.Status != proxyAuthRequired {
		// Probe S15, 2026-09-07: on the bench's proxy a CONNECT that was ALLOWED
		// came back 503 because the origin was unreachable, and a CONNECT to a
		// non-SSL port came back 403 from a proxy wanting no credentials at all.
		// All three look the same from here and mean three different things.
		caveats = append(caveats, "only a 407 answers whether a proxy wants credentials, "+
			"and this code says something else - so what it means for this URL is outside what this run established")
		return caveats
	}
	if body.CarriedCredentials {
		caveats = append(caveats, "the configuration naming this proxy carries a credential, which certdoctor "+
			"cut off where it read it and did not send - so this proxy may well accept the one this machine holds")
	}
	if len(body.Schemes) == 0 {
		caveats = append(caveats, "this proxy demanded credentials without naming a single way of supplying them, "+
			"so there is nothing here to say which kind it wants")
	}
	return caveats
}

// summaryOfChallenge is the one line a surface prints when it knows nothing
// about this kind.
//
// IT NAMES NO ENDPOINT, for the reason every other summary in this layer gives.
// The address is in the body, which has a masking rule that can see it.
//
// A ROW THAT WAS NOT ASKED CARRIES ITS REASON IN THE SUMMARY, AND THAT WAS
// MEASURED ON THE BINARY RATHER THAN REASONED. The terminal renders a summary
// and a value and never a Detail, so the first version printed "was not asked
// whether it wants credentials" beside an address and said nothing at all about
// why - inviolable rule 1 broken on the surface most people read. summaryOfScript
// solved the same problem the same way one file over, by carrying the
// evaluator's sentence inline.
//
// NONE OF THOSE SENTENCES NAMES THE ENDPOINT, which is what makes this safe:
// they are written not to, on both sides of the port, and the refusal in the
// adapter has a test of its own saying so. A summary crosses the assembly path
// through a rule that cannot see a bare "host:port".
func summaryOfChallenge(body report.ProxyChallenge, target Target) string {
	switch {
	case !body.Asked:
		return fmt.Sprintf("a proxy this machine would use for %s was not asked whether it wants credentials - %s",
			describe(target), body.Detail)
	case body.Status == proxyAuthRequired:
		return fmt.Sprintf("a proxy %s goes through demands credentials before it will pass a request",
			describe(target))
	default:
		return fmt.Sprintf("a proxy %s goes through answered %d when asked whether it wants credentials",
			describe(target), body.Status)
	}
}
