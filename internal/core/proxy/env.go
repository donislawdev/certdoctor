package proxy

import "strings"

// Lookup is the port this package sees the environment through.
//
// IT IS DECLARED HERE RATHER THAN IMPORTED FROM internal/core/machine, which has
// an identical one. Two core packages importing each other is a sideways edge,
// forbidden by default and costing an entry in the layer guard's
// intraLayerEdges - a standing guard weakened for a function type four words
// long. Go's assignability rules mean machine.Lookup satisfies this one at a
// call site with no conversion, so nothing is given up.
type Lookup func(name string) (value string, set bool)

// environmentSuffix is what every proxy variable's name ends in.
const environmentSuffix = "_proxy"

// noProxyToken names the exception list rather than an address, and allProxyToken
// names the fallback for protocols with no entry of their own.
//
// SOURCE for the second: Microsoft, HttpClient.DefaultProxy, read 2026-09-06 -
// "ALL_PROXY: the proxy server used on HTTP and/or HTTPS requests in case
// HTTP_PROXY and/or HTTPS_PROXY are not defined."
// https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httpclient.defaultproxy
//
// That is the same idea the Windows list expresses with a bare entry, so it maps
// onto Server.IsDefault rather than onto a protocol called "all" - one concept,
// one shape, and ServerFor already knows how to answer with it.
const (
	noProxyToken  = "no"
	allProxyToken = "all"
)

// EnvironmentLens is what the environment this process was started with says
// about proxying.
//
// PRECEDENCE IS THE PRODUCT HERE, and both vendors that document it agree.
//
// Go, golang.org/x/net/http/httpproxy, FromEnvironment, read 2026-09-06 - "When
// both the uppercase and lowercase versions are provided, the lowercase versions
// are prioritized."
// https://pkg.go.dev/golang.org/x/net/http/httpproxy
//
// Microsoft, HttpClient.DefaultProxy, read 2026-09-06 - "On systems where
// environment variables are case-sensitive, the variable names may be all
// lowercase or all uppercase. The lowercase names are checked first."
//
// WHAT AN EMPTY LOWER CASE VALUE DOES IS DOCUMENTED BY ONLY ONE OF THEM, AND
// THAT LIMIT IS WRITTEN DOWN RATHER THAN PAPERED OVER. Go's helper takes the
// first NON-EMPTY value of the two, so http_proxy= does not hide a set
// HTTP_PROXY; Microsoft's page says only that the lower case name is checked
// first. This takes Go's reading, because the alternative - an empty lower case
// name shadowing a set upper case one - would report no proxy on a machine where
// at least one runtime is using one, and inviolable rule 15 points that way.
//
// THE NAMES ARE A PARAMETER AND NOT A LIST IN THIS FILE. Writing the eight
// spellings again would put the same literals in the tree twice, which is the
// measured shape of OBS50 - it disarmed two L0 mutation entries the day
// machine.ProxyVariables was first written out by hand. The caller passes
// machine.ProxyVariables(), which derives them from the one declared list.
//
// A NAME THAT IS NEITHER ALL LOWER NOR ALL UPPER IS IGNORED, and so is one not
// ending in _proxy. Every vendor above checks exactly two spellings, so a
// Http_Proxy is a variable none of them reads, and reporting it would put a
// proxy in the report that nothing on the machine will use.
//
// WHAT THIS FUNCTION DOES NOT CHECK, SAID OUT LOUD RATHER THAN LEFT TO BE FOUND:
// whether a name ending in _proxy carries an ADDRESS at all. NODE_USE_ENV_PROXY
// ends in it and is a switch saying whether Node reads the others; the rule that
// keeps it out - a name ending in _PROXY with exactly one underscore - lives in
// machine.ProxyVariables and is deliberately not repeated here. A second copy
// would be one RULE in two places, which is the shape OBS50 has measured five
// times, most recently while that very list was being written.
func EnvironmentLens(lookup Lookup, names []string) Lens {
	const source = "the proxy environment variables this process was started with"

	if lookup == nil {
		return UnreadableLens(StackEnvironment, source,
			"no way to read the environment was supplied, so nothing this process was started with could be established")
	}

	// An empty, non-nil slice: this stack WAS read, and Lens.Servers documents
	// nil as the answer for one that was not - ADR20.
	lens := Lens{Stack: StackEnvironment, Source: source, Read: true, Servers: []Server{}}

	var notes []string
	for _, pair := range environmentPairs(names) {
		reading := pair.read(lookup)
		notes = append(notes, reading.notes()...)

		if pair.token == noProxyToken {
			// Set rather than non-empty, because Lens.BypassSet exists to keep
			// "no list" apart from "a list excusing nothing".
			lens.BypassSet = reading.lowerSet || reading.upperSet
			lens.Bypass = reading.value
			continue
		}
		server, ok := parseServer(reading.value)
		if !ok {
			continue
		}
		// The token decides the protocol, so a stray "=" inside a value cannot
		// be read as one. For all_proxy the protocol is empty, which is what
		// Server.IsDefault means.
		server.Protocol = ""
		if pair.token != allProxyToken {
			server.Protocol = pair.token
		}
		lens.Servers = append(lens.Servers, server)
	}
	lens.Detail = strings.Join(notes, "; ")
	return lens
}

// environmentPair is the two spellings of one variable.
type environmentPair struct {
	// token is what the name says before _proxy, lower cased: http, https, all,
	// no. It is not called "protocol" because two of the four are not one.
	token string
	lower string
	upper string
}

// environmentPairs groups the names handed in, keeping first-appearance order so
// that the report order is the order L0 already uses.
func environmentPairs(names []string) []environmentPair {
	var out []environmentPair
	at := map[string]int{}
	for _, name := range names {
		token, ok := proxyTokenOf(name)
		if !ok {
			continue
		}
		index, seen := at[token]
		if !seen {
			index = len(out)
			at[token] = index
			out = append(out, environmentPair{token: token})
		}
		switch {
		case name == strings.ToLower(name):
			out[index].lower = name
		case name == strings.ToUpper(name):
			out[index].upper = name
		}
	}
	return out
}

// proxyTokenOf reads the token out of a variable name, and refuses a name that
// carries none.
func proxyTokenOf(name string) (string, bool) {
	lowered := lower(name)
	token := strings.TrimSuffix(lowered, environmentSuffix)
	if token == lowered || token == "" {
		return "", false
	}
	return token, true
}

// environmentReading is what the two spellings of one variable hold, and which
// of them won.
type environmentReading struct {
	pair                   environmentPair
	lowerValue, upperValue string
	lowerSet, upperSet     bool
	// value is the winner, empty when neither spelling holds anything.
	value string
	// wonByUpper says the upper case spelling supplied the value, which is the
	// case curl reads differently for http.
	wonByUpper bool
}

// read asks for both spellings and applies the precedence above.
func (p environmentPair) read(lookup Lookup) environmentReading {
	r := environmentReading{pair: p}
	if p.lower != "" {
		r.lowerValue, r.lowerSet = lookup(p.lower)
	}
	if p.upper != "" {
		r.upperValue, r.upperSet = lookup(p.upper)
	}
	switch {
	case r.lowerValue != "":
		r.value = r.lowerValue
	case r.upperValue != "":
		r.value, r.wonByUpper = r.upperValue, true
	}
	return r
}

// notes says what a reader has to know about this pair that the winning value
// does not already say.
//
// BOTH SENTENCES DESCRIBE A DISAGREEMENT INSIDE ONE STACK, which is a thing
// proxy.Divergence cannot express: that vocabulary compares PLACES, and both
// halves of this one are the same place. So it goes in Detail, where a sentence
// is allowed to be about something the closed list has no word for.
func (r environmentReading) notes() []string {
	var out []string
	if r.lowerValue != "" && r.upperValue != "" && r.lowerValue != r.upperValue {
		out = append(out, r.pair.lower+" and "+r.pair.upper+
			" are both set and name different proxies, and the lower case one is the one Go and .NET use")
	}
	// curl, and only curl, refuses the upper case spelling of the http proxy.
	// SOURCE: Everything curl, "http_proxy in lower case only", read 2026-08-04
	// and quoted in full beside the variable list in internal/core/machine -
	// the reason is the CGI convention of turning an incoming request header
	// into an environment variable prefixed HTTP_, which would let a remote
	// request hand a server side script its own proxy.
	if r.wonByUpper && r.pair.token == "http" {
		out = append(out, r.pair.upper+
			" is the spelling in use and curl honours this one in lower case only, so curl sends http requests direct where Go and .NET go through the proxy")
	}
	return out
}
