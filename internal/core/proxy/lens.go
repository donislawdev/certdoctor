package proxy

import "sort"

// Stack names one place a machine keeps proxy configuration.
//
// IT IS A PLACE AND NOT A PROGRAM, and the distinction decides the whole shape.
// "Edge" is not a stack - it is a program that reads one. Several programs read
// the same stack and one program can read two, so a report organised by program
// would repeat itself and still miss the case this layer exists for: two stacks
// on one machine saying different things.
type Stack string

const (
	// StackEnvironment - the proxy environment variables of this process.
	StackEnvironment Stack = "environment"
	// StackWinINET - the current user's Internet Settings, which Edge, Chrome
	// and .NET follow.
	StackWinINET Stack = "wininet"
	// StackWinHTTP - this machine's default WinHTTP configuration, which
	// services follow.
	StackWinHTTP Stack = "winhttp"
	// StackMacSystem - the macOS system configuration, as scutil reports it.
	StackMacSystem Stack = "macos_system"
)

var stackMeanings = map[Stack]string{
	StackEnvironment: "the proxy environment variables this process was started with",
	StackWinINET:     "the current user's Internet Settings, which Edge, Chrome and .NET follow",
	StackWinHTTP:     "this machine's default WinHTTP configuration, which services follow",
	StackMacSystem:   "the macOS system configuration, as scutil reports it",
}

// AllStacks lists every place exactly once, in declaration order.
var AllStacks = []Stack{StackEnvironment, StackWinINET, StackWinHTTP, StackMacSystem}

// Valid reports whether s is one of the four.
func (s Stack) Valid() bool {
	_, ok := stackMeanings[s]
	return ok
}

// Meaning returns the English text for s, or the empty string outside the list.
func (s Stack) Meaning() string { return stackMeanings[s] }

// String makes Stack printable without a conversion at every call site.
func (s Stack) String() string { return string(s) }

// Lens is what one stack says about proxying, as read and not as judged.
//
// THE ZERO VALUE IS A LENS THAT WAS NEVER ASKED, which is the safe direction:
// a forgotten assignment reports "not read" rather than "no proxy configured",
// and those two are the pair this whole type exists to keep apart.
type Lens struct {
	// Stack says which place this was read from.
	Stack Stack
	// Source is what was actually asked - a function name, a registry path, a
	// command line. It goes in the report so a reader can repeat the reading.
	Source string
	// Read says whether the stack could be read at all. False with a Detail is
	// an answer. False without one is a defect on our side.
	Read bool
	// Detail is why it could not be read, or an extra sentence about what was.
	Detail string
	// Servers are the proxies this stack names, in the order it named them.
	//
	// Nil means the stack was not read. An empty slice means it was read and
	// names none - ADR20, the same distinction findings carry.
	Servers []Server
	// Bypass is the exception list exactly as the stack holds it, joined for
	// Rule where the platform hands over an array.
	Bypass string
	// BypassSet says whether the stack held an exception list at all. An absent
	// list and an empty one are different facts about a machine.
	BypassSet bool
	// Rule is how Bypass has to be read. It is a property of the STACK and not
	// of the program asking, because the list belongs to the stack.
	//
	// The environment stack is the exception and carries no rule: one NO_PROXY
	// is read at least three ways, so the rule there belongs to whichever
	// runtime is being asked about, not to the variable.
	Rule Rule
	// PACURL is the address of an automatic configuration script, if the stack
	// named one.
	//
	// ITS PRESENCE IS NOT PROOF THAT PAC IS IN USE - OBS111. Measured
	// 2026-09-05: writing AutoConfigURL into the registry without touching any
	// enabling switch makes the Windows API hand it straight back, and the
	// switch itself lives in a blob this program does not read. So this is a
	// fact of configuration and never a conclusion about behaviour.
	PACURL string
	// AutoDetect says whether the stack has WPAD discovery turned on, or that
	// the question has no answer here.
	AutoDetect Tristate
}

// Tristate is yes, no, or "this stack does not answer that question".
//
// A BOOLEAN WOULD HAVE TO PICK ONE OF THE TWO NEGATIVES, and they are not the
// same: WinHTTP's structure has no auto-detect field at all, while the Internet
// Settings view has one and it can be off. Reporting both as false would claim
// this program checked something it never asked.
type Tristate uint8

const (
	// Unasked - this stack has no such setting to report.
	Unasked Tristate = iota
	// Off - the stack has the setting and it is off.
	Off
	// On - the stack has the setting and it is on.
	On
)

// String makes Tristate printable.
func (t Tristate) String() string {
	switch t {
	case Off:
		return "off"
	case On:
		return "on"
	default:
		return "not answered by this stack"
	}
}

// NamesAProxy reports whether this lens names at least one proxy server.
//
// A PAC URL IS DELIBERATELY NOT COUNTED. A stack holding only an autoconfig
// address has not named a proxy - it has named a script that might name one,
// and this program does not fetch it until P8-K3. Counting it here would make
// the divergence below say two stacks agree when one of them has not answered.
func (l Lens) NamesAProxy() bool { return len(l.Servers) > 0 }

// Divergence is how two or more stacks on one machine differ.
//
// IT IS A CLOSED LIST OF ITS OWN AND NOT report.Divergence, for the reason
// ADR79 gives about the PAC evaluator: that vocabulary has seven values and
// every one of them is a sentence about SETS OF ADDRESSES for one name. This
// asks something else entirely, so borrowing the words would make two different
// questions answer with the same vocabulary and neither would be readable.
type Divergence string

const (
	// DivergeAgree - every stack that could be read names the same proxies.
	DivergeAgree Divergence = "agree"
	// DivergeAgreeDirect - every stack that could be read names no proxy at
	// all. It is separate from agree because "nobody configured a proxy" and
	// "everybody agrees on the same proxy" are different rows in a report, and
	// only one of them is a finding.
	DivergeAgreeDirect Divergence = "agree_direct"
	// DivergeOneSided - at least one stack names a proxy and at least one names
	// none.
	//
	// THIS IS THE MEASURED CASE AND THE REASON L2 EXISTS. Measured 2026-09-05:
	// with a proxy configured in the current user's Internet Settings, the IE
	// view returns it in full and WinHttpGetDefaultProxyConfiguration still
	// reports WINHTTP_ACCESS_TYPE_NO_PROXY. Edge and .NET go through the proxy,
	// a service on WinHTTP goes direct, and nothing on that machine is
	// misconfigured.
	DivergeOneSided Divergence = "one_sided"
	// DivergeConflicting - two stacks name proxies and they are not the same.
	DivergeConflicting Divergence = "conflicting"
	// DivergeUnreadable - fewer than two stacks could be read, so there is
	// nothing to compare. It is NOT "they agree": a comparison that could not
	// happen must never come back looking like one that did.
	DivergeUnreadable Divergence = "unreadable"
)

var divergenceMeanings = map[Divergence]string{
	DivergeAgree:       "every stack that could be read names the same proxies",
	DivergeAgreeDirect: "every stack that could be read names no proxy at all",
	DivergeOneSided:    "one stack names a proxy and another names none, so two programs on this machine will do different things",
	DivergeConflicting: "two stacks name proxies and they are not the same",
	DivergeUnreadable:  "fewer than two stacks could be read, so nothing was compared",
}

// AllDivergences lists every class exactly once, in declaration order.
var AllDivergences = []Divergence{
	DivergeAgree, DivergeAgreeDirect, DivergeOneSided, DivergeConflicting, DivergeUnreadable,
}

// Valid reports whether d is one of the five.
func (d Divergence) Valid() bool {
	_, ok := divergenceMeanings[d]
	return ok
}

// Meaning returns the English text for d, or the empty string outside the list.
func (d Divergence) Meaning() string { return divergenceMeanings[d] }

// String makes Divergence printable.
func (d Divergence) String() string { return string(d) }

// Compare says how a machine's stacks differ.
//
// A CLASS EXISTS ONLY WHERE THERE ARE TWO LENSES TO COMPARE - ADR65, which
// settled exactly this for the two DNS views. One readable stack is not a
// machine whose stacks agree, and the second return says so rather than leaving
// the caller to infer it from a value that looks like an answer.
//
// UNREADABLE LENSES ARE EXCLUDED FROM THE COMPARISON AND NOT COUNTED AS SILENT.
// A stack that could not be read has said nothing, so treating it as "names no
// proxy" would manufacture a one_sided finding out of our own failure to look -
// which is inviolable rule 15 read from the other end.
func Compare(lenses []Lens) (Divergence, bool) {
	var readable []Lens
	for _, l := range lenses {
		if l.Read {
			readable = append(readable, l)
		}
	}
	if len(readable) < 2 {
		return DivergeUnreadable, false
	}

	naming, silent := 0, 0
	seen := map[string]bool{}
	for _, l := range readable {
		if !l.NamesAProxy() {
			silent++
			continue
		}
		naming++
		seen[fingerprint(l.Servers)] = true
	}

	switch {
	case naming == 0:
		return DivergeAgreeDirect, true
	case silent > 0:
		return DivergeOneSided, true
	case len(seen) > 1:
		return DivergeConflicting, true
	default:
		return DivergeAgree, true
	}
}

// fingerprint reduces a stack's proxy list to one comparable string.
//
// IT SORTS, because two stacks naming the same two proxies in different orders
// are configured the same way and a report saying they conflict would send
// somebody looking for a difference that is not there. The order INSIDE a lens
// is still kept as the platform gave it - see Lens.Servers - because that is
// what the platform will act on. This is only for asking whether two lenses say
// the same thing.
func fingerprint(servers []Server) string {
	parts := make([]string, 0, len(servers))
	for _, s := range servers {
		parts = append(parts, s.Protocol+"="+s.Scheme+"://"+lower(s.Address))
	}
	sort.Strings(parts)
	out := ""
	for _, p := range parts {
		out += p + ";"
	}
	return out
}
