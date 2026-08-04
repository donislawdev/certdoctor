// Package allowed holds the finite set of places this program may connect to.
//
// INVIOLABLE RULE 16 WRITTEN AS A TYPE. certdoctor connects only to what it
// derived from what the user asked about: the target URL, the addresses that
// host resolved to, the resolvers configured on this machine, the proxy, and
// the address of the PAC file. Nothing else - no telemetry, no crash reporting,
// no update check, no OCSP or CRL in v1.
//
// WHY THAT NEEDS A TYPE AND NOT A PARAGRAPH. "A diagnostic tool does not phone
// home" is the one promise a user cannot check for themselves, and at a tool
// that reads trust stores it decides whether it gets permission to run inside a
// company at all. A set that can be enumerated is a promise that can be
// asserted against; a paragraph in a README is not.
//
// THE SET GROWS DURING A RUN, AND THAT IS ITS HARDEST PROPERTY. The addresses
// are unknown before L1 and the proxy before L2, so "built before the first
// connection" can only mean "before the first connection OF ITS KIND". Growth
// is therefore explicit and named - Allow takes a reason from a closed list -
// rather than something a caller does by appending to a field. It never
// shrinks: an answer to "was this target allowed" that depended on when it was
// asked would be worth nothing.
package allowed

import (
	"fmt"
	"sort"
	"strings"
)

// Reason says which of the five permitted derivations put a target in the set.
//
// The list is closed and it is closed for the same purpose as the status
// vocabulary: an open list means the next person adds "monitoring" and the rule
// dissolves without anybody deciding to dissolve it.
type Reason string

const (
	// ReasonTarget - the URL the user asked about.
	ReasonTarget Reason = "target"
	// ReasonResolvedAddress - an address that URL's host resolved to.
	ReasonResolvedAddress Reason = "resolved_address"
	// ReasonResolver - a DNS resolver configured on this machine.
	ReasonResolver Reason = "resolver"
	// ReasonProxy - a proxy named by the environment, by system settings or by
	// a PAC result.
	ReasonProxy Reason = "proxy"
	// ReasonPACFile - the address the PAC file itself is fetched from.
	ReasonPACFile Reason = "pac_file"
)

var reasonMeanings = map[Reason]string{
	ReasonTarget:          "the URL the user asked about",
	ReasonResolvedAddress: "an address the target host resolved to",
	ReasonResolver:        "a DNS resolver configured on this machine",
	ReasonProxy:           "a proxy named by the environment, system settings or PAC",
	ReasonPACFile:         "the address the PAC file is fetched from",
}

// AllReasons lists every permitted derivation exactly once, in declaration
// order. It is five long and the registry test refuses a sixth that arrives
// without a meaning.
var AllReasons = []Reason{ReasonTarget, ReasonResolvedAddress, ReasonResolver, ReasonProxy, ReasonPACFile}

// Valid reports whether r is one of the five.
func (r Reason) Valid() bool {
	_, ok := reasonMeanings[r]
	return ok
}

// Meaning returns the English text for r, or the empty string outside the list.
func (r Reason) Meaning() string { return reasonMeanings[r] }

// String makes Reason printable without a conversion at every call site.
func (r Reason) String() string { return string(r) }

// Targets is the set. Its zero value is an empty set that permits nothing,
// which is the safe direction: a forgotten assignment refuses every connection
// rather than allowing every one.
type Targets struct {
	// entries maps a normalised host:port to why it is in here. A map rather
	// than a slice because the same address arrives twice routinely - a host
	// that resolves to an address which is also a resolver - and asking twice
	// has to give the same answer.
	entries map[string]Reason
}

// New returns an empty set.
func New() *Targets { return &Targets{entries: map[string]Reason{}} }

// Allow puts one target in the set and says which of the five derivations put
// it there.
//
// IT REFUSES RATHER THAN IGNORING. A reason outside the list, or an empty
// target, is a defect in our code and not something arriving from the machine
// being diagnosed - so it comes back as an error the caller has to look at,
// instead of silently widening or silently narrowing what this program may
// reach.
//
// Allowing the same target twice is not an error. It happens routinely and the
// first reason is kept: the set answers "may I connect", never "how many ways
// did we arrive at this".
func (t *Targets) Allow(target string, reason Reason) error {
	if t.entries == nil {
		t.entries = map[string]Reason{}
	}
	key := normalise(target)
	if key == "" {
		return fmt.Errorf("an empty target cannot be allowed, and %s is not a reason to try", reason)
	}
	if !reason.Valid() {
		return fmt.Errorf("%q is not one of the five derivations rule 16 permits, so %s may not be allowed", reason, key)
	}
	if _, already := t.entries[key]; already {
		return nil
	}
	t.entries[key] = reason
	return nil
}

// Permits reports whether target may be connected to, and why it was allowed.
//
// The reason comes back with the answer on purpose. A refusal has to be able to
// say what the set DID contain, and an audit of a run has to be able to show
// that every connection traces to something the user asked for.
// A LOOKUP IS ENOUGH AND THE GUARD CLAUSE THAT USED TO STAND HERE WAS NOT.
// It refused an empty key and a nil map before looking, which reads as caution
// and was doing nothing: reading from a nil map in Go is safe and answers "not
// present", and an empty key can never be stored because Allow refuses it. The
// mutation register found it - the branch could be deleted with every test
// still green, which is what "this line does not decide anything" looks like.
func (t *Targets) Permits(target string) (Reason, bool) {
	reason, ok := t.entries[normalise(target)]
	return reason, ok
}

// Len is how many distinct targets are in the set.
func (t *Targets) Len() int { return len(t.entries) }

// List returns every allowed target with its reason, sorted.
//
// Sorted rather than in insertion order, because this ends up in a report and
// in a test comparison, and map iteration in Go is randomised - the same run
// would otherwise produce different bytes.
func (t *Targets) List() []Entry {
	out := make([]Entry, 0, len(t.entries))
	for target, reason := range t.entries {
		out = append(out, Entry{Target: target, Reason: reason})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Target < out[j].Target })
	return out
}

// Entry is one allowed target and the derivation that put it there.
type Entry struct {
	Target string
	Reason Reason
}

// normalise puts a target into the one form the set stores.
//
// WHY LOWER CASE AND TRIMMED, AND WHY NOTHING ELSE. Host names are case
// insensitive, so EXAMPLE.COM and example.com are one machine, and storing them
// as two would let a connection be refused for a target that was allowed one
// line earlier. Nothing else is done: this function must not start parsing
// URLs, because a set that interprets its own input can disagree with whatever
// the dialler actually does with the same string, and then the guard passes
// while the connection goes somewhere else.
func normalise(target string) string {
	return strings.ToLower(strings.TrimSpace(target))
}
