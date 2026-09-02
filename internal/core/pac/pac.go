// Package pac implements the twelve helper functions a proxy auto-configuration
// file may call, as ordinary Go functions that know nothing about JavaScript.
//
// WHY THEY ARE OURS RATHER THAN A LIBRARY'S - ADR10. The one ready-made Go PAC
// library keeps its helper map unexported and calls net.LookupIP from inside the
// sandbox, which breaks inviolable rule 16 through a dependency rather than
// through our code, and returns ips[0] from a list with no defined order - so
// the same PAC rule could answer differently between two runs of the same
// program. Writing twelve short functions costs less than reading somebody
// else's twelve line by line, which we would have to do anyway.
//
// WHY THEY LIVE IN THE CORE, AWAY FROM THE ENGINE. Everything here is a pure
// function of its arguments and its ports, so it can be checked against
// hand-written vectors with no JavaScript anywhere in the test. The engine that
// exposes these to a PAC file lives in internal/adapter/pac and does nothing but
// translate. That split is what stops the only witness to these twelve functions
// from being the JavaScript that calls them - the shape OBS48 names, where a
// test asks the code under test what the answer should be.
//
// EVERY CLAIM HERE IS A CLAIM ABOUT SOMEBODY ELSE'S RUNTIME, so inviolable rule
// 18 applies to all of it: the semantics come from Mozilla's PAC documentation,
// read at source on 2026-09-02 at
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Proxy_servers_and_tunneling/Proxy_Auto-Configuration_PAC_file
// and each function repeats the part of it that decides its behaviour. Where
// browsers are known to disagree with each other, the comment says so rather
// than picking one and going quiet.
//
// NOTHING HERE MAY BLOCK OR LOOP WITHOUT A BOUND, AND THAT IS A RULE OF THE
// PACKAGE RATHER THAN A STYLE NOTE. Measured on 2026-09-02: goja's Interrupt
// stops the JavaScript interpreter between instructions, and does NOT stop a
// native Go function called from JavaScript - a 3 second native loop ran to
// completion against a 50 millisecond budget, and the interrupt was only
// delivered afterwards. The sandbox's third condition therefore does not cover
// this package. What keeps a PAC file from spending a user's whole run inside
// one of these twelve functions is that none of them can take long.
package pac

import "time"

// Ports is everything these helpers need from outside themselves.
//
// A NIL PORT IS LEGAL AND MEANS "NOBODY CAN ANSWER THAT", WHICH IS NOT THE SAME
// AS "THE ANSWER IS NO". Each helper below says what it does with a missing
// port, and the answer is never a quiet false: a PAC file asking isResolvable
// on a run with no resolver has not learned that the name does not resolve.
//
// THE PORTS ARE NOT WIRED TO ANYTHING IN P8-K1, AND THAT IS DELIBERATE RATHER
// THAN UNFINISHED. Reaching a resolver from here would widen the set of places
// this program may connect to, which is inviolable rule 16 and a load-bearing
// change of its own; it belongs with the slice that reads the machine's proxy
// configuration. Until then the sandbox has no network because there is nothing
// behind these ports, which makes the mandatory guard true by construction
// rather than by promise.
type Ports struct {
	// Resolve turns a host name into its addresses, in the order the resolver
	// gave them. An empty result means the name did not resolve; an error means
	// nobody could be asked.
	Resolve func(host string) ([]string, error)

	// LocalAddress is the address this machine would use to reach the world.
	LocalAddress func() (string, error)

	// Now is the clock. It is a port for the same reason every other layer's
	// clock is: weekdayRange, dateRange and timeRange are functions OF the
	// current time, so a test that could not fix the time could only assert
	// things that are true all year.
	Now func() time.Time
}
