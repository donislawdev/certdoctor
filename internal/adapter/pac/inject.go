package pac

import (
	"errors"
	"time"

	"github.com/dop251/goja"

	corepac "github.com/donislawdev/certdoctor/internal/core/pac"
)

// helperNames is every name this sandbox puts into the global scope.
//
// CONDITION 4 OF docs/14 SECTION 2.1 IS THIS LIST BEING EXHAUSTIVE: "we
// expose ONLY the helper functions from the PAC specification, nothing beyond".
// It is written out separately from the injection below so a test can assert
// that the two agree AND that nothing else appeared - a check that cannot be
// made against a map the code builds for itself, which is the shape OBS48 names.
var helperNames = []string{
	"isPlainHostName", "dnsDomainIs", "localHostOrDomainIs", "isResolvable",
	"isInNet", "dnsResolve", "myIpAddress", "dnsDomainLevels", "shExpMatch",
	"weekdayRange", "dateRange", "timeRange",
}

// makeDeterministic pins the two sources of non-determinism ECMAScript brings.
//
// THIS IS A CORRECTION TO WHAT ADR75 RECORDED, AND IT IS AN IMPROVEMENT
// RATHER THAN A CONTRADICTION. That record says Date and Math.random "are
// present, so they cannot be removed without work" - true, they are not host
// objects. Measured 2026-09-02: they do not need removing, because goja exposes
// SetTimeSource and SetRandSource. A PAC file therefore sees THIS RUN's clock,
// which is what makes timeRange and dateRange answer about the moment the user
// is asking about, and a fixed random source, which is what makes two runs of
// one binary produce the same report.
//
// THE PRICE, NAMED: a PAC file that balances load with Math.random will
// always take the same branch here, where a browser would spread across them.
// That is one of the answers the browser could give rather than an answer it
// could not - but a report resting on such a branch is saying less than it
// looks, and the layer has to be able to say so.
// It returns a function saying whether the PAC file ever asked for randomness,
// so the result can carry that rather than leaving the caveat in a comment.
// It also returns a reader saying whether the file read the clock through
// goja's OWN Date, which is a second route to the same caveat and was measured
// to be open all along: with Ports.Now nil the engine fell back to its default
// time source, so new Date() answered correctly while our three helpers threw.
// A file deciding by Date has just as much of a date on its answer as one
// deciding by timeRange, and a report that said so for one and not the other
// would be describing the helper rather than the answer.
func (s Sandbox) makeDeterministic(vm *goja.Runtime) (func() bool, func() bool) {
	readClock := false
	if s.Ports.Now != nil {
		// WRAPPED TO RECORD, NOT TO PIN. pinnedClock explains why Date is left
		// moving: freezing it changes what somebody else's file DOES, while
		// this only changes what we can say about it.
		vm.SetTimeSource(func() time.Time {
			readClock = true
			return s.Ports.Now()
		})
	}
	source, used := fixedRandom()
	vm.SetRandSource(source)
	return used, func() bool { return readClock }
}

// fixedRandom is a xorshift64 sequence with a fixed seed.
//
// It is written out rather than taken from math/rand because the only property
// that matters is that it gives the same sequence every time this binary runs,
// and a standard library generator's stream is not promised to be stable across
// Go releases. Nothing here is security-bearing: it feeds Math.random inside a
// PAC file.
func fixedRandom() (goja.RandSource, func() bool) {
	state := uint64(0x2545F4914F6CDD1D)
	asked := false
	source := func() float64 {
		asked = true
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		return float64(state>>11) / float64(uint64(1)<<53)
	}
	return source, func() bool { return asked }
}

// inject puts the twelve helpers into vm and nothing else, and hands back the
// list of those the file called with nothing behind them.
//
// FOUR OF THE TWELVE NEED THE WORLD AND THE OTHER EIGHT DO NOT, which is why
// only four are wrapped. A run may legally supply no resolver - pac.Ports says
// a nil port is legal and means "nobody can answer that" - but the PAC contract
// has no way for isResolvable to say so, so the file gets a false and takes a
// branch it would not take in a browser. Recording the call is what lets the
// layer say the answer rests on a question this run could not ask.
//
// THE RULE LIVES IN ONE PLACE. noteUnanswered is told whether the port behind a
// helper was supplied, rather than four sites each deciding it for themselves -
// the shape OBS50 has measured six times in this tree.
func (s Sandbox) inject(vm *goja.Runtime, expired func() bool) (func() helperRecord, error) {
	unanswered := map[string]bool{}
	noteUnanswered := func(name string, supplied bool) {
		if !supplied {
			unanswered[name] = true
		}
	}

	// THE HELPERS BELOW READ ports AND NOT s.Ports, AND THE DIFFERENCE IS THE
	// WHOLE BOUND. s.Ports.Resolve is whatever the caller wired; ports.Resolve
	// is that same resolver behind a cache and an allowance, so this file cannot
	// send one name twice or more names than Sandbox.MaxLookups permits.
	ports, lookups := s.boundedPorts()

	// AND THE CLOCK IS PINNED THE SAME WAY, for the reason the next function
	// gives: one evaluation describes one moment or it describes none.
	clock, clockUsed := s.pinnedClock()
	ports.Now = clock

	helpers := map[string]any{
		"isPlainHostName":     corepac.IsPlainHostName,
		"dnsDomainIs":         corepac.DNSDomainIs,
		"localHostOrDomainIs": corepac.LocalHostOrDomainIs,
		"dnsDomainLevels":     corepac.DNSDomainLevels,
		// THE ONE HELPER WHOSE WORK GROWS WITH ITS INPUT, so it alone asks the
		// stopwatch's question between its steps - ADR114. When it stops early
		// it interrupts the engine itself: its false is no answer, and the
		// stopwatch's next tick may come after the file has already taken the
		// branch that false chose.
		"shExpMatch": func(text, pattern string) bool {
			matched, finished := corepac.ShExpMatchUntil(text, pattern, expired)
			if !finished {
				vm.Interrupt(LimitTime)
			}
			return matched
		},
		"isResolvable": func(host string) bool {
			noteUnanswered("isResolvable", ports.Resolve != nil)
			return ports.IsResolvable(host)
		},

		"isInNet": func(host, pattern, mask string) bool {
			noteUnanswered("isInNet", ports.Resolve != nil)
			return ports.IsInNet(host, pattern, mask)
		},

		"dnsResolve": func(host string) goja.Value {
			noteUnanswered("dnsResolve", ports.Resolve != nil)
			address, ok := ports.DNSResolve(host)
			if !ok {
				// The specification's own answer for a name that does not
				// resolve. It is null rather than an empty string so a PAC file
				// testing the result gets what a browser would give it.
				return goja.Null()
			}
			return vm.ToValue(address)
		},

		"myIpAddress": func() string {
			noteUnanswered("myIpAddress", s.Ports.LocalAddress != nil)
			address, _ := s.Ports.MyIPAddress()
			return address
		},

		// THESE THREE READ ports AND NOT s.Ports, WHICH THEY DID NOT UNTIL
		// 2026-09-08. The comment above this map has always said the helpers
		// read the bounded copy, and for the resolver ones it was true - these
		// three reached past it to the raw clock. Nothing was visibly wrong
		// while the clock was nil, because they answered "not understood"
		// either way. Measured the moment it was wired: they answered
		// correctly, took an unpinned instant, and recorded nothing - so the
		// caveat that says this answer has a date on it would never have fired.
		"weekdayRange": s.timeHelper(vm, "weekdayRange", ports.WeekdayRange),
		"dateRange":    s.timeHelper(vm, "dateRange", ports.DateRange),
		"timeRange":    s.timeHelper(vm, "timeRange", ports.TimeRange),
	}

	for _, name := range helperNames {
		helper, ok := helpers[name]
		if !ok {
			// The two lists have come apart. Refusing to build the sandbox is
			// the only safe direction: a PAC file calling a name that silently
			// went missing would fail as though the FILE were wrong.
			return nil, errNoSuchHelper(name)
		}
		if err := vm.Set(name, helper); err != nil {
			return nil, err
		}
	}

	// THE ORDER IS helperNames' ORDER AND NOT THE ORDER THE FILE CALLED THEM.
	// Two runs of one binary against one file have to produce one document -
	// the determinism guard - and a map's range order is not stable even
	// within a run.
	return func() helperRecord {
		var called []string
		for _, name := range helperNames {
			if unanswered[name] {
				called = append(called, name)
			}
		}
		asked, exhausted, failed := lookups()
		return helperRecord{unanswered: called, asked: asked, exhausted: exhausted, failed: failed, usedClock: clockUsed()}
	}, nil
}

// helperRecord is what the injected helpers noticed while a file ran.
//
// It exists so the three things the sandbox learns about a file - what it asked
// that nobody could answer, which names it sent to a resolver, and whether it
// spent its allowance - travel back as one value. They arrive together, they are
// attached together in Evaluate, and three accessors would be three chances to
// attach two of them.
type helperRecord struct {
	unanswered []string
	asked      []string
	exhausted  bool
	failed     bool
	usedClock  bool
}

// errLookupsExhausted is the answer a name gets once the allowance is spent.
//
// IT IS AN ERROR AND NOT AN EMPTY RESULT, and pac.Ports draws exactly that
// distinction at the top of its Resolve field: an empty list means the name did
// not resolve, an error means nobody could be asked. Nobody could be asked is
// what actually happened, and the difference decides what the helpers hand the
// file - a truthful "no answer" rather than a false "does not exist".
var errLookupsExhausted = errors.New("this evaluation has already asked about as many distinct names as it may")

// boundedPorts puts the resolver behind a per-evaluation cache and allowance,
// and hands back a reader for what the file did with it.
//
// WHY A CACHE IS PART OF THE BOUND RATHER THAN AN OPTIMISATION. A corporate PAC
// file testing one host against several subnets calls isInNet several times
// about ONE name. Counting calls would refuse such a file for traffic it never
// generated, and the thing worth bounding is not how often the file asks but how
// many names leave this machine - because the names are what a hostile file
// chooses and what a watcher downstream would read.
//
// WHY THE ERROR IS CACHED TOO. A name that failed is a question that already
// left; asking again would send it a second time to learn what we know. It also
// keeps the allowance honest, since a file could otherwise spend one slot an
// unbounded number of times.
//
// A NIL RESOLVER IS RETURNED UNTOUCHED so that pac.Ports' own rule - a nil port
// means nobody can answer - stays the single description of that state. Wrapping
// it would put a second one here.
//
// A RESOLVER THAT FAILED IS RECORDED, NOT ONLY CACHED - ADR114. The helpers hand
// the file a null for it, the same null a name that does not exist gets, so the
// layer can only refuse to rest a route on that branch if it is told.
func (s Sandbox) boundedPorts() (corepac.Ports, func() (asked []string, exhausted, failed bool)) {
	ports := s.Ports
	if ports.Resolve == nil {
		return ports, func() ([]string, bool, bool) { return nil, false, false }
	}

	type answer struct {
		addresses []string
		err       error
	}

	// NO LOCK, AND THAT IS A PROPERTY OF THE ENGINE RATHER THAN AN OVERSIGHT.
	// goja runs one Runtime on one goroutine, so every helper call is on the
	// goroutine that called RunString. The stopwatch goroutine touches only
	// Interrupt, and ADR78 measured what that does: a native call already
	// running finishes before the interrupt surfaces, so no helper is still
	// writing when Evaluate reads this back.
	seen := map[string]answer{}
	var asked []string
	exhausted, failed := false, false

	resolve := s.Ports.Resolve
	ports.Resolve = func(host string) ([]string, error) {
		if had, ok := seen[host]; ok {
			return had.addresses, had.err
		}
		if len(seen) >= s.MaxLookups {
			exhausted = true
			return nil, errLookupsExhausted
		}
		addresses, err := resolve(host)
		seen[host] = answer{addresses: addresses, err: err}
		asked = append(asked, host)
		failed = failed || err != nil
		return addresses, err
	}

	return ports, func() ([]string, bool, bool) { return asked, exhausted, failed }
}

// pinnedClock hands the three time helpers ONE instant for the whole
// evaluation, and a reader saying whether they took it.
//
// WHY ONE INSTANT AND NOT time.Now ON EVERY CALL. A PAC file may ask
// weekdayRange and then timeRange, and an evaluation is bounded in
// milliseconds - but a boundary crossed between those two calls would have the
// file answering about two different moments, and the branch it then takes is
// one no browser would take. That is the same class of untruth this package
// already refuses for a name nobody could resolve, arriving through the clock
// instead of through the resolver. Pinning is also what makeDeterministic
// already does to the random source, and for a reason stated the same way: a
// report describes one moment or it describes none.
//
// IT DOES NOT PIN goja'S OWN Date, AND THAT IS DELIBERATE. makeDeterministic
// hands the engine s.Ports.Now, which is the real clock, so a file calling
// Date.now() sees time move exactly as it does today. Freezing it would be a
// change in what somebody else's file does rather than in what we report: a
// file spinning until a few milliseconds pass would spin until the stopwatch
// stopped it, and we would then blame a working file for running long. OBS130
// is that mistake made once already, and it is not worth making again for a
// tidier invariant.
//
// NO LOCK, FOR THE REASON boundedPorts GIVES ABOVE: goja runs one Runtime on one
// goroutine, so the helper that writes this flag and the Evaluate that reads it
// back are the same goroutine, and the stopwatch touches only Interrupt.
func (s Sandbox) pinnedClock() (func() time.Time, func() bool) {
	if s.Ports.Now == nil {
		// A nil port stays nil so that pac.Ports' own rule - nobody can answer -
		// remains the single description of that state. Wrapping it would put a
		// second one here.
		return nil, func() bool { return false }
	}

	instant := s.Ports.Now()
	used := false
	return func() time.Time {
		used = true
		return instant
	}, func() bool { return used }
}

// timeHelper adapts one of the three variadic time helpers.
//
// AN ARGUMENT SHAPE THIS PROGRAM CANNOT READ THROWS RATHER THAN ANSWERING
// FALSE, AND THE DIRECTION OF THE BLAME IS THE REASON. dateRange has seven
// documented shapes and timeRange four; a PAC file may legally use one this
// implementation does not cover. Returning false would silently take a branch
// the browser would not take, which is inviolable rule 15's case - an unknown
// answered as a quiet no. Throwing makes the run say it could not read the file,
// and the message says the gap is OURS rather than the file's.
func (s Sandbox) timeHelper(vm *goja.Runtime, name string, ask func([]corepac.Argument) (bool, bool)) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		answer, understood := ask(argumentsOf(call))
		if !understood {
			panic(vm.NewTypeError("certdoctor does not understand this form of %s and will not guess an answer", name))
		}
		return vm.ToValue(answer)
	}
}

// argumentsOf keeps each argument's type, because dateRange tells a day from a
// year by magnitude and a month from both by being text.
func argumentsOf(call goja.FunctionCall) []corepac.Argument {
	arguments := make([]corepac.Argument, 0, len(call.Arguments))
	for _, argument := range call.Arguments {
		if _, isText := argument.Export().(string); isText {
			arguments = append(arguments, corepac.TextArgument(argument.String()))
			continue
		}
		arguments = append(arguments, corepac.NumberArgument(int(argument.ToInteger())))
	}
	return arguments
}

type errNoSuchHelper string

func (e errNoSuchHelper) Error() string {
	return "the helper " + string(e) + " is named in helperNames but not built, so the sandbox would be missing one of the twelve"
}
