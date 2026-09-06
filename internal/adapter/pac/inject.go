package pac

import (
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
func (s Sandbox) makeDeterministic(vm *goja.Runtime) func() bool {
	if s.Ports.Now != nil {
		vm.SetTimeSource(s.Ports.Now)
	}
	source, used := fixedRandom()
	vm.SetRandSource(source)
	return used
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
func (s Sandbox) inject(vm *goja.Runtime) (func() []string, error) {
	unanswered := map[string]bool{}
	noteUnanswered := func(name string, supplied bool) {
		if !supplied {
			unanswered[name] = true
		}
	}

	helpers := map[string]any{
		"isPlainHostName":     corepac.IsPlainHostName,
		"dnsDomainIs":         corepac.DNSDomainIs,
		"localHostOrDomainIs": corepac.LocalHostOrDomainIs,
		"dnsDomainLevels":     corepac.DNSDomainLevels,
		"shExpMatch":          corepac.ShExpMatch,
		"isResolvable": func(host string) bool {
			noteUnanswered("isResolvable", s.Ports.Resolve != nil)
			return s.Ports.IsResolvable(host)
		},

		"isInNet": func(host, pattern, mask string) bool {
			noteUnanswered("isInNet", s.Ports.Resolve != nil)
			return s.Ports.IsInNet(host, pattern, mask)
		},

		"dnsResolve": func(host string) goja.Value {
			noteUnanswered("dnsResolve", s.Ports.Resolve != nil)
			address, ok := s.Ports.DNSResolve(host)
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

		"weekdayRange": s.timeHelper(vm, "weekdayRange", s.Ports.WeekdayRange),
		"dateRange":    s.timeHelper(vm, "dateRange", s.Ports.DateRange),
		"timeRange":    s.timeHelper(vm, "timeRange", s.Ports.TimeRange),
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
	return func() []string {
		var called []string
		for _, name := range helperNames {
			if unanswered[name] {
				called = append(called, name)
			}
		}
		return called
	}, nil
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
